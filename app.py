from flask import Flask, request, jsonify, Blueprint
from flask_migrate import Migrate
from models import OTP, db, User, Account, RevokedToken, Transaction
from config import Config
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash
import uuid
from datetime import datetime, timezone
import re

import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

app = Flask(__name__)

app.config.from_object(Config)
db.init_app(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

api = Blueprint('api', __name__)

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    token = jwt_payload['jti']
    return RevokedToken.query.filter_by(token=token).first() is not None


@app.route('/')
def hello():
    return "Hello, World!"


@api.route('users/register', methods=['POST'])
def register_user():
    data = request.get_json()

    if not data.get('name') or not data.get('password') or not data.get('email') or not data.get('address') or not data.get('phoneNumber'):
        return jsonify({"error": "All fields are required."}), 400

    if not User.validate_email(data['email']):
        return jsonify({"error": "Invalid email format."}), 400

    if not User.validate_phone(data['phoneNumber']):
        return jsonify({"error": "Invalid phone number."}), 400

    existing_user = User.query.filter((User.email == data['email']) | (User.phone_number == data['phoneNumber'])).first()
    if existing_user:
        return jsonify({"error": "Email or phone number already exists."}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')

    new_user = User(
        account_number=str(uuid.uuid4()),
        name=data['name'],
        email=data['email'],
        phone_number=data['phoneNumber'],
        address=data['address'],
        password=hashed_password
    )

    db.session.add(new_user)
    db.session.commit()

    new_account = Account(
        balance=0.0,
        user_account_number=new_user.account_number
    )

    new_user.account = new_account

    db.session.add(new_account)
    db.session.commit()

    return jsonify({
        "name": new_user.name,
        "email": new_user.email,
        "phoneNumber": new_user.phone_number,
        "address": new_user.address,
        "accountNumber": new_user.account_number,
        "hashedPassword": new_user.password
    }), 201


@api.route('users/login', methods=['POST'])
def login():
    data = request.get_json()
    identifier = data.get("identifier")
    password = data.get("password")

    user = User.query.filter(
        (User.email == identifier) | (User.account_number == identifier)
    ).first()

    if not user:
        return jsonify({"error": f"User not found for the given identifier: {identifier}"}), 400

    if not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Bad credentials"}), 401

    access_token = create_access_token(identity=user.account_number)
    return jsonify({"token": access_token})


@api.route('dashboard/user', methods=['GET'])
@jwt_required()
def get_user_info():
    account_number = get_jwt_identity()

    user = User.query.filter_by(account_number=account_number).first()

    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "name": user.name,
        "email": user.email,
        "phoneNumber": user.phone_number,
        "address": user.address,
        "accountNumber": user.account_number,
        "hashedPassword": user.password
    }), 200


@api.route('dashboard/account', methods=['GET'])
@jwt_required()
def get_account_info():
    current_user = get_jwt_identity()
    account = Account.query.filter_by(user_account_number=current_user).first()

    if not account:
        return jsonify({"error": "Account not found."}), 404

    return jsonify({
        "accountNumber": account.user_account_number,
        "balance": account.balance
    }), 200


@api.route('users/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']  
    revoked_token = RevokedToken(token=jti)
    db.session.add(revoked_token)
    db.session.commit()
    return jsonify(msg="Successfully logged out"), 200


@api.route('/auth/password-reset/send-otp', methods=['POST'])
def send_otp():
    data = request.get_json()
    identifier = data.get("identifier")

    user = User.query.filter_by(email=identifier).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    otp = random.randint(100000, 999999)

    otp_entry = OTP(identifier=identifier, otp=str(otp))
    db.session.add(otp_entry)
    db.session.commit()

    send_email(identifier, otp)

    return jsonify({"message": f"OTP sent successfully to: {identifier}"}), 200

def send_email(to_email, otp):
    from_email = "CaixaBank@caixabank.com" 
    subject = "Your OTP Code"
    body = f"OTP: {otp}"

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    smtp_server = 'smtp'
    smtp_port = 1025

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.send_message(msg)


@api.route('/auth/password-reset/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    identifier = data.get("identifier")
    otp = data.get("otp")

    otp_entry = OTP.query.filter_by(identifier=identifier, otp=otp).first()
    user = User.query.filter_by(email=identifier).first()

    if not otp_entry:
        return jsonify({"error": "Invalid or expired OTP."}), 400
    
    otp_entry.current_datetime = datetime.now(timezone.utc)
    db.session.commit()

    if not otp_entry.is_valid():
        return jsonify({"error": "Invalid or expired OTP."}), 400

    password_reset_token = str(uuid.uuid4())
    user.reset_token = password_reset_token
    db.session.commit()

    return jsonify({"passwordResetToken": password_reset_token}), 200


@api.route('/auth/password-reset', methods=['POST'])
def reset_password():
    data = request.get_json()
    identifier = data.get("identifier")
    reset_token = data.get("resetToken")
    new_password = data.get("newPassword")

    user = User.query.filter_by(email=identifier).first()
    if not user:
        return jsonify({"error": "User not found."}), 404

    if user.reset_token != reset_token:
        return jsonify({"error": "Invalid reset token."}), 400

    hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')

    user.password = hashed_password
    user.reset_token = None  
    db.session.commit()

    return jsonify({"message": "Password reset successfully"}), 200


@api.route('/account/pin/create', methods=['POST'])
@jwt_required() 
def create_pin():
    data = request.get_json()
    pin = data.get("pin")
    password = data.get("password")

    if not re.match(r'^\d{4}$', pin):
        return jsonify({"error": "PIN must be 4 digits."}), 400

    current_user_id = get_jwt_identity()
    
    user = User.query.get(current_user_id)

    if not user or not bcrypt.check_password_hash(user.password, password):
        return jsonify({"error": "Incorrect password"}), 401

    user.pin = pin
    db.session.commit()

    return jsonify({"msg": "PIN created successfully"}), 201


@api.route('/account/pin/update', methods=['PUT'])
@jwt_required() 
def update_pin():
    data = request.get_json()
    current_user_id = get_jwt_identity()

    if not all(key in data for key in ["oldPin", "password", "newPin"]):
        return jsonify({"error": "Missing fields."}), 400
    
    user = User.query.get(current_user_id)

    if user is None:
        return jsonify({"error": "User not found."}), 404
    
    if not bcrypt.check_password_hash(user.password, data['password']):
        return jsonify({"error": "Incorrect password."}), 401
    
    if user.pin != data['oldPin']:
        return jsonify({"error": "Incorrect old PIN."}), 400
    
    if not re.match(r'^\d{4}$', data['newPin']):
        return jsonify({"error": "PIN must be 4 digits."}), 400
    
    user.pin = data['newPin']

    try:
        db.session.commit() 
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

    return jsonify({"msg": "PIN updated successfully"}), 200
   

@api.route('/account/deposit', methods=['POST'])
@jwt_required()
def deposit_money():
    current_user = get_jwt_identity()
    data = request.get_json()
    
    pin = data.get("pin")
    amount_str = data.get("amount")

    user = User.query.filter_by(account_number=current_user).first()
    
    if not user or user.pin != pin:
        return jsonify({"error": "Incorrect PIN"}), 400

    try:
        amount = float(amount_str)
    except ValueError:
        return jsonify({"error": "Invalid amount format"}), 400

    if amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400

    account = Account.query.filter_by(user_account_number=current_user).first()
    if not account:
        return jsonify({"error": "Account not found"}), 404

    account.balance += amount
    db.session.commit()
    
    transaction = Transaction(
        amount=amount,
        transaction_type="CASH_DEPOSIT",
        transaction_date=datetime.now(timezone.utc),
        source_account_number=account.user_account_number,
        target_account_number="N/A"
    )
    
    db.session.add(transaction)
    db.session.commit()

    return jsonify({"msg": "Cash deposited successfully"}), 200


@api.route('/account/withdraw', methods=['POST'])
@jwt_required()
def withdraw_money():
    current_user = get_jwt_identity() 
    data = request.get_json()
    
    pin = data.get("pin")
    amount_str = data.get("amount") 

    user = User.query.filter_by(account_number=current_user).first()
    
    if not user or user.pin != pin:
        return jsonify({"error": "Incorrect PIN"}), 400

    try:
        amount = float(amount_str)
    except ValueError:
        return jsonify({"error": "Invalid amount format"}), 400

    if amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400

    account = Account.query.filter_by(user_account_number=current_user).first()
    if not account:
        return jsonify({"error": "Account not found"}), 404

    if account.balance < amount:
        return jsonify({"error": "Insufficient balance"}), 400

    account.balance -= amount
    db.session.commit()

    transaction = Transaction(
        amount=amount,
        transaction_type="CASH_WITHDRAWAL",
        transaction_date=datetime.now(timezone.utc),
        source_account_number=account.user_account_number,
        target_account_number="N/A"
    )
    
    db.session.add(transaction)
    db.session.commit()


    return jsonify({"msg": "Cash withdrawn successfully"}), 200


@api.route('/account/fund-transfer', methods=['POST'])
@jwt_required()
def transfer_funds():
    current_user = get_jwt_identity()
    data = request.get_json()
    
    pin = data.get("pin")
    amount_str = data.get("amount") 
    target_account_number = data.get("targetAccountNumber")

    user = User.query.filter_by(account_number=current_user).first()
    
    if not user or user.pin != pin:
        return jsonify({"error": "Incorrect PIN"}), 400

    try:
        amount = float(amount_str)
    except ValueError:
        return jsonify({"error": "Invalid amount format"}), 400

    if amount <= 0:
        return jsonify({"error": "Invalid amount"}), 400

    source_account = Account.query.filter_by(user_account_number=current_user).first()
    if not source_account:
        return jsonify({"error": "Source account not found"}), 404

    if source_account.balance < amount:
        return jsonify({"error": "Insufficient balance"}), 400

    target_account = Account.query.filter_by(user_account_number=target_account_number).first()
    if not target_account:
        return jsonify({"error": "Target account not found"}), 404

    source_account.balance -= amount
    target_account.balance += amount
    db.session.commit()

    transaction = Transaction(
        amount=amount,
        transaction_type="CASH_TRANSFER",
        transaction_date=datetime.now(timezone.utc),
        source_account_number=source_account.user_account_number,
        target_account_number=target_account.user_account_number
    )
    
    db.session.add(transaction)
    db.session.commit()

    return jsonify({"msg": "Funds transferred successfully"}), 200


@api.route('/account/transactions', methods=['GET'])
@jwt_required()
def get_transaction_history():
    current_user = get_jwt_identity() 

    account = Account.query.filter_by(user_account_number=current_user).first()
    
    if not account:
        return jsonify({"error": "Account not found"}), 404

    transactions = Transaction.query.filter(
        (Transaction.source_account_number == account.user_account_number) | 
        (Transaction.target_account_number == account.user_account_number)
    ).all()

    transaction_history = []
    for transaction in transactions:
        transaction_history.append({
            "id": transaction.id,
            "amount": transaction.amount,
            "transactionType": transaction.transaction_type,
            "transactionDate": int(transaction.transaction_date.timestamp() * 1000),
            "sourceAccountNumber": transaction.source_account_number,
            "targetAccountNumber": transaction.target_account_number or "N/A"
        })

    return jsonify(transaction_history), 200














app.register_blueprint(api, url_prefix='/api')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)


