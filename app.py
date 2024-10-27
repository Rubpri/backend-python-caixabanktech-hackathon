from flask import Flask, request, jsonify, Blueprint
from flask_migrate import Migrate
import requests
from models import OTP, db, User, Account, RevokedToken, Transaction, UserAsset
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

    email = data['email']
    email_pattern = r"^[\w\.-]+@[a-zA-Z\d\.-]+\.[a-zA-Z]{2,}$"
    if not re.match(email_pattern, email):
        return jsonify({"error": f"Invalid email: {email}"}), 400

    password = data['password']

    if not any(char.isupper() for char in password):
        return jsonify({"error": "Password must contain at least one uppercase letter."}), 400

    if not (any(char.isdigit() for char in password) and re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return jsonify({"error": "Password must contain at least one digit and one special character."}), 400

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return jsonify({"error": "Password must contain at least one special character."}), 400

    if any(char.isspace() for char in password):
        return jsonify({"error": "Password cannot contain whitespace."}), 400

    if len(password) >= 128:
        return jsonify({"error": "Password must be less than 128 characters long."}), 400

    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters long."}), 400

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


@api.route('/account/buy-asset', methods=['POST'])
@jwt_required()
def buy_assets():
    current_user = get_jwt_identity()  
    data = request.get_json()  
    
    asset_symbol = data.get("assetSymbol")
    pin = data.get("pin")
    amount_invested = data.get("amount")
    
    user = User.query.filter_by(account_number=current_user).first()
    
    if not user or user.pin != pin:
        return jsonify({"error": "Incorrect PIN"}), 400
    
    if amount_invested <= 0:
        return jsonify({"error": "Amount must be greater than zero."}), 400

    account = Account.query.filter_by(user_account_number=current_user).first()
    
    if account.balance < amount_invested:
        return jsonify({"error": "Insufficient balance."}), 400

    try:
        price_response = requests.get('https://faas-lon1-917a94a7.doserverless.co/api/v1/web/fn-e0f31110-7521-4cb9-86a2-645f66eefb63/default/market-prices-simulator')
        price_data = price_response.json()
        purchase_price = price_data.get(asset_symbol)
        
        if purchase_price is None:
            return jsonify({"error": "Asset symbol not found"}), 400
    
    except requests.RequestException:
        return jsonify({"error": "Internal error occurred while fetching asset price"}), 500

    units_purchased = amount_invested / purchase_price

    try:
        account.balance -= amount_invested

        user_asset = UserAsset.query.filter_by(user_account_number=current_user, asset_symbol=asset_symbol).first()
        if user_asset:
            user_asset.quantity += units_purchased
            user_asset.amount = amount_invested
            user_asset.purchase_price = purchase_price
        else:
            user_asset = UserAsset(
                user_account_number=current_user,
                asset_symbol=asset_symbol,
                quantity=units_purchased,
                amount=amount_invested,
                purchase_price=purchase_price
            )
            db.session.add(user_asset)

            transaction = Transaction(
            amount=amount_invested,
            transaction_type="ASSET_PURCHASE",
            source_account_number=current_user,
            target_account_number="N/A"
        )
        db.session.add(transaction)

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "An error occurred while processing the transaction"}), 500


    send_investment_confirmation_email(user, asset_symbol, units_purchased, amount_invested, purchase_price, account.balance)

    

    return jsonify({"msg": "Asset purchase successful."}), 200

def send_investment_confirmation_email(user, asset_symbol, units_purchased, amount_invested, purchase_price, balance):
    from_email = "CaixaBank@caixabank.com"  
    to_email = user.email  
    subject = "Investment Purchase Confirmation"

    user_asset = UserAsset.query.filter_by(user_account_number=user.account_number, asset_symbol=asset_symbol).first()
    
    current_holdings = user_asset.quantity if user_asset else 0
    
    body = f"""
    Dear {user.name},

    You have successfully purchased {units_purchased:.2f} units of {asset_symbol} for a total amount of ${amount_invested:.2f}.

    Current holdings of {asset_symbol}: {current_holdings:.2f} units

    Summary of current assets:
    - {asset_symbol}: {current_holdings:.2f} units purchased at ${purchase_price}

    Account Balance: ${balance:.2f}
    Net Worth: ${balance + (current_holdings * purchase_price):.2f}

    Thank you for using our investment services.

    Best Regards,
    Investment Management Team
    """

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    smtp_server = 'smtp'
    smtp_port = 1025

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.send_message(msg)


@api.route('/account/sell-asset', methods=['POST'])
@jwt_required()
def sell_assets():
    current_user = get_jwt_identity()  
    data = request.get_json()

    asset_symbol = data.get("assetSymbol")
    pin = data.get("pin")
    quantity = data.get("quantity")

    user = User.query.filter_by(account_number=current_user).first()
    account = Account.query.filter_by(user_account_number=current_user).first()

    if not account:
        return jsonify({"error": "Account not found"}), 400

    if not user or user.pin != pin:
        return jsonify({"error": "Incorrect PIN"}), 400

    if quantity <= 0:
        return jsonify({"error": "Quantity must be greater than zero."}), 400

    user_asset = UserAsset.query.filter_by(user_account_number=current_user, asset_symbol=asset_symbol).first()

    if not user_asset:
        return jsonify({"error": "Asset not found in your portfolio."}), 404

    if user_asset.quantity < quantity:
        return jsonify({"error": "Insufficient asset quantity to sell."}), 400

    try:
        price_response = requests.get('https://faas-lon1-917a94a7.doserverless.co/api/v1/web/fn-e0f31110-7521-4cb9-86a2-645f66eefb63/default/market-prices-simulator')
        price_data = price_response.json()
        sell_price = price_data.get(asset_symbol)

        if sell_price is None:
            return jsonify({"error": "Asset price not found."}), 400
    
    except requests.RequestException:
        return jsonify({"error": "Internal error occurred while fetching asset price"}), 500
        
    total_sale_value = quantity * sell_price
    
    try:
        account.balance += total_sale_value
        
        user_asset.quantity -= quantity
        # user_asset.amount = total_sale_value
        # user_asset.purchase_price = sell_price
        db.session.add(user_asset)

        transaction = Transaction(
            amount=total_sale_value,
            transaction_type="ASSET_SELL",
            source_account_number=current_user,
            target_account_number="N/A"
        )
        db.session.add(transaction)

        db.session.commit()
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": "An error occurred while processing the transaction"}), 500

    gain_loss = total_sale_value - user_asset.amount

    send_investment_sale_confirmation_email(user, asset_symbol, quantity, user_asset.quantity, gain_loss, user_asset.purchase_price, account.balance )
        
    return jsonify({"msg": "Asset sale successful."}), 200

def send_investment_sale_confirmation_email(user, asset_symbol, units_sold, remaining_quantity, gain_loss, purchase_price, balance ):
    from_email = "CaixaBank@caixabank.com"  
    to_email = user.email  
    subject = "Investment Sale Confirmation"
    
    body = f"""
    Dear {user.name},

    You have successfully sold {units_sold:.2f} units of {asset_symbol}.

    Total Gain/Loss: ${gain_loss:.2f}

    Remaining holdings of {asset_symbol}: {remaining_quantity:.2f} units

    Summary of current assets:
    - {asset_symbol}: {remaining_quantity:.2f} units purchased at ${purchase_price:.2f}

    Account Balance: ${balance:.2f}
    Net Worth: ${balance + (remaining_quantity * purchase_price):.2f}

    Thank you for using our investment services.

    Best Regards,
    Investment Management Team
    """

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    smtp_server = 'smtp'
    smtp_port = 1025

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.send_message(msg)


@app.route('/market/prices', methods=['GET'])
def get_market_prices():
    try:
        response = requests.get('https://faas-lon1-917a94a7.doserverless.co/api/v1/web/fn-e0f31110-7521-4cb9-86a2-645f66eefb63/default/market-prices-simulator')
        prices = response.json()

        return jsonify(prices), 200

    except Exception as e:
        print(f"Error retrieving market prices: {str(e)}")
        return jsonify({"error": "Could not retrieve market prices."}), 500
    
@app.route('/market/prices/<string:symbol>', methods=['GET'])
def get_price_by_symbol(symbol):
    try:
        response = requests.get('https://faas-lon1-917a94a7.doserverless.co/api/v1/web/fn-e0f31110-7521-4cb9-86a2-645f66eefb63/default/market-prices-simulator')
        prices = response.json()

        if symbol in prices:
            return jsonify({symbol: prices[symbol]}), 200
        else:
            return jsonify({"error": "Symbol not found."}), 404

    except Exception as e:
        print(f"Error retrieving price for symbol {symbol}: {str(e)}")
        return jsonify({"error": "Could not retrieve market price for symbol."}), 500




app.register_blueprint(api, url_prefix='/api')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)


