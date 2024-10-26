from flask import Flask, request, jsonify, Blueprint
from flask_migrate import Migrate
from models import db, User, Account, RevokedToken
from config import Config
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, get_jwt, jwt_required, get_jwt_identity
from werkzeug.security import check_password_hash
import uuid

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


app.register_blueprint(api, url_prefix='/api')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)


