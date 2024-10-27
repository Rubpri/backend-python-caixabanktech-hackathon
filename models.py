from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from sqlalchemy import Column, Integer, String, Float, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import relationship
import uuid
import re
from datetime import datetime, timezone, timedelta



db = SQLAlchemy()
bcrypt = Bcrypt()

class User(db.Model):
    account_number = db.Column(db.String(36), primary_key=True, unique=True, default=str(uuid.uuid4()))
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    phone_number = db.Column(db.String(15), nullable=False)
    address = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(128), nullable=False)
    reset_token = Column(String(36), nullable=True)
    pin = Column(String(4), nullable=True)

    account = relationship("Account", back_populates="user", uselist=False)

    def __repr__(self):
        return f'<User {self.email}>'

    @staticmethod
    def validate_email(email):
        email_regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
        return re.match(email_regex, email) is not None

    @staticmethod
    def validate_phone(phone):
        return len(phone) == 9 and phone.isdigit()


class Account(db.Model):
    id = Column(Integer, primary_key=True, autoincrement=True)
    balance = Column(Float, nullable=False, default=0.0)
    user_account_number = Column(String(36), ForeignKey('user.account_number'))
    auto_invest_bot_enabled = Column(Boolean, default=False)

    user = relationship("User", back_populates="account")
    assets = relationship("UserAsset", back_populates="account")
    subscriptions = relationship("Subscription", back_populates="account")


class RevokedToken(db.Model):
    __tablename__ = 'revoked_tokens'

    id = Column(Integer, primary_key=True)
    token = Column(String(500), unique=True, nullable=False)
    revoked_at = Column(DateTime, default=datetime.now(timezone.utc))


class OTP(db.Model):

    id = Column(Integer, primary_key=True)
    identifier = Column(String(255), nullable=False) 
    otp = Column(String(6), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime, default=lambda: datetime.now(timezone.utc) + timedelta(minutes=5))
    current_datetime = Column(DateTime, nullable=True)

    def is_valid(self):
        if self.current_datetime:
            return self.current_datetime < self.expires_at
        return False


class Transaction(db.Model):
    id = Column(Integer, primary_key=True, autoincrement=True)
    amount = Column(Float, nullable=False)
    transaction_type = Column(String(20), nullable=False)
    transaction_date = Column(DateTime, default=datetime.now(timezone.utc))
    source_account_number = Column(String(36), ForeignKey('account.user_account_number'), nullable=False)
    target_account_number = Column(String(36),nullable=True)

    source_account = relationship("Account", foreign_keys=[source_account_number])
    

class UserAsset(db.Model):

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_account_number = Column(String(36), ForeignKey('account.user_account_number'), nullable=False)
    asset_symbol = Column(String(10), nullable=False)
    amount = Column(Float, nullable=False)
    purchase_price = Column(Float, nullable=False)
    quantity = Column(Float, default=0.0)

    account = relationship("Account", back_populates="assets")

class Subscription(db.Model):
    id = Column(Integer, primary_key=True)
    user_account_number = Column(String(36), ForeignKey('account.user_account_number'), nullable=False)
    amount = Column(Float, nullable=False)
    interval_seconds = Column(Integer, nullable=False)
    next_payment = Column(DateTime, default=datetime.now(timezone.utc))

    account = relationship("Account", back_populates="subscriptions")