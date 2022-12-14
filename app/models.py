from flask_login import UserMixin
from flask import Flask
from app.database import db
import hashlib

app = Flask(__name__)


class User(UserMixin,db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    account_status = db.Column(db.Integer, default="1")
    role = db.Column(db.String(80), default="User")

    
    def __init__(self,username,password_hash,account_status,role):
        self.user_id = User.id
        self.username = username
        self.password_hash = password_hash
        self.account_status = account_status
        self.role = role
    
    def set_password(self, password, username):
        salt = bytes(str(id) + username, "utf-8")
        print(salt,"password salt")
        hashed_password = hashlib.pbkdf2_hmac(
            "sha256",  # The hashing algorithm to use
            password.encode(),  # The password to hash, as bytes
            salt,  # The salt to use, as bytes
            100000  # The number of iterations to use
        )
        self.password_hash=str(hashed_password.hex())
        print(self.password_hash,"pw hash")
        # self.password_hash = generate_password_hash(password)

    def check_password(self, password, username):
        salt = bytes(str(id) + username, "utf-8")
        hashed_user_password = hashlib.pbkdf2_hmac(
            "sha256",  # The hashing algorithm to use
            password.encode(),  # The password to hash, as bytes
            salt,  # The salt to use, as bytes
            100000  # The number of iterations to use
        )
        print(hashed_user_password)
        hash_login_password=str(hashed_user_password.hex())
        if hash_login_password == self.password_hash:
            return True
        else:
            return False
        # return check_password_hash(self.password_hash, password)
    
    def set_user_id(self, user_id):
        self.user_id = user_id
    
    def set_role(self, role):
        self.role = role
    
    def set_username(self, username):
        self.username = username
    
    def set_password_hash(self, password_hash):
        self.password_hash = password_hash
    
    def set_account_status(self, account_status):
        self.account_status = account_status
    
    def get_id(self):
        return self.id
    
    def get_role(self):
        return self.role
    
    def get_username(self):
        return self.username
    
    def get_password_hash(self):
        return self.password_hash
    
    def get_account_status(self):
        return self.account_status
    