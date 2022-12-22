from flask_login import UserMixin
from flask import Flask
from app.database import db
import hashlib, uuid, re

app = Flask(__name__)


class User(UserMixin,db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    account_status = db.Column(db.Integer, default="1")
    role = db.Column(db.String(80), default="User")
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(20))
    title = db.Column(db.String(5), default="Female")
    title = db.Column(db.String(3), default="Mr")
    email = db.Column(db.String(255))
    account_salt = db.Column(db.String(255))

    def __init__(self,username,email,password_hash,account_status,role,title,first_name,last_name,gender):
        self.user_id = User.id
        self.username = username
        self.password_hash = password_hash
        self.account_status = account_status
        self.role = role
        self.first_name = first_name
        self.last_name = last_name
        self.gender = gender
        self.title = title
        self.email = email
        self.account_salt = User.account_salt
    
    def set_password(self, password):
        Useruuid = str(uuid.uuid4())[:8].encode('utf-8')
        salt = bytes(hashlib.sha256(Useruuid).hexdigest(), "utf-8")
        self.account_salt = salt
        print(salt,"password salt")
        hashed_password = hashlib.pbkdf2_hmac(
            "sha256",  # The hashing algorithm to use
            password.encode(),  # The password to hash, as bytes
            salt,  # The salt to use, as bytes
            100000  # The number of iterations to use
        )
        print(hashed_password)
        self.password_hash=str(hashed_password.hex())
        print(self.password_hash,"pw hash")
        # self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        salt = self.account_salt
        print(salt,"password salt")
        hashed_user_password = hashlib.pbkdf2_hmac(
            "sha256",  # The hashing algorithm to use
            password.encode(),  # The password to hash, as bytes
            salt,  # The salt to use, as bytes
            100000  # The number of iterations to use
        )
        print(hashed_user_password)
        hash_login_password=str(hashed_user_password.hex())
        print(hash_login_password,"hash login password")
        if hash_login_password == self.password_hash:
            print("password hash match")
            return True
        elif hash_login_password != self.password_hash:
            print("password hash does not match")
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
        
    def set_first_name(self, first_name):
        self.first_name = first_name

    def set_last_name(self, last_name):
        self.last_name = last_name

    def set_gender(self, gender):
        self.gender = gender

    def set_title(self, title):
        self.title = title
        
    def set_email(self, email):
        self.email = email
    
    def set_account_salt(self,account_salt):
        self.account_salt = account_salt
    
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
    
    def get_first_name(self):
        return self.first_name

    def get_last_name(self):
        return self.last_name

    def get_gender(self):
        return self.gender

    def get_title(self):
        return self.title
    
    def get_email(self):
        return self.email
    
    def get_account_salt(self):
        return self.account_salt