from flask_login import UserMixin
from flask import Flask
from app.database import db,db2
import hashlib, uuid, re

app = Flask(__name__)


class User(UserMixin,db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(80), default="User")
    first_name = db.Column(db.String(20))
    last_name = db.Column(db.String(20))
    gender = db.Column(db.String(6), default="Female")
    title = db.Column(db.String(10), default="Mr")
    email = db.Column(db.String(255))
    account_salt = db.Column(db.String(255))
    account_status = db.Column(db.String(10), default="enabled")
    multifactorauth = db.Column(db.String(10), default="disabled")

    def __init__(self,username,email,password_hash,role,title,first_name,last_name,gender,account_status,account_salt,multifactorauth):
        self.user_id = User.id
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.first_name = first_name
        self.last_name = last_name
        self.gender = gender
        self.title = title
        self.email = email
        self.account_status = account_status
        self.account_salt  = account_salt
        self.multifactorauth = multifactorauth
    
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
        print(f"Hash Password:{hashed_password} String: {str(hashed_password.hex().encode('UTF-8'))}" )
        print(hashed_password,"byte")
        self.password_hash=hashed_password.hex()
        print(bytes(self.password_hash.encode('UTF-8')),"pw hash")
        # self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        print(self.account_salt)
        # salt = bytes(self.account_salt.encode('UTF-8')
        if isinstance(self.account_salt,bytes):
            salt = self.account_salt
        else:
            salt = bytes(self.account_salt.encode('UTF-8'))
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
    
    def set_multifactorauth(self,multifactorauth):
        self.multifactorauth = multifactorauth
    
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
    
    def get_multifactorauth(self):
        return self.multifactorauth

# class Order(UserMixin,db.Model):
#     count_id = 0
#     __tablename__ = 'orders'
#     id = db2.Column(db2.Integer, primary_key=True)
#     order_item = db2.Column(db2.String(50))
#     meat = db2.Column(db2.String(50))
#     sauce = db2.Column(db2.String(50))
#     remarks = db2.Column(db2.String(50))
#     price = db2.Column(db2.Float)
#     email = db2.Column(db2.String(50))
#     user_id = db2.Column(db2.Integer, db2.ForeignKey('user.id', ondelete='CASCADE'), nullable=False)
    
#     def __init__(self, order_item, meat, sauce, remarks, price, email):
#         Order.count_id += 1
#         self.__order_id = Order.count_id
#         self.__order_item = order_item
#         self.__meat = meat
#         self.__sauce = sauce
#         self.__remarks = remarks
#         self.__price = price
#         self.__email = email

#     def get_order_id(self):
#         return self.__order_id

#     def get_order_item(self):
#         return self.__order_item

#     def get_meat(self):
#         return self.__meat

#     def get_sauce(self):
#         return self.__sauce

#     def get_remarks(self):
#         return self.__remarks

#     def get_price(self):
#         return self.__price

#     def get_email(self):
#         return self.__email

#     def set_order_id(self, order_id):
#         self.__order_id = order_id

#     def set_order_item(self, order_item):
#         self.__order_item = order_item

#     def set_meat(self, meat):
#         self.__meat = meat

#     def set_sauce(self, sauce):
#         self.__sauce = sauce

#     def set_remarks(self, remarks):
#         self.__remarks = remarks

#     def set_price(self, price):
#         self.__price = price

#     def set_email(self, email):
#         self.__email = email