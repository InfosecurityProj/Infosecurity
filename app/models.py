from flask_login import UserMixin
from werkzeug.security import generate_password_hash,check_password_hash
from flask import Flask
from app.database import db

app = Flask(__name__)


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True)
    role = db.Column(db.String(80), default="User")
    
    def __init__(self,username,password_hash,is_active,role):
        self.user_id = User.id
        self.username = username
        self.password_hash = password_hash
        self.is_active = is_active
        self.role = role
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def set_user_id(self, user_id):
        self.user_id = user_id
    
    def set_role(self, role):
        self.role = role
    
    def set_username(self, username):
        self.username = username
    
    def set_password_hash(self, password_hash):
        self.password_hash = password_hash
    
    def set_is_active(self, is_active):
        self.is_active = is_active
    
    def get_id(self):
        return self.id
    
    def get_role(self):
        return self.role
    
    def get_username(self):
        return self.username
    
    def get_password_hash(self):
        return self.password_hash
    
    def is_active(self):
        return self.is_active
    
    def is_authenticated(self):
        return True
    
    
    
