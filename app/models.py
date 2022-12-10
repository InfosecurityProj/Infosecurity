from flask_login import UserMixin
from werkzeug.security import generate_password_hash,check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask import Flask
from app.database import db

app = Flask(__name__)

class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    is_suspended = db.Column(db.Boolean, default=False)
    
    def __init__(self,id, username, password_hash,is_suspended):
        self.id = id
        self.username = username
        self.password_hash = password_hash
        self.is_suspended = is_suspended
        
    @property
    def is_active(self):
        return not self.is_suspended
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
