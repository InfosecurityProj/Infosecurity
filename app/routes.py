from flask import Flask,request,flash,render_template,make_response,redirect,url_for,session
from flask_login import LoginManager,login_required,logout_user,current_user,login_user
from flask_sqlalchemy import SQLAlchemy
from app.Forms import *
from app.models import User
from app.database import db

app = Flask(__name__)
app.secret_key = 'NahidaKawaii'
login_manager = LoginManager()
login_manager.init_app(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test1.db"
db.init_app(app)

with app.app_context():
    db.create_all()
    users = User.query.all()
    print(users)
    if User.query.filter_by(username="admin").first():
    # The "admin" username already exists, so handle the error
    # ...
        print("admin exist")
        pass
    else:
        # The "admin" username does not exist, so create a new user
        user=User(username="admin",password_hash="7d6c1c4b5e4172025422498f0833953fe5c4d1ecda84c8d4e6ecb8a845d3f453",account_status="1",role="Administrator")
        db.session.add(user)
        db.session.commit()
        
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        # print(user.check_password(password),"passwordcheck")
        if user is None or not user.check_password(password,username):
            flash('Invalid username or password.')
            return redirect(url_for('login'))
        elif user.get_account_status == "0":
            flash('Account is disabled.')
            return redirect(url_for(index))
        login_user(user)
        return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    create_user_form = CreateUserForm(request.form)
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['first_name']
        password = request.form['password']
        user = User(username=username,password_hash=password,account_status="1",role="User")
        user.set_password(password,username)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('register.html', form=create_user_form)

@app.route('/retrieving')
def retrieving_users():
    if not session.get('type'):
        session['type'] = 'guest'
    if current_user.is_authenticated :
        if current_user.get_role() == "Administrator" :  # edited to prevent path traversal
            response = make_response(render_template('retrieving.html'))
            return response
        else:
            resp = make_response(redirect(url_for('index')))
            return resp
    else:
        flash("You have been logged out due to 30 minutes of inactivity. Please re-login again.")
        resp = make_response(redirect(url_for('login')))
        return resp


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logout successful!")
    return redirect(url_for("login"))
