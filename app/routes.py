from flask import Flask,request,flash,render_template,make_response,redirect,url_for,session
from flask_login import LoginManager,login_required,logout_user,current_user,login_user
from sqlalchemy import or_
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
        print("admin exist")
        pass
    else:
        # The "admin" username does not exist, so create a new user
        admin=User(username="admin",email="admin@gmail.com",password_hash="7a14def6c43d661e14c59a3dd7174f617137b338ea128d428868e677dc3bed00",account_status="1",role="Administrator",
                        title="Mister",first_name="admin",last_name=" ",gender="M",account_salt="7f7ae7b152053e0e99d2db2cdb8caea759c473353322c8de03798357c0810b88")
        kurokami=User(username="kurokami",email="kuro@gmail.com",password_hash="93c8033745689de41d5966ef63f56cf0d608658c284509eefd75de2335459c7f",account_status="1",role="Administrator",
                        title="Mister",first_name="kurokami",last_name="desu",gender="M",account_salt="845a111eb9585de318efd85a4810099eeb82903cc3b89c8b9ccfd6a5288dcea8")
        db.session.add(admin)
        db.session.add(kurokami)
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
        email = request.form['email']
        password = request.form['password']
        # user = User.query.filter_by(username=username).first()
        user = User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first()
        # user,useremail = User.query.filter_by(username=username).first(),User.query.filter_by(email=email).first()
        # user = User.query.filter(or_(username==username,email==email)).first()
        print(user)
        # print(user.check_password(password),"passwordcheck")
        # if user.get_account_status == 0:
        #     print("account disbaled")
        #     flash('Account is disabled.Contact support for help.')
        #     return redirect(url_for('login'))
        # print(user.get_account_status,"account_status")
        if user is None or not user.check_password(password):
            flash('Invalid username or password.')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('index'))
    return render_template('login.html', form=CreateUserForm)

@app.route('/register', methods=['GET', 'POST'])
def register():
    create_user_form = CreateUserForm(request.form)
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST' :
            username = request.form['username']
            password = request.form['password']
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            gender = request.form['gender']
            title = request.form['title']
            email = request.form['email']
            user = User(username=username,email=email,password_hash=password,account_status="1",role="User",
                        title=title,first_name=first_name,last_name=last_name,gender=gender)
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            flash('Congratulations, you are now a registered user!')
            return redirect(url_for('login'))
    return render_template('register.html', form=create_user_form)

@app.route('/retrieving')
def retrieving_users():
    if not session.get('type'):
        session['type'] = 'guest'
    if current_user.is_authenticated:
        if current_user.get_role() == "Administrator" :  # edited to prevent path traversal
            users = User.query.all()
            response = make_response(render_template('retrieving.html', users=users))
            return response
        else:
            resp = make_response(redirect(url_for('index')))
            return res**p
    else:
        flash("You have been logged out due to 30 minutes of inactivity. Please re-login again.")
        resp = make_response(redirect(url_for('login')))
        return resp

# profile
@app.route("/profile")
def profile():
    if not session.get('type'):
        session['type'] = 'guest'
    if current_user.get_role() == "Administrator":
        resp = make_response(render_template('profile.html'))
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
