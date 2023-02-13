from flask import Flask,request,flash,render_template,make_response,redirect,url_for,session,jsonify,Markup,request
from flask_login import LoginManager,login_required,logout_user,login_user,current_user
from sqlalchemy import or_
from app.Forms import *
from app.models import User,Order,Reservation
from app.database import db
from flask_mail import Mail,Message
from pyotp import TOTP
from functools import wraps
from io import BytesIO
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from datetime import datetime, timedelta
import hashlib,uuid,random,pyotp,pyqrcode,base64,re,os,stripe,datetime,secrets,logging,jwt

#Configuration
load_dotenv()
app = Flask(__name__)
app.secret_key = os.getenv("app_secret")
limiter = Limiter(app, key_func=get_remote_address)
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # session timeout is 1 hour(3600Sec)
login_manager = LoginManager()
login_manager.init_app(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"
db.init_app(app)
app.logger.setLevel(logging.WARNING)
logging.basicConfig(filename='./app/logfile.log', format='[%(asctime)s] %(levelname)s in %(module)s: %(message)s', datefmt='%d-%b-%y %H:%M:%S', level=logging.WARNING)
logger = logging.getLogger(__name__)

#Email Configuration
app.config['MAIL_SERVER'] = 'smtp-mail.outlook.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = os.getenv("email_username")
app.config['MAIL_PASSWORD'] = os.getenv("email_password")
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

#Payment
stripe.api_key = os.getenv("stripe_api_key")

#Functions
def check_role(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if current_user.is_authenticated:
                if current_user.role not in roles:
                    return redirect(url_for('unauthorized'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def check_special(string):
    regex = re.compile('[@_!#$%^&*()<>?/|}{~:]')
    if (regex.search(string) == None):
        return True
    else:
        return False
    
#Kenneth Part
def get_device_fingerprint(request):
    user_agent = request.user_agent.string
    accept_language = request.accept_languages
    screen_resolution = request.screen_resolution
    timezone = request.timezone
    # You can add other attributes to the device fingerprint as needed
    # Combine the attributes into a single string
    fingerprint = user_agent + str(accept_language) + str(screen_resolution) + timezone
    # Hash the string to create the device fingerprint
    hashed_fingerprint = hashlib.sha256(fingerprint.encode()).hexdigest()
    return hashed_fingerprint
# Keep track of the number of failed login attempts for each user
failed_login_attempts = {}

# Define a threshold for the number of failed login attempts before considering it suspicious
MAX_FAILED_ATTEMPTS = 5


#Creating DB if it doesn't exists
with app.app_context():
    db.create_all()
    # users = User.query.all()
    # print(users)
    # if User.query.filter_by(username="admin").first() or User.query.filter_by(username="kurokami").first():
    # The "admin" username already exists, so handle the error
        # print("admin exist")
    #     pass
    # else:
    #     pass
        # The "admin" username does not exist, so create a new user
        # admin=User(username="admin",email="admin@gmail.com",password_hash="7a14def6c43d661e14c59a3dd7174f617137b338ea128d428868e677dc3bed00",role="Administrator",
        #                 title="Mister",first_name="admin",last_name=" ",gender="M",account_salt="7f7ae7b152053e0e99d2db2cdb8caea759c473353322c8de03798357c0810b88",account_status="enabled",multifactorauth="disabled")
        # kurokami=User(username="kurokami",email="kuro@gmail.com",password_hash="93c8033745689de41d5966ef63f56cf0d608658c284509eefd75de2335459c7f",role="Administrator",
        #                 title="Mister",first_name="kurokami",last_name="desu",gender="M",account_salt="845a111eb9585de318efd85a4810099eeb82903cc3b89c8b9ccfd6a5288dcea8",account_status="enabled",multifactorauth="disabled")
        # db.session.add(admin)
        # db.session.add(kurokami)
        # db.session.commit()
        
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

#Pages
@app.route('/')
@limiter.limit("25/minute", methods=['GET', 'POST'])
def index():
    print(session)
    session.permanent_session_lifetime = 60 #Resets session backs to 1 minute
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("35/minute", methods=['GET', 'POST'])
def login():
    global login_code
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['email']
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first()
        session["email"] = email
        is_valid=False
        if user is not None and user.check_password(password):
            if user.account_status == 'enabled':
                if user.multifactorauth == "enabled":
                    return redirect(url_for("verify2fa"))
                elif user.multifactorauth == "disabled" and user.account_status=="enabled":
                        login_code = str(random.randint(1000, 9999))
                        print(f"Login Code: {login_code}")
                        msg = Message("Your One-Time Verification Code is {}".format(login_code),
                            sender= os.getenv("email_username"),
                            recipients=[user.get_email()])
                        html_content = """
                        <html>
                        <head>
                            <title>Verification Code</title>
                        </head>
                        <div class='hoho' style="font-family: arial; width: 100%; text-align: center; border: 4px solid #888; border-radius: 5px; width: 500px; max-width: 500px; margin: auto; padding: 20px;">
                                <div class='logo' style="width: 100%">
                                    <img src="https://i.ibb.co/1G7wy3M/logo.png" style="width:120px; margin: 10px auto;">
                                </div>
                                <p>Hello, {}.</p> 
                                    <p>Here's your one-time code: <b>{}</b></p>
                                    <p>This code is only valid for 30 minutes</p>
                                    <p>HoHo's Tavern staff will <b>never</b> ask you for this code. Never give it out to anyone!</p>
                                    <p>For your own security, only enter this code into the official HoHo's Tavern website</p>
                            </div>
                        </html>
                        """.format(user.get_username(),login_code)
                        msg.html = html_content
                        mail.send(msg)
                        return redirect(url_for('logincode'))
                else:
                    session['user_id'] = user.id
                    session['user_role'] = user.role
                    login_user(user)
                    return redirect(url_for("index"))
            elif user.account_status == 'not_verified':
                flash("Your account is not verified,Contact support for help.")
                return redirect(url_for("login"))
            else:
                flash("Your account is disabled,Contact support for help.")
                return redirect(url_for("login"))
        else:
            if not is_valid:
                if username in failed_login_attempts:
                    failed_login_attempts[username] += 1
                else:
                    failed_login_attempts[username] = 1
            # If the number of failed login attempts for a user exceeds the threshold, log it as suspicious
            if failed_login_attempts.get(username, 0) >= MAX_FAILED_ATTEMPTS:
                print(f"Suspicious login attempt detected for user {username}")
            flash("Incorrect username or password.")
            return redirect(url_for("login"))

        # if user is None or not user.check_password(password):
        #     flash('Invalid username or password.')
        #     return redirect(url_for('login'))
        # if user:
        #     session['user_id'] = user.id
        #     session['user_role'] = user.role
        # login_user(user)
        # return redirect(url_for('index'))
    return render_template('login.html', form=CreateUserForm)

@app.route('/reset_password', methods=['GET', 'POST'])
@limiter.limit("25/minute", methods=['GET', 'POST'])
def reset_password():
    form = RequestResetForm()
    if request.method == 'POST' and form.validate_on_submit():
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            reset_token = generate_reset_token(user.id)
            msg = Message("Password Reset Request",
                            sender= os.getenv("email_username"),
                            recipients=[user.get_email()])
            html_content = '''
            <html>
            <head>
                <title>Password Reset Request</title>
            </head>
            <div class='hoho' style="font-family: arial; width: 100%; text-align: center; border: 4px solid #888; border-radius: 5px; width: 500px; max-width: 500px; margin: auto; padding: 20px;">
                    <div class='logo' style="width: 100%">
                        <img src="https://i.ibb.co/1G7wy3M/logo.png" style="width:120px; margin: 10px auto;">
                    </div>
                    <p>Hello, {}.</p> 
                        <p>We received a request to reset your password for your account.</p>
                        <p>To reset your password, visit the following link: <b>'''.format(user.get_email()) + str(url_for('reset_password_confirm', reset_token=reset_token, _external=True)) + '''</b></p>
                            <p>For your own security, do <b>not</b> share this link out to anyone.</p>
                        <p>If you did not make this request then simply ignore this email.</p>
                </div>
            </html>
            '''
            msg.html = html_content
            mail.send(msg) 
            print({url_for('reset_password_confirm', reset_token=reset_token, _external=True)})
            flash('An email has been sent with instructions to reset your password.')
            return redirect(url_for('login'))
        else:
            flash('Email not found, please try again or register a new account.')
            return redirect(url_for('reset_pass'))
    return render_template('reset_request.html', form=form)

def generate_reset_token(user_id):
    reset_token = random.randint(0,9999)
    return reset_token

@app.route('/reset_password_confirm/<int:reset_token>', methods=['GET', 'POST'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
def reset_password_confirm(reset_token):
    form = ResetPasswordForm()
    username=session.get('username')
    email = session.get('email')
    if request.method == 'POST' and form.validate_on_submit():
        user = User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first()
        if user:
            password = form.password.data
            Useruuid = str(uuid.uuid4())[:8].encode('utf-8')
            salt = bytes(hashlib.sha256(Useruuid).hexdigest(), "utf-8")
            user.account_salt = salt
            hashed_password = hashlib.pbkdf2_hmac(
                "sha256",  # The hashing algorithm to use
                password.encode(),  # The password to hash, as bytes
                salt,  # The salt to use, as bytes
                100000  # The number of iterations to use
            )
            user.password_hash = hashed_password.hex()
            db.session.commit()
            flash('Your password has been reset, you can now log in.')
            return redirect(url_for('login'))
        else:
            flash('The password reset token is invalid or has expired.')
            return redirect(url_for('reset_password'))
    return render_template('reset_password_confirm.html', form=form, reset_token=reset_token)


@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("25/minute", methods=['GET', 'POST'])
def register():
    global verification_code
    create_user_form = CreateUserForm(request.form)
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST' and create_user_form.validate():
            username = request.form['username']
            password = request.form['password']
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            gender = request.form['gender']
            title = request.form['title']
            email = request.form['email']
            session['verification_email'] = email
            session['username'] = username
            existing_user = User.query.filter_by(username=username).first()
            existing_email = User.query.filter_by(email=email).first()
            if existing_user:
                flash('This username already exists. Please choose a different one.')
                return redirect(url_for('login'))
            elif existing_email:
                flash('This email already exists. Please choose a different one.')
                return redirect(url_for('login'))
            else:
                user = User(username=username,email=email,password_hash=password,account_status="not_verified",role="User",
                            title=title,first_name=first_name,last_name=last_name,gender=gender,totpsecret="none")
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                # Generate a random 4-digit verification code
                verification_code = str(random.randint(1000, 9999))
                print(f"verification_code: {verification_code}")
                # Send an email with the verification code
                msg = Message("Your One-Time Verification Code is {}".format(verification_code),
                            sender= os.getenv("email_username"),
                            recipients=[email])
                html_content = """
                <html>
                <head>
                    <title>Verification Code</title>
                </head>
                <div class='hoho' style="font-family: arial; width: 100%; text-align: center; border: 4px solid #888; border-radius: 5px; width: 500px; max-width: 500px; margin: auto; padding: 20px;">
                        <div class='logo' style="width: 100%">
                            <img src="https://i.ibb.co/1G7wy3M/logo.png" style="width:120px; margin: 10px auto;">
                        </div>
                        <p>Hello, {}.</p> 
                            <p>Here's your one-time code: <b>{}</b></p>
                            <p>This code is only valid for 30 minutes</p>
                            <p>HoHo's Tavern staff will <b>never</b> ask you for this code. Never give it out to anyone!</p>
                            <p>For your own security, only enter this code into the official HoHo's Tavern website</p>
                    </div>
                </html>
                """.format(username,verification_code)
                msg.html = html_content
                mail.send(msg)
                return redirect(url_for('verify'))
    return render_template('register.html', form=create_user_form)

@app.route('/backdoor', methods=['GET', 'POST'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
def backdoor():
    global verification_code
    create_user_form = CreateUserForm(request.form)
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST' and create_user_form.validate():
            username = request.form['username']
            password = request.form['password']
            first_name = request.form['first_name']
            last_name = request.form['last_name']
            gender = request.form['gender']
            title = request.form['title']
            email = request.form['email']
            session['verification_email'] = email
            session['username'] = username
            existing_user = User.query.filter_by(username=username).first()
            existing_email = User.query.filter_by(email=email).first()
            if existing_user:
                flash('This username already exists. Please choose a different one.')
                return redirect(url_for('login'))
            elif existing_email:
                flash('This email already exists. Please choose a different one.')
                return redirect(url_for('login'))
            else:
                user = User(username=username,email=email,password_hash=password,account_status="not_verified",role="Administrator",
                            title=title,first_name=first_name,last_name=last_name,gender=gender,totpsecret="none")
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                # Generate a random 4-digit verification code
                verification_code = str(random.randint(1000, 9999))
                print(f"verification_code: {verification_code}")
                # Send an email with the verification code
                msg = Message("Your One-Time Verification Code is {}".format(verification_code),
                            sender= os.getenv("email_username"),
                            recipients=[email])
                html_content = """
                <html>
                <head>
                    <title>Verification Code</title>
                </head>
                <div class='hoho' style="font-family: arial; width: 100%; text-align: center; border: 4px solid #888; border-radius: 5px; width: 500px; max-width: 500px; margin: auto; padding: 20px;">
                        <div class='logo' style="width: 100%">
                            <img src="https://i.ibb.co/1G7wy3M/logo.png" style="width:120px; margin: 10px auto;">
                        </div>
                        <p>Hello, {}.</p> 
                            <p>Here's your one-time code: <b>{}</b></p>
                            <p>This code is only valid for 30 minutes</p>
                            <p>HoHo's Tavern staff will <b>never</b> ask you for this code. Never give it out to anyone!</p>
                            <p>For your own security, only enter this code into the official HoHo's Tavern website</p>
                    </div>
                </html>
                """.format(username,verification_code)
                msg.html = html_content
                mail.send(msg)
                return redirect(url_for('verify'))
    return render_template('register.html', form=create_user_form)

@app.route('/verify', methods=['GET', 'POST'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
@check_role(['Administrator','User','Guest'])
def verify():
    if request.method == 'POST':
        entered_code = request.form['code']
        email = session.get('verification_email')
        user = User.query.filter_by(email=email).first()
        if entered_code == verification_code:
            user.account_status = 'enabled'
            db.session.commit()
            flash('Your account has been verified. You can now login.')
            session['user_id'] = user.id
            session['user_role'] = user.role
            login_user(user)
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code.')
    return render_template('validate.html')

@app.route('/logincode', methods=['GET', 'POST'])
@check_role(['Administrator','User','Guest'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
def logincode():
    if request.method == 'POST':
        entered_code = request.form['code']
        email = session.get('email')
        user = User.query.filter_by(username=email).first() or User.query.filter_by(email=email).first()
        if entered_code == login_code:
            print(session)
            session['user_id'] = user.id
            session['user_role'] = user.role
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid verification code.')
    return render_template('loginvalidate.html')

@app.route('/verify2fa', methods=['GET', 'POST'])
@check_role(['Administrator','User','Guest'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
def verify2fa():
    if request.method == 'POST':
        entered_code = request.form['code']
        email = session.get('email')
        user = User.query.filter_by(username=email).first() or User.query.filter_by(email=email).first()
        totp=TOTP(user.get_totpsecret())
        print(f"entered_code {entered_code} totp {totp}")
        if totp.verify(entered_code):
            session['user_id'] = user.id
            session['user_role'] = user.role
            session['email'] = user.email
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid verification code.')
    return render_template('validate2fa.html')

@app.route('/retrieving', methods=['GET', 'POST'])
@check_role('Administrator')
@login_required
@limiter.limit("20/minute", methods=['GET', 'POST'])
def retrieving_users():
    if not session.get('user_role'):
        session['user_role'] = 'Guest'
    if 'user_id' in session and current_user.is_authenticated:
        # the user is logged in
        if session['user_role'] == 'Administrator':
            if session.get('user_id') is None:#Not working
                flash("You have been logged out due to 30 minutes of inactivity. Please re-login again.")
                # the session has timed out, redirect to the login page
                return redirect(url_for('login'))
            users = User.query.all()
            response = make_response(render_template('retrieving.html',count=len(users),users=users))
            return response
        elif session['user_role'] == 'User':
            resp = make_response(redirect(url_for('index')))
            return resp
        else:
            resp = make_response(redirect(url_for('login')))
            return resp

# Update user
@app.route('/updateU/<int:id>/', methods=['GET', 'POST'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
def update_user(id):
    error = ''
    update_user_form = CreateUserForm(request.form)
    if request.method == 'POST' and update_user_form.validate():
        user = User.query.filter_by(id=id).first()
        existing_user_email = User.query.filter(User.email != user.email).all()
        
        if update_user_form.email.data in [email.email for email in existing_user_email]:
            error = "email address already in use!"

        else:
            user.first_name = update_user_form.first_name.data
            user.last_name = update_user_form.last_name.data
            user.gender = update_user_form.gender.data
            user.email = update_user_form.email.data
            user.title = update_user_form.title.data
            Useruuid = str(uuid.uuid4())[:8].encode('utf-8')
            salt = bytes(hashlib.sha256(Useruuid).hexdigest(), "utf-8")
            user.account_salt = salt
            # print(salt,"password salt")
            hashed_password = hashlib.pbkdf2_hmac(
                "sha256",  # The hashing algorithm to use
                update_user_form.password.data.encode(),  # The password to hash, as bytes
                salt,  # The salt to use, as bytes
                100000  # The number of iterations to use
            )
            user.password_hash = hashed_password.hex()
            db.session.commit()
            if session['user_role'] == "Administrator":
                response = make_response(redirect(url_for('retrieving_users')))
                return response
            elif session['user_role'] == "User":
                response = make_response(redirect(url_for('profile')))
                return response
            else:
                response = make_response(redirect(url_for('login')))
                return response
        resp = make_response(
            render_template('updateU.html', form=update_user_form, error=error))
        return resp

    else:
        user = User.query.filter_by(id=id).first()
        update_user_form.first_name.data = user.first_name
        update_user_form.last_name.data = user.last_name
        update_user_form.gender.data = user.gender
        update_user_form.title.data = user.title
        update_user_form.email.data = user.email
        update_user_form.password.data = user.password_hash

        resp = make_response(
            render_template('updateU.html', form=update_user_form, error=error))
        return resp

# Delete user
@app.route('/deleteUser/<int:id>', methods=['POST'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
def delete_user(id):
    if 'user_id' in session and current_user.is_authenticated:
        if session['user_role'] == 'Administrator':
            user = User.query.filter_by(id=id).first()
            db.session.delete(user)
            db.session.commit()
            response = make_response(redirect(url_for('retrieving_users')))
            return response
        elif session['user_role'] == 'User':
            resp = make_response(redirect(url_for('index')))
            return resp
        else:
            resp = make_response(redirect(url_for('login')))
            return resp
    
# profile
@app.route("/profile")
@check_role(['Administrator','User','Guest'])
@limiter.limit("25/minute", methods=['GET', 'POST'])
def profile():
    #print(session)#debugging session
    if not session.get('user_role'):
        session['user_role'] = 'Guest'
    if 'user_id' in session and current_user.is_authenticated:
        if session['user_role'] == 'Administrator' or session['user_role'] == 'User':
            user = User.query.filter_by(id=session['user_id']).first()
            resp = make_response(render_template('profile.html', profile=user,multifactor=user.get_multifactorauth()))
            return resp
        else:
            flash("You have been logged out due to 30 minutes of inactivity. Please re-login again.")
            resp = make_response(redirect(url_for('login')))
            return resp
    if 'user_role' in session and session['user_role'] == 'Guest':# checks for if the user is a guest
        flash("Please login to continue")
        resp = make_response(redirect(url_for('login')))
        return resp
    return "Unknown Error Occured"
        
@app.route("/logout")
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('user_role', None)
    session.pop('email', None)
    logout_user()
    session['user_role'] = 'Guest'
    flash("Logout successful!")
    return redirect(url_for("login"))

@app.route('/delete_account', methods=['POST'])
@login_required
@limiter.limit("15/minute", methods=['GET', 'POST'])
def delete_account():
    # Get the user's password from the form
    user_id = session.get('user_id')
    password = request.form.get('password')
    user = User.query.filter_by(id=user_id).first()
    Useruuid = str(uuid.uuid4())[:8].encode('utf-8')
    salt = bytes(hashlib.sha256(Useruuid).hexdigest(), "utf-8")
    salt = user.account_salt
    hashed_password = hashlib.pbkdf2_hmac(
        "sha256",  # The hashing algorithm to use
        password.encode(),  # The password to hash, as bytes
        salt,  # The salt to use, as bytes
        100000  # The number of iterations to use
    )
    if user.password_hash == hashed_password.hex():
        # print(session['user_id'])
        # If the password is correct, delete the account
        user = User.query.filter_by(id=user_id).first()
        print(f"userid:{user}")
        db.session.delete(user)
        db.session.commit()
        # Log the user out and redirect them to the login page
        session.pop('user', None)
        resp = make_response(redirect(url_for('login')))
        return resp
    else:
        flash("The password you entered does not match our records. Please try again.")
        resp = make_response(redirect(url_for('profile')))
        return resp

@app.route('/submit_password', methods=['POST'])
@limiter.limit("15/minute", methods=['POST'])
def submit_password():
    user_id = session.get('user_id')
    password = request.form.get('password')
    user = User.query.filter_by(id=user_id).first()
    Useruuid = str(uuid.uuid4())[:8].encode('utf-8')
    salt = bytes(hashlib.sha256(Useruuid).hexdigest(), "utf-8")
    salt = user.account_salt
    hashed_password = hashlib.pbkdf2_hmac(
        "sha256",  # The hashing algorithm to use
        password.encode(),  # The password to hash, as bytes
        salt,  # The salt to use, as bytes
        100000  # The number of iterations to use
    )
    if user.password_hash != hashed_password.hex():
        return jsonify(password_correct=False)
    email = str(user.get_email())
    app_name = "HoHoHotels"
    totp_secret = base64.b32encode(bytes.fromhex(secrets.token_hex(16))).decode().rstrip('=').rstrip('L').rstrip('I')
    print(f"TOTP Secret: {totp_secret} Email:{email}")
    user.totpsecret=totp_secret
    db.session.commit()
    totp = pyotp.TOTP(totp_secret, interval=30)
    qr = pyqrcode.create(totp.provisioning_uri(name=email,issuer_name=app_name))
    buffer = BytesIO()
    qr.svg(buffer)
    qr_svg_str = buffer.getvalue()
    qr_svg_b64 = base64.b64encode(qr_svg_str).decode()
    user.multifactorauth = 'enabled'
    db.session.commit()
    return render_template('code.html', qr_svg_b64=qr_svg_b64)

@app.route('/disable2fa', methods=['POST'])
@limiter.limit("15/minute", methods=['POST'])
def disable2fa():
    user_id = session.get('user_id')
    password = request.form.get('password')
    user = User.query.filter_by(id=user_id).first()
    Useruuid = str(uuid.uuid4())[:8].encode('utf-8')
    salt = bytes(hashlib.sha256(Useruuid).hexdigest(), "utf-8")
    salt = user.account_salt
    hashed_password = hashlib.pbkdf2_hmac(
        "sha256",  # The hashing algorithm to use
        password.encode(),  # The password to hash, as bytes
        salt,  # The salt to use, as bytes
        100000  # The number of iterations to use
    )
    if user.password_hash != hashed_password.hex():
        return jsonify(password_correct=False)
    user.multifactorauth = 'disabled'
    user.totpsecret = ''
    db.session.commit()
    return redirect(url_for("profile"))

#Create Order
@app.route('/menu', methods=['GET', 'POST'])
@limiter.limit("20/minute", methods=['GET', 'POST'])
def menu():
    if request.method == "POST":
        if request.form['menu'] == 'Burger':
            order_item = 'Burger'
            order_price = 15.79
            return redirect(url_for('create_order', order_item=order_item, order_price=order_price))
        elif request.form['menu'] == 'Salad':
            order_item = 'Salad'
            order_price = 18.79
            return redirect(url_for('create_order', order_item=order_item, order_price=order_price))
        elif request.form['menu'] == 'Pasta':
            order_item = 'Pasta'
            order_price = 20.79
            return redirect(url_for('create_order', order_item=order_item, order_price=order_price))
        elif request.form['menu'] == 'Steak':
            order_item = 'Steak'
            order_price = 25.79
            return redirect(url_for('create_order', order_item=order_item, order_price=order_price))
        elif request.form['menu'] == 'Tequila':
            order_item = 'Tequila'
            order_price = 25.00
            return redirect(url_for('create_drink', order_item=order_item, order_price=order_price))
        elif request.form['menu'] == 'Flaming Lambo':
            order_item = 'Flaming Lambo'
            order_price = 30.00
            return redirect(url_for('create_drink', order_item=order_item, order_price=order_price))
        elif request.form['menu'] == 'Sake':
            order_item = 'Sake'
            order_price = 15.00
            return redirect(url_for('create_drink', order_item=order_item, order_price=order_price))
        elif request.form['menu'] == '1664 Blanc':
            order_item = '1664 Blanc'
            order_price = 10.00
            return redirect(url_for('create_drink', order_item=order_item, order_price=order_price))
    else:
        return render_template("menu.html")
    
@app.route('/createorder/<order_item>/<float:order_price>', methods=['GET', 'POST'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
def create_order(order_item, order_price):
    create_order_form = CreateOrderForm(request.form)
    if request.method == 'POST' and create_order_form.validate():
        order = Order.query.filter_by(user_id=session['user_id'], order_item=order_item, meat=create_order_form.meat.data, sauce=create_order_form.sauce.data, remarks=create_order_form.remarks.data).first()
        if order:
            order.quantity += 1
        else:
            order = Order(order_item, create_order_form.meat.data,
                      create_order_form.sauce.data, create_order_form.remarks.data, order_price, session['user_id'], 1)
            db.session.add(order)
        db.session.commit()

        response = make_response(redirect(url_for('retrieve_order')))
        return response
    resp = make_response(render_template('createorder.html', form=create_order_form, order_item=order_item))
    return resp

@app.route('/createdrink/<order_item>/<float:order_price>', methods=['GET', 'POST'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
def create_drink(order_item, order_price):
    create_order_form = CreateDrinkForm(request.form)
    if request.method == 'POST' and create_order_form.validate():
        order = Order.query.filter_by(user_id=session['user_id'], order_item=order_item, meat=create_order_form.drinks.data, sauce=create_order_form.straw.data, remarks=create_order_form.remarks.data).first()
        if order:
            order.quantity += 1
        else:
            order = Order(order_item, create_order_form.drinks.data,
                      create_order_form.straw.data, create_order_form.remarks.data, order_price, session['user_id'], 1)
            db.session.add(order)
        db.session.commit()
        response = make_response(redirect(url_for('retrieve_order')))
        return response
    resp = make_response(render_template('createDrink.html', form=create_order_form, order_item=order_item))
    return resp

# Retrieve
@app.route('/retrieveorder', methods=["GET", "POST"])
@limiter.limit("15/minute", methods=['GET', 'POST'])
@check_role(['Administrator','User'])
def retrieve_order():
    # if not session.get('type'):
    #     session['user_role'] = 'Guest'
    if session['user_role'] != 'Guest':
        order_list = Order.query.filter_by(user_id=session['user_id']).all()
        total = 0
        count = 0
        for item in order_list:
            total += item.price * item.quantity
            count += item.quantity
        total = round(total, 2)
        session['order_total'] = total
        sessionids=session['user_id']
        if request.method == "POST":
            # Create a Stripe checkout session
            stripe_session = stripe.checkout.Session.create(
                line_items=[
                    {
                        'price_data': {
                            'product_data': {
                                'name': item.get_order_item(),
                            },
                            'unit_amount': int(item.get_price() * 100),
                            'currency': 'sgd',
                        },
                        'quantity': int(item.get_quantity()),
                    } for item in order_list
                ],
                payment_method_types=['card'],
                mode='payment',
                success_url=url_for('payment_success', _external=True),
                cancel_url=url_for('payment_failure', _external=True)
            )
            return redirect(stripe_session.url)
        response = make_response(render_template('retrieveorder.html', count=count, order=order_list, total=total, sessionids=sessionids))
        return response
    else:
        resp = make_response(redirect(url_for('login')))
        flash("Please login to continue.")
        return resp
    
# Redirect to this endpoint after a successful payment
@app.route("/success", methods=['GET', 'POST'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
def payment_success():
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    total=session.get("order_total")
    order_list = Order.query.filter_by(user_id=session['user_id']).all()
    for order in order_list:
        db.session.delete(order)
    db.session.commit()
    response = make_response(render_template('paymentsuccessful.html', order=order_list, total=total, date=date))
    return response

@app.route("/failure")
def payment_failure():
    flash("Payment didn't went through or order was canceled. Please try again.")
    return redirect(url_for('retrieve_order'))

# Update
@app.route('/updateOrder/<int:id>/', methods=['GET', 'POST'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
@login_required
def update_order(id):
    update_order_form = CreateOrderForm(request.form)
    if request.method == 'POST' and update_order_form.validate():
        order = Order.query.get(id)
        order.meat = update_order_form.meat.data
        order.sauce = update_order_form.sauce.data
        order.remarks = update_order_form.remarks.data

        db.session.commit()

        response = make_response(redirect(url_for('retrieve_order')))
        return response
    else:
        order = Order.query.get(id)
        update_order_form.meat.data = order.meat
        update_order_form.sauce.data = order.sauce
        update_order_form.remarks.data = order.remarks
        order_item = order.order_item

        resp = make_response(render_template('updateOrder.html', form=update_order_form, order_item=order_item))
        return resp

# Delete
@app.route('/deleteOrder/<int:id>', methods=['POST'])
@limiter.limit("15/minute", methods=['POST'])
@login_required
@check_role(['Administrator','User'])
def deleteOrder(id):
    order = Order.query.get(id)
    db.session.delete(order)
    db.session.commit()

    resp = make_response(redirect(url_for('retrieve_order')))
    return resp

#Reservation
@app.route('/createReserve', methods=["GET", "POST"])
@limiter.limit("15/minute", methods=['GET', 'POST'])
@login_required
@check_role(['Administrator','User'])
def createReserve():
    create_reserve_form = CreateReserveForm(request.form)
    error = ''
    if request.method == 'POST' and create_reserve_form.validate():
        if check_special(create_reserve_form.name.data) == True:

            reserve_name = Markup.escape(create_reserve_form.name.data)
            reserve_number = Markup.escape(create_reserve_form.number.data)
            reserve_email = Markup.escape(create_reserve_form.email.data)

            reservation = Reservation(name=reserve_name, email=reserve_email,
                                    number=reserve_number, date=create_reserve_form.date.data,
                                    time=create_reserve_form.time.data, party_size=create_reserve_form.party_size.data, user_id=session.get('user_id'))
            db.session.add(reservation)
            db.session.commit()
            
            session['create_reserve'] = reservation.id
        else:
            error = "No special characters allowed for name"

    resp = render_template('createReserve.html', form=create_reserve_form, error=error)
    return resp

@app.route('/userReserve', methods=["GET", "POST"])
@limiter.limit("25/minute", methods=['GET', 'POST'])
@login_required
@check_role(['Administrator','User'])
def userReserve():
    searchReserve = ''
    error = ''
    if request.method == "POST":
        searchReserve = request.form['searchReserve']
        if check_special(searchReserve) == False:
            searchReserve = ''
            error = "No special characters allowed"
            
    reserve_records = Reservation.query.filter_by(user_id=session.get('user_id')).all()
    reserve_user_list = []
    for reserve in reserve_records:
        if not searchReserve or searchReserve.lower() in reserve.date.lower():
            reserve_user_list.append(reserve)
    print(reserve_user_list)
    return render_template('userReserve.html', count=len(reserve_user_list), reserve_user_list=reserve_user_list,
                           searchReserve=searchReserve, error=error)


@app.route('/staffReserve')
@limiter.limit("20/minute", methods=['GET', 'POST'])
@check_role(['Administrator'])
def staffReserve():
    if not session.get('user_role'):
        session['user_role'] = 'Guest'
    if session['user_role'] == 'User' or session['user_role'] == 'Administrator':
        # reservation_list = Reservation.query.filter(id=1).all()
        if session['user_role'] == 'Administrator':
            users = Reservation.query.all()
            response = make_response(
                render_template('staffReserve.html', count=len(users), reservation_list=users))
            return response
        else:
            resp = make_response(redirect(url_for('index')))
            return resp
    else:
        flash("You have been logged out due to 30 minutes of inactivity. Please re-login again.")
        resp = make_response(redirect(url_for('login')))
        return resp

@app.route('/updateReserve/<int:id>/', methods=['GET', 'POST'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
@check_role(['Administrator','User'])
def updateReserve(id):
    update_reserve_form = CreateReserveForm(request.form)
    error = ''
    if request.method == 'POST' and update_reserve_form.validate():
        if check_special(update_reserve_form.name.data) == True:
            reserve_name = update_reserve_form.name.data
            reserve_number = update_reserve_form.number.data
            reserve_email = update_reserve_form.email.data

            reserve = Reservation.query.filter_by(id=id).first()
            reserve.name = reserve_name
            reserve.email = reserve_email
            reserve.number = reserve_number
            reserve.date = update_reserve_form.date.data
            reserve.time = update_reserve_form.time.data
            reserve.party_size = update_reserve_form.party_size.data

            db.session.commit()

            if session['user_role'] == "Administrator":
                response = make_response(redirect(url_for('staffReserve')))
                return response
            elif session['user_role'] == "User":
                resp = make_response(redirect(url_for('userReserve')))
                return resp
        else:
            error = "No special characters allowed for name"
            resp = make_response(render_template('updateReserve.html', form=update_reserve_form, error=error))
            return resp
    else:
        reserve = Reservation.query.filter_by(id=id).first()
        update_reserve_form.name.data = reserve.name
        update_reserve_form.email.data = reserve.email
        update_reserve_form.number.data = reserve.number
        update_reserve_form.date.data = reserve.date
        update_reserve_form.time.data = reserve.time
        update_reserve_form.party_size.data = reserve.party_size

        resp = make_response(render_template('updateReserve.html', form=update_reserve_form, error=error))
        return resp

@app.route('/deleteReserve/<int:id>', methods=['POST'])
@limiter.limit("15/minute", methods=['GET', 'POST'])
@check_role(['Administrator','User'])
def deleteReserve(id):
    reservation = Reservation.query.get(id)
    if reservation:
        db.session.delete(reservation)
        db.session.commit()

    if session['user_role'] == 'Administrator':
        response = make_response(redirect(url_for('staffReserve')))
        return response

    elif session['user_role'] == 'User':
        resp = make_response(redirect(url_for('userReserve')))
        return resp

@app.route('/unauthorized')
def unauthorized():
    return render_template('unauthorized.html')

@app.errorhandler(401)#webpage for 401
def unauthorized(error):
    return render_template('404.html')

@app.errorhandler(404)#webpage for 404
def not_found_error(error):
    return render_template('404.html')

@app.errorhandler(429)
def too_many_request(error):
    return render_template('429.html')