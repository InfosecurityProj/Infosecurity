from flask import Flask,request,flash,render_template,make_response,redirect,url_for,session,jsonify
from flask_login import LoginManager,login_required,logout_user,current_user,login_user
from sqlalchemy import or_
from app.Forms import *
from app.models import User,Order
from app.database import db
from flask_mail import Mail,Message
from pyotp import TOTP
from functools import wraps
from io import BytesIO

import hashlib,uuid,random,pyotp,pyqrcode,base64

app = Flask(__name__)
app.secret_key = 'NahidaKawaii'
totp_secret = "JBSWY3DPEHPK3PXP"#pyotp.random_base32()
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # session timeout is 1 hour(3600Sec)
login_manager = LoginManager()
login_manager.init_app(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test1.db"
db.init_app(app)
# rbac = RBAC(app)#rbac

#Email Configuration
app.config['MAIL_SERVER'] = 'smtp-mail.outlook.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'testyamifood@outlook.com'
app.config['MAIL_PASSWORD'] = 'TestYami123'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)
what
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


# def check_role(role):
#     def decorator(f):
#         @wraps(f)
#         def decorated_function(*args, **kwargs):
#             if current_user.is_authenticated:
#                 if current_user.role != role:
#                     return redirect(url_for('unauthorized'))
#             # user = current_user()
#             # if user.role != role:
#             #     return redirect(url_for('unauthorized'))
#             return f(*args, **kwargs)
#         return decorated_function
#     return decorator

with app.app_context():
    db.create_all()
    users = User.query.all()
    print(users)
    if User.query.filter_by(username="admin").first() or User.query.filter_by(username="kurokami").first():
    # The "admin" username already exists, so handle the error
        # print("admin exist")
        pass
    else:
        # The "admin" username does not exist, so create a new user
        admin=User(username="admin",email="admin@gmail.com",password_hash="7a14def6c43d661e14c59a3dd7174f617137b338ea128d428868e677dc3bed00",role="Administrator",
                        title="Mister",first_name="admin",last_name=" ",gender="M",account_salt="7f7ae7b152053e0e99d2db2cdb8caea759c473353322c8de03798357c0810b88",account_status="enabled",multifactorauth="disabled")
        kurokami=User(username="kurokami",email="kuro@gmail.com",password_hash="93c8033745689de41d5966ef63f56cf0d608658c284509eefd75de2335459c7f",role="Administrator",
                        title="Mister",first_name="kurokami",last_name="desu",gender="M",account_salt="845a111eb9585de318efd85a4810099eeb82903cc3b89c8b9ccfd6a5288dcea8",account_status="enabled",multifactorauth="disabled")
        db.session.add(admin)
        db.session.add(kurokami)
        db.session.commit()
        
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    print(session)
    session.permanent_session_lifetime = 60 #Resets session backs to 1 minute
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
        # print(user)
        session["email"] = email
        if user is not None and user.check_password(password):
            if user.account_status == 'enabled':
                if user.multifactorauth == "enabled":
                    return redirect(url_for("verify2fa"))
                else:
                    session['user_id'] = user.id
                    session['user_role'] = user.role
                    login_user(user)
                    #rbac.set_user_role(user.role)# Set the current user role based on the role attribute in the database
                    return redirect(url_for("index"))
            elif user.account_status == 'not_verified':
                flash("Your account is not verified,Contact support for help.")
                return redirect(url_for("login"))
            else:
                flash("Your account is disabled,Contact support for help.")
                return redirect(url_for("login"))
        else:
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

@app.route('/register', methods=['GET', 'POST'])
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
                            title=title,first_name=first_name,last_name=last_name,gender=gender)
                user.set_password(password)
                db.session.add(user)
                db.session.commit()
                # Generate a random 4-digit verification code
                verification_code = str(random.randint(1000, 9999))
                # Send an email with the verification code
                msg = Message("Verification Code",
                            sender="testyamifood@outlook.com",
                            recipients=[email])
                msg.body = "Welcome {}!\nThanks for signing up, you’re almost done creating your account!.\nYour verification code is: {}.\nPlease complete the account verification process in 30 minutes.".format(username,verification_code)
                mail.send(msg)
                #flash('Congratulations, you are now a registered user!')
                return redirect(url_for('verify'))
    return render_template('register.html', form=create_user_form)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        entered_code = request.form['code']
        email = session.get('verification_email')
        user = User.query.filter_by(email=email).first()
        if entered_code == verification_code:
            user.account_status = 'enabled'
            db.session.commit()
            flash('Your account has been verified. You can now login.')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code.')
    return render_template('validate.html')

@app.route('/verify2fa', methods=['GET', 'POST'])
def verify2fa():
    if request.method == 'POST':
        entered_code = request.form['code']
        totp=TOTP(totp_secret)
        print(f"entered_code {entered_code} totp {totp}")
        if totp.verify(entered_code):
            email = session.get('email')
            user = User.query.filter_by(email=email).first()
            session['user_id'] = user.id
            session['user_role'] = user.role
            session['email'] = user.email
            # rbac.set_user_role(user.role)# Set the current user role based on the role attribute in the database
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid verification code.')
    return render_template('validate2fa.html')
# @app.route('/register', methods=['GET', 'POST'])
# def register():
#     create_user_form = CreateUserForm(request.form)
#     if current_user.is_authenticated:
#         return redirect(url_for('index'))
#     #and create_user_form.validate()
#     if request.method == 'POST' :
#             username = request.form['username']
#             password = request.form['password']
#             first_name = request.form['first_name']
#             last_name = request.form['last_name']
#             gender = request.form['gender']
#             title = request.form['title']
#             email = request.form['email']
#             user = User(username=username,email=email,password_hash=password,account_status="enabled",role="User",
#                         title=title,first_name=first_name,last_name=last_name,gender=gender)
#             user.set_password(password)
#             db.session.add(user)
#             db.session.commit()
#             flash('Congratulations, you are now a registered user!')
#             return redirect(url_for('login'))
#     return render_template('register.html', form=create_user_form)

@app.route('/retrieving')
@check_role('Administrator')
@login_required
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
    # session['user_deleted'] = user.get_first_name() + ' ' + user.get_last_name()
    
# profile
@app.route("/profile")
@check_role(['Administrator','User','Guest'])
def profile():
    #print(session) debugging session
    if not session.get('user_role'):
        session['user_role'] = 'Guest'
    if 'user_id' in session and current_user.is_authenticated:
        if session['user_role'] == 'Administrator':
            user = User.query.filter_by(id=session['user_id']).first()
            resp = make_response(render_template('profile.html', profile=user))
            return resp
        if session['user_role'] == 'User':
            user = User.query.filter_by(id=session['user_id']).first()
            resp = make_response(render_template('profile.html', profile=user))
            return resp
        else:
            flash("You have been logged out due to 30 minutes of inactivity. Please re-login again.")
            resp = make_response(redirect(url_for('login')))
            return resp
    if 'user_role' in session and session['user_role'] == 'Guest':# checks for if the user is a guest
        flash("Please login to continue")
        resp = make_response(redirect(url_for('login')))
        return resp
        
@app.route("/logout")
@login_required
def logout():
    session.pop('user_id', None)
    session.pop('user_role', None)
    logout_user()
    session['user_role'] = 'Guest'
    flash("Logout successful!")
    return redirect(url_for("login"))

@app.route('/delete_account', methods=['POST'])
def delete_account():
    # Get the user's password from the form
    user_id = session.get('user_id')
    password = request.form.get('password')
    user = User.query.filter_by(id=user_id).first()
    Useruuid = str(uuid.uuid4())[:8].encode('utf-8')
    salt = bytes(hashlib.sha256(Useruuid).hexdigest(), "utf-8")
    salt = user.account_salt
    # print(salt,"password salt")
    hashed_password = hashlib.pbkdf2_hmac(
        "sha256",  # The hashing algorithm to use
        password.encode(),  # The password to hash, as bytes
        salt,  # The salt to use, as bytes
        100000  # The number of iterations to use
    )
    # print(f"hashed_password{hashed_password.hex()} user.password:{user.password_hash}")
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
    
# @app.route('/submit_password', methods=['POST'])
# def submit_password():
#     user_id = session.get('user_id')
#     password = request.form.get('password')
#     user = User.query.filter_by(id=user_id).first()
#     Useruuid = str(uuid.uuid4())[:8].encode('utf-8')
#     salt = bytes(hashlib.sha256(Useruuid).hexdigest(), "utf-8")
#     salt = user.account_salt
#     # print(salt,"password salt")
#     hashed_password = hashlib.pbkdf2_hmac(
#         "sha256",  # The hashing algorithm to use
#         password.encode(),  # The password to hash, as bytes
#         salt,  # The salt to use, as bytes
#         100000  # The number of iterations to use
#     )
#     # print(f"hashed_password{hashed_password.hex()} user.password:{user.password_hash}")
#     if user.password_hash != hashed_password.hex():
#     #if entered_password != user_password:
#         flash('Incorrect password')
#         return redirect(url_for('profile'))
#     email = 'example@example.com'
#     app_name = "HoHoHotels"
#     secret = pyotp.random_base32()
#     totp = pyotp.TOTP(secret, interval=30)
#     qr = pyqrcode.create(totp.provisioning_uri(email,issuer_name=app_name))
#     buffer = BytesIO()
#     qr.svg(buffer)
#     qr_svg_str = buffer.getvalue()
#     qr_svg_b64 = base64.b64encode(qr_svg_str).decode()
#     return render_template('code.html', qr_svg_b64=qr_svg_b64)

@app.route('/submit_password', methods=['POST'])
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
    email = session.get('email')
    app_name = "HoHoHotels"
    totp = pyotp.TOTP(totp_secret, interval=30)
    qr = pyqrcode.create(totp.provisioning_uri(email,issuer_name=app_name))
    print(qr)
    buffer = BytesIO()
    qr.svg(buffer)
    qr_svg_str = buffer.getvalue()
    qr_svg_b64 = base64.b64encode(qr_svg_str).decode()
    user.multifactorauth = 'enabled'
    db.session.commit()
    return render_template('code.html', qr_svg_b64=qr_svg_b64)
    # return jsonify(password_correct=True)

#Create Order
# @app.route('/createOrder', methods=['GET', 'POST'])
# def create_order():
#     create_order_form = CreateOrderForm(request.form)
#     if request.method == 'POST' and create_order_form.validate():

#         order = Order(meat=create_order_form.meat.data,
#                       sauce=create_order_form.sauce.data,
#                       remarks=create_order_form.remarks.data,
#                       price="699",
#                       order_item="My Depression",
#                       email="mydepression@gmail.com")
#         db.session.add(order)
#         db.session.commit()
        
#         response = make_response(redirect(url_for('retrieve_order')))
#         return response
#     resp = make_response(render_template('createOrder.html', form=create_order_form))
#     return resp

#TOTP Code Testing
@app.route('/code')
@check_role(['Administrator','User'])
def generate_qr_code():
    email = session.get('email')
    app_name = "HoHoHotels"
    totp = pyotp.TOTP(totp_secret, interval=30)
    qr = pyqrcode.create(totp.provisioning_uri(email,issuer_name=app_name))
    buffer = BytesIO()
    qr.svg(buffer)
    qr_svg_str = buffer.getvalue()
    qr_svg_b64 = base64.b64encode(qr_svg_str).decode()
    return render_template('code.html', qr_svg_b64=qr_svg_b64)

@app.route('/admin')
@check_role('Administrator')
def admin():
    return render_template('index.html')

@app.route('/unauthorized')
def unauthorized():
    return render_template('unauthorized.html')


# @app.errorhandler(401)#webpage for 401
# def unauthorized(error):
#     return render_template('404.html')

# @app.errorhandler(404)#webpage for 401
# def not_found_error(error):
#     return render_template('404.html')