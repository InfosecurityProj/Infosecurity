from flask import Flask, render_template, request, redirect, url_for, session, render_template_string, Markup, flash, \
    make_response  # x
from Forms import CreateReserveForm, CreateOrderForm, CreateUserForm, RequestResetForm, ResetPasswordForm
import shelve, Reservation, Order, users, random, bcrypt, os
import flask_monitoringdashboard as dashboard
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from twilio.rest import Client
from dotenv import load_dotenv
from jinja2 import Environment
import jinja2
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
import socket
import logging
import logging.handlers
import os
from authlib.integrations.flask_client import OAuth
from datetime import timedelta  # x
import re

from flask_security import (Security, SQLAlchemyUserDatastore,
                            UserMixin, RoleMixin, login_required
                            )
from flask_security.utils import encrypt_password, hash_password
import flask_admin
from flask_admin import helpers as admin_helpers
from flask_admin.contrib import sqla

# find way for jinja2
load_dotenv()
os.environ['TWILIO_ACCOUNT_SID'] = "ACc289e06ac3e682f226689a160ab82b48"
os.environ['TWILIO_AUTH_TOKEN'] = "1f223bc4ae6180bc9437ed43c565468d"
os.environ['TWILIO_NUMBER'] = "+12282564761"
os.environ['EMAIL_USER'] = "Yamifood123@gmail.com"
os.environ['EMAIL_PASS'] = "Foodyami@123"

app = Flask(__name__)
dashboard.bind(app)
app.secret_key = 'any random string'

app.config['MAIL_SERVER'] = 'smtp.googlemail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
mail = Mail(app)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.config.from_pyfile('config.py')
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'

Jinja2 = Environment()

account_sid = 'ACc289e06ac3e682f226689a160ab82b48'
auth_token = "1f223bc4ae6180bc9437ed43c565468d"
client = Client(account_sid, auth_token)

app.config['RECAPTCHA_USE_SSL'] = False
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LeeyjceAAAAAKm8X85J28q2LcPqMAqFYO2E6p8Q'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LeeyjceAAAAAPnfQ3zr2c72Qpzr-Lq07Y90FOCE'
app.config['RECAPTCHA_OPTIONS'] = {'theme': 'black'}

# --------------------------------
# SQL Login Test
# --------------------------------
# Define models
roles_users = db.Table(
    'roles_users',
    db.Column('user_id', db.Integer(), db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer(), db.ForeignKey('role.id'))
)


class Role(db.Model, RoleMixin):
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(80), unique=True)
    description = db.Column(db.String(255))

    def __str__(self):
        return self.name


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(255))
    last_name = db.Column(db.String(255))
    email = db.Column(db.String(255), unique=True)
    password = db.Column(db.String(255))
    active = db.Column(db.Boolean())
    confirmed_at = db.Column(db.DateTime())
    roles = db.relationship('Role', secondary=roles_users,
                            backref=db.backref('users', lazy='dynamic'))

    def __str__(self):
        return self.email


# Setup Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)


# Create customized model view class
class MyModelView(sqla.ModelView):
    def is_accessible(self):
        return (current_user.is_active and
                current_user.is_authenticated and
                current_user.has_role('superuser')
        )

    def _handle_view(self, name, **kwargs):
        """
        Override builtin _handle_view in order to redirect users when a view is not accessible.
        """
        if not self.is_accessible():
            if current_user.is_authenticated:
                # permission denied
                abort(403)
            else:
                # login
                return redirect(url_for('security.login', next=request.url))

# Create admin
admin = flask_admin.Admin(
    app,
    'Example: Auth',
    base_template='my_master.html',
    template_mode='bootstrap4',
)

# Add model views
admin.add_view(MyModelView(Role, db.session))
admin.add_view(MyModelView(User, db.session))

# define a context processor for merging flask-admin's template context into the
# flask-security views.
@security.context_processor
def security_context_processor():
    return dict(
        admin_base_template=admin.base_template,
        admin_view=admin.index_view,
        h=admin_helpers,
        get_url=url_for
    )


def build_sample_db():
    """
    Populate a small db with some example entries.
    """

    import string
    import random

    db.drop_all()
    db.create_all()

    with app.app_context():
        user_role = Role(name='user')
        super_user_role = Role(name='superuser')
        db.session.add(user_role)
        db.session.add(super_user_role)
        db.session.commit()

        test_user = user_datastore.create_user(
            first_name='Admin',
            email='admin',
            password=hash_password('admin'),
            roles=[user_role, super_user_role]
        )

        first_names = [
            'Harry', 'Amelia', 'Oliver', 'Jack', 'Isabella', 'Charlie', 'Sophie', 'Mia',
            'Jacob', 'Thomas', 'Emily', 'Lily', 'Ava', 'Isla', 'Alfie', 'Olivia', 'Jessica',
            'Riley', 'William', 'James', 'Geoffrey', 'Lisa', 'Benjamin', 'Stacey', 'Lucy'
        ]
        last_names = [
            'Brown', 'Smith', 'Patel', 'Jones', 'Williams', 'Johnson', 'Taylor', 'Thomas',
            'Roberts', 'Khan', 'Lewis', 'Jackson', 'Clarke', 'James', 'Phillips', 'Wilson',
            'Ali', 'Mason', 'Mitchell', 'Rose', 'Davis', 'Davies', 'Rodriguez', 'Cox', 'Alexander'
        ]

        for i in range(len(first_names)):
            tmp_email = first_names[i].lower() + "." + last_names[i].lower() + "@example.com"
            tmp_pass = ''.join(random.choice(string.ascii_lowercase + string.digits) for i in range(10))
            user_datastore.create_user(
                first_name=first_names[i],
                last_name=last_names[i],
                email=tmp_email,
                password=hash_password(tmp_pass),
                roles=[user_role, ]
            )
        db.session.commit()
    return
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/about')
def about():
    resp = make_response(render_template("about.html"))
    return resp

@app.before_request  # x https://stackoverflow.com/questions/11783025/is-there-an-easy-way-to-make-sessions-timeout-in-flask
def make_session_perm():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)  # seconds=10 minutes=30
    session.modified = True


@app.after_request  # x
def add_security_headers(resp):
    resp.headers['Content-Security-Policy'] = 'default-src \'self\''
    resp.headers['Content-Security-Policy'] = "img - src'self';"
    return resp

# Retrieve users
@app.route('/retrieving')
def retrieving_users():
    if not session.get('type'):
        session['type'] = 'guest'
    if current_user.is_authenticated :
        if current_user.has_role('superuser'):  # edited to prevent path traversal
            response = make_response(render_template('retrieving.html', count=len(users_list), users_list=users_list))
            return response
        else:
            resp = make_response(redirect(url_for('index')))
            return resp
    else:
        flash("You have been logged out due to 30 minutes of inactivity. Please re-login again.")
        resp = make_response(redirect(url_for('security.login')))
        return resp

if __name__ == '__main__':

    # Build a sample db on the fly, if one does not exist yet.
    app_dir = os.path.realpath(os.path.dirname(__file__))
    database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
    if not os.path.exists(database_path):
        build_sample_db()

    # Start app
    app.run(port="3000",debug=True)




from models_old import *


# add staff account
def add_staff():
    users_dict = {}
    db = shelve.open('user.db', 'c')
    users_dict = db['users']
    if len(users_dict) > 0:
        users.User.count_id = list(users_dict.keys())[-1]

    # email = staff@yamifood.yay , password = tHeStAFf!a87#$

    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw('tHeStAFf!a87#$'.encode('utf8'), salt)
    staff = users.User('Admin', 'Lee', 'M', 'Mister', 'staff@yamifood.yay', hashed, hashed, 'staff', salt)
    users_dict[staff.get_user_id()] = staff
    db['users'] = users_dict
    db.close()





@app.route('/testssti', methods=["GET", "POST"])
def testssti():
    if request.method == 'POST':
        query = request.form['query']
        query = Jinja2.from_string(query).render()  # to make it vulnerable to ssti
        query = Markup(query)  # to make it vulnerable to xss
        response = make_response(render_template('test.html', query=query))
        return response
    else:
        resp = make_response(render_template('test.html'))
        return resp


# @app.route('/')
# def index():
#     # session.pop('name', None)
#     # session.pop('type', None)
#     session['attempt'] = 3
#     if not session.get('type'): #edited to prevent path traversal
#         session['type'] = 'guest'
#     resp = make_response(render_template('index.html'))
#     return resp


# @app.route('/', methods=['GET', 'POST'])
# def index():
#     global order_item, order_price
#     order_item = ''
#     order_price = 0
#     if not session.get('type'):
#         session['type'] = 'guest'
#     if request.method == "POST":
#         if session['type'] == 'guest':
#             return render_template("menu.html", error="Please log in before adding to cart.")
#         else:
#             # if request.form['menu'] == 'Tea':
#             #     order_item = 'Tea'
#             # elif request.form['menu'] == 'Fruit Juice':
#             #     order_item = 'Fruit Juice'
#             # elif request.form['menu'] == 'Soft Drink':
#             #     order_item = 'Soft Drink'
#             if request.form['menu'] == 'Burger':
#                 order_item = 'Burger'
#                 order_price = 15.79
#             elif request.form['menu'] == 'Salad':
#                 order_item = 'Salad'
#                 order_price = 18.79
#             elif request.form['menu'] == 'Pasta':
#                 order_item = 'Pasta'
#                 order_price = 20.79
#             elif request.form['menu'] == 'Steak':
#                 order_item = 'Steak'
#                 order_price = 25.79
#             elif request.form['menu'] == 'Korean Rice':
#                 order_item = 'Korean Rice'
#                 order_price = 22.79
#             elif request.form['menu'] == 'Hotplate':
#                 order_item = 'Hotplate'
#                 order_price = 24.79
#             response = make_response(redirect(url_for('create_order')))
#             return response
#     else:
#         resp = make_response(render_template("menu.html"))
#         return resp


@app.route('/about')
def about():
    resp = make_response(render_template("about.html"))
    return resp


#  Start Reservation

# Create
@app.route('/createReserve', methods=["GET", "POST"])
def createReserve():
    create_reserve_form = CreateReserveForm(request.form)
    key = get_fixed_key()
    error = ''
    if request.method == 'POST' and create_reserve_form.validate():

        if check_special(create_reserve_form.name.data) == True:

            reserve_name = Markup(create_reserve_form.name.data)  # to allow xss
            reserve_name = Markup.escape(reserve_name)  # to prevent xss
            reserve_name = Jinja2.from_string(reserve_name).render()  # to allow ssti
            reserve_name = encrypt(key, reserve_name.encode('utf8'))

            reserve_number = Markup.escape(create_reserve_form.number.data)  # to prevent xss
            reserve_number = encrypt(key, reserve_number.encode('utf8'))
            # reserve_name = Markup(create_reserve_form.name.data)

            reserve_email = Markup.escape(create_reserve_form.email.data)  # to prevent xss
            reserve_email = encrypt(key, reserve_email.encode('utf8'))
            # reserve_email = Markup(create_reserve_form.email.data)

            reserve_dict = {}
            db = shelve.open('reservation.db', 'c')

            try:
                reserve_dict = db['Reservation']
            except:
                print("Error in retrieving Users from reservation.db.")

            if len(reserve_dict) > 0:
                Reservation.Reservation.count_id = list(reserve_dict.keys())[-1]

            reservation = Reservation.Reservation(reserve_name, reserve_email,
                                                  reserve_number, create_reserve_form.date.data,
                                                  create_reserve_form.time.data, create_reserve_form.party_size.data)
            reserve_dict[reservation.get_user_id()] = reservation
            db['Reservation'] = reserve_dict

            # Test codes
            # reserve_dict = db['Reservation']
            # user = reserve_dict[reservation.get_user_id()]
            # print(reservation.get_name(), "was stored in reservation.db successfully with user_id ==",
            #       user.get_user_id())

            db.close()

            session['create_reserve'] = reservation.get_user_id()
        else:
            error = "No special characters allowed for name"

    resp = render_template('createReserve.html', form=create_reserve_form, error=error)
    return resp


def check_special(string):
    regex = re.compile('[@_!#$%^&*()<>?/|}{~:]')
    if (regex.search(string) == None):
        return True
    else:
        return False


# Retrieve for staff
@app.route('/staffReserve')
def staffReserve():
    global reserve
    if not session.get('type'):
        session['type'] = 'guest'
    if session['type'] == 'user' or session['type'] == 'staff':
        reserve_dict = {}
        db = shelve.open('reservation.db', 'r')
        reserve_dict = db['Reservation']
        db.close()

        dec_key = get_fixed_key()

        reserve_list = []
        name_list = []
        number_list = []
        email_list = []
        for b in range(0, 30):
            name_list.append(' ')
            number_list.append(' ')
            email_list.append(' ')

        for key in reserve_dict:
            reserve = reserve_dict.get(key)
            reserve_list.append(reserve)
            reserve_name = decrypt(dec_key, reserve.get_name()).decode('utf8')
            reserve_number = decrypt(dec_key, reserve.get_number()).decode('utf8')
            reserve_email = decrypt(dec_key, reserve.get_email()).decode('utf8')

            name_list[reserve.get_user_id()] = reserve_name
            number_list[reserve.get_user_id()] = reserve_number
            email_list[reserve.get_user_id()] = reserve_email

        # return render_template('staffReserve.html', count=len(reserve_list), reserve_list=reserve_list) # vulnerable
        if session['type'] == 'staff':  # edited to prevent path traversal
            response = make_response(
                render_template('staffReserve.html', count=len(reserve_list), reserve_list=reserve_list,
                                name_list=name_list, number_list=number_list, email_list=email_list))
            return response
        else:
            resp = make_response(redirect(url_for('index')))
            return resp
    else:
        flash("You have been logged out due to 30 minutes of inactivity. Please re-login again.")
        resp = make_response(redirect(url_for('login')))
        return resp


# Retrieve for user
@app.route('/userReserve', methods=["GET", "POST"])
def userReserve():
    if not session.get('type'):
        session['type'] = 'guest'
    if session['type'] == 'user' or session['type'] == 'staff':
        reserve_dict = {}
        db = shelve.open('reservation.db', 'r')
        reserve_dict = db['Reservation']
        db.close()

        dec_key = get_fixed_key()

        reserve_list = []
        name_list = []
        number_list = []
        email_list = []

        searchReserve = ''
        error = ''
        if request.method == "POST":
            searchReserve = request.form['searchReserve']
            if check_special(searchReserve) == True:
                # searchReserve = Jinja2.from_string(searchReserve).render()  # to make it vulnerable to ssti
                # searchReserve = Markup(searchReserve) # to make it vulnerable to xss
                searchReserve = Markup.escape(searchReserve)  # to prevent xss
            else:
                searchReserve = ''
                error = "No special characters allowed"
        for b in range(0, 30):
            name_list.append(' ')
            number_list.append(' ')
            email_list.append(' ')

        for key in reserve_dict:
            reserve = reserve_dict.get(key)
            reserve_list.append(reserve)

            reserve_name = decrypt(dec_key, reserve.get_name()).decode('utf8')
            reserve_number = decrypt(dec_key, reserve.get_number()).decode('utf8')
            reserve_email = decrypt(dec_key, reserve.get_email()).decode('utf8')

            name_list[reserve.get_user_id()] = reserve_name
            number_list[reserve.get_user_id()] = reserve_number
            email_list[reserve.get_user_id()] = reserve_email
        reserve_user_list = []

        for reserve in reserve_list:
            if decrypt(dec_key, reserve.get_email()).decode('utf8') == session['email']:
                if searchReserve:
                    if searchReserve.lower() in reserve.get_date().lower():
                        reserve_user_list.append(reserve)
                else:
                    reserve_user_list.append(reserve)
        resp = make_response(
            render_template('userReserve.html', count=len(reserve_list), reserve_user_list=reserve_user_list,
                            name_list=name_list, number_list=number_list, email_list=email_list,
                            searchReserve=searchReserve, error=error))
        return resp
    else:
        flash("You have been logged out due to 30 minutes of inactivity. Please re-login again.")
        resp = make_response(redirect(url_for('login')))
        return resp


# Update
@app.route('/updateReserve/<int:id>/', methods=['GET', 'POST'])
def updateReserve(id):
    update_reserve_form = CreateReserveForm(request.form)
    key = get_fixed_key()

    if request.method == 'POST' and update_reserve_form.validate():
        reserve_dict = {}
        db = shelve.open('reservation.db', 'w')
        reserve_dict = db['Reservation']

        if check_special(update_reserve_form.name.data) == True:
            reserve_name = Markup(update_reserve_form.name.data)  # to allow xss harr
            # reserve_name = Jinja2.from_string(reserve_name).render()  # to allow ssti
            reserve_name = Markup.escape(reserve_name)  # to prevent xss
            reserve_name = encrypt(key, reserve_name.encode('utf8'))

            reserve_number = Markup.escape(update_reserve_form.number.data)  # to prevent xss
            reserve_number = encrypt(key, reserve_number.encode('utf8'))
            # reserve_name = Markup(create_reserve_form.name.data)

            reserve_email = Markup.escape(update_reserve_form.email.data)  # to prevent xss
            reserve_email = encrypt(key, reserve_email.encode('utf8'))
            # reserve_email = Markup(create_reserve_form.email.data)

            reserve = reserve_dict.get(id)
            reserve.set_name(reserve_name)
            reserve.set_email(reserve_email)
            reserve.set_number(reserve_number)
            reserve.set_date(update_reserve_form.date.data)
            reserve.set_time(update_reserve_form.time.data)
            reserve.set_party_size(update_reserve_form.party_size.data)

            db['Reservation'] = reserve_dict
            db.close()
            if session['type'] == "staff":
                response = make_response(redirect(url_for('staffReserve')))
                return response
            elif session['type'] == "user":
                resp = make_response(redirect(url_for('userReserve')))
                return resp
        else:
            error = "No special characters allowed for name"
            resp = make_response(render_template('updateReserve.html', form=update_reserve_form, error=error))
            return resp
    else:
        reserve_dict = {}
        db = shelve.open('reservation.db', 'r')
        reserve_dict = db['Reservation']
        db.close()

        dec_key = get_fixed_key()

        name_list = []
        number_list = []
        email_list = []
        for b in range(0, 30):
            name_list.append(' ')
            number_list.append(' ')
            email_list.append(' ')

        for key in reserve_dict:
            reserve = reserve_dict.get(key)
            reserve_name = decrypt(dec_key, reserve.get_name()).decode('utf8')
            reserve_number = decrypt(dec_key, reserve.get_number()).decode('utf8')
            reserve_email = decrypt(dec_key, reserve.get_email()).decode('utf8')

            name_list[reserve.get_user_id()] = reserve_name
            number_list[reserve.get_user_id()] = reserve_number
            email_list[reserve.get_user_id()] = reserve_email

        reserve = reserve_dict.get(id)
        update_reserve_form.name.data = name_list[reserve.get_user_id()]
        update_reserve_form.email.data = email_list[reserve.get_user_id()]
        update_reserve_form.number.data = number_list[reserve.get_user_id()]
        update_reserve_form.date.data = reserve.get_date()
        update_reserve_form.time.data = reserve.get_time()
        update_reserve_form.party_size.data = reserve.get_party_size()

        resp = make_response(render_template('updateReserve.html', form=update_reserve_form))
        return resp


# Delete
@app.route('/deleteReserve/<int:id>', methods=['POST'])
def deleteReserve(id):
    reserve_dict = {}
    db = shelve.open('reservation.db', 'w')
    reserve_dict = db['Reservation']

    reserve = reserve_dict.pop(id)

    db['Reservation'] = reserve_dict
    db.close()

    if session['type'] == 'staff':
        response = make_response(redirect(url_for('staffReserve')))
        return response

    elif session['type'] == 'user':
        resp = make_response(redirect(url_for('userReserve')))
        return resp


# End Reservation

# Start Login & Register


# login
@app.route('/login', methods=['GET', 'POST'])
def login():
    global validated_user
    error = ''
    if not session.get('type'):
        session['type'] = 'guest'
    # session['attempt'] = 3
    if request.method == "POST":
        users_dict = {}
        db = shelve.open('user.db', 'r')
        users_dict = db['users']
        db.close()

        users_list = []
        for key in users_dict:
            user = users_dict.get(key)
            users_list.append(user)

        for user in users_list:
            hashed = bcrypt.hashpw(request.form['password'].encode('utf8'), user.get_salt())
            if request.form['email'] == user.get_emails() and hashed == user.get_password():
                validated_user = user
                session['name'] = validated_user.get_first_name()
                session['type'] = validated_user.get_type()
                session['email'] = validated_user.get_emails()
                session.pop('guest', None)
                responses = make_response(redirect(url_for('index')))
                return responses
            # # return redirect(url_for('index'))
            #     return redirect(url_for('generate'))

        attempt = session.get('attempt')
        try:
            attempt -= 1
        except:
            return redirect(url_for('index'))
        session['attempt'] = attempt

        if attempt <= 1:
            client_ip = socket.gethostbyname(socket.gethostname())
            error = 'Invalid login credentials. Multiple failed attempts will be logged.'

            logging.basicConfig(filename='logfile.log', format='%(asctime)s - %(message)s', datefmt='%d-%b-%y %H:%M:%S')
            logging.disable(logging.INFO)
            logging.warning('Multiple failed login attempts by {}'.format(client_ip))

        else:
            error = 'Invalid login credentials. Try again.'

    resp = make_response(render_template('login.html', error=error))
    return resp



# @app.route('/auth')
# def auth():
#     google = oauth.create_client('google')
#     token = google.authorize_access_token()
#     resp = google.get('userinfo')  # userinfo contains stuff u specificed in the scrope
#     user_info = resp.json()
#     # user = oauth.google.userinfo()
#     email = user_info['email']

#     name_list = user_info['name'].split()
#     first_name = name_list[0]
#     last_name = name_list[1]

#     users_dict = {}
#     db = shelve.open('user.db', 'c')
#     users_dict = db['users']

#     googleuser = ''
#     for key in users_dict:
#         user = users_dict.get(key)
#         if email == user.get_emails():
#             googleuser = user

#     if not googleuser:
#         if len(users_dict) > 0:
#             users.User.count_id = list(users_dict.keys())[-1]

#         googleuser = users.User(first_name, last_name, '', '', email, '', '', 'user', '')
#         users_dict[googleuser.get_user_id()] = googleuser
#         db['users'] = users_dict
#         db.close()

#     session['name'] = googleuser.get_first_name()
#     session['type'] = googleuser.get_type()
#     session['email'] = googleuser.get_emails()
#     session.pop('guest', None)

#     resp = make_response(redirect(url_for('index')))
#     return resp


def send_reset_email(token):
    users_dict = {}
    db = shelve.open('user.db', 'c')
    users_dict = db['users']

    users_email_list = []
    for key in users_dict:
        user = users_dict.get(key)
        email = user.get_emails()
        if token == user.get_emails():
            msg = Message('Password Reset Request',
                          sender='noreply@demo.com',
                          recipients=[email])

            msg.body = f'''To reset your password, visit the following link:
        {url_for('update_user', id=key, _external=True)}
        If you did not make this request then simply ignore this email and no changes will be made.
        '''
            mail.send(msg)


@app.route("/reset_password", methods=['GET', 'POST'])
def reset_request():
    # if current_user.is_authenticated:
    #     return redirect(url_for('home'))
    form = RequestResetForm()
    if form.validate_on_submit():
        # user = User.query.filter_by(email=form.email.data).first()
        send_reset_email(form.email.data)
        message = 'An email has been sent with instructions to {} to reset your password.'.format(form.email.data)
        response = make_response(
            render_template('reset_request.html', title='Reset Password', form=form, message=message))
        return response

    resp = make_response(render_template('reset_request.html', title='Reset Password', form=form))
    return resp

    # just in case not working ^
    #     return render_template('reset_request.html', title='Reset Password', form=form, message=message)
    # return render_template('reset_request.html', title='Reset Password', form=form)


# profile
@app.route("/profile")
def profile():
    if not session.get('type'):
        session['type'] = 'guest'
    if session['type'] == 'user' or session['type'] == 'staff':
        profile_dict = {}
        db = shelve.open('user.db', 'r')
        profile_dict = db['users']
        db.close()

        profile_list = []
        for key in profile_dict:
            profile = profile_dict.get(key)
            profile_list.append(profile)

        profile_user_list = []
        for user in profile_list:
            if user.get_emails() == session['email']:
                profile_user_list.append(user)

        resp = make_response(
            render_template('profile.html', count=len(profile_list), profile_user_list=profile_user_list))
        return resp
    else:
        flash("You have been logged out due to 30 minutes of inactivity. Please re-login again.")
        resp = make_response(redirect(url_for('login')))
        return resp


# log out
@app.route('/logout')
def logout():
    session.pop('name', None)
    session.pop('type', None)
    session.pop('email', None)
    session['type'] = 'guest'

    resp = make_response(redirect(url_for('login')))
    return resp


# Register
@app.route('/regi', methods=['GET', 'POST'])
def create_user():
    error = ''
    recaptchaerror = ''
    create_user_form = CreateUserForm(request.form)
    if request.method == 'POST':
        recaptchaerror = "recaptcha not submitted"
    if request.method == 'POST' and create_user_form.validate():

        users_dict = {}
        db = shelve.open('user.db', 'c')

        try:
            users_dict = db['users']
        except:
            print("Error in retrieving Users from storage.db.")

        if len(users_dict) > 0:
            users.User.count_id = list(users_dict.keys())[-1]

        recaptchaerror = ''

        users_email_list = []
        for key in users_dict:
            user = users_dict.get(key)
            users_email_list.append(user.get_emails())

        if create_user_form.emails.data in users_email_list:
            error = "email address already in use!"
        else:
            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(create_user_form.password.data.encode('utf8'), salt)

            user = users.User(create_user_form.first_name.data, create_user_form.last_name.data,
                              create_user_form.gender.data,
                              create_user_form.title.data, create_user_form.emails.data, hashed,
                              create_user_form.confirm_password.data, 'user', salt)

            user.set_emails(create_user_form.emails.data)
            users_dict[user.get_user_id()] = user
            db['users'] = users_dict

            # Test codes
            # users_dict = db['users']
            # user = users_dict[user.get_user_id()]
            # print(user.get_first_name(), user.get_last_name(), "was stored in storage.db successfully with user_id ==",
            #       user.get_user_id())

            db.close()

            # session['user_created'] = user.get_first_name() + ' ' + user.get_last_name()

            response = make_response(redirect(url_for('login')))
            return response
    resp = make_response(
        render_template('regi.html', form=create_user_form, error=error, recaptchaerror=recaptchaerror))
    return resp


# Retrieve users
@app.route('/retrieving')
def retrieving_users():
    if not session.get('type'):
        session['type'] = 'guest'
    if session['type'] == 'user' or session['type'] == 'staff':
        users_dict = {}
        db = shelve.open('user.db', 'r')
        users_dict = db['users']
        db.close()

        users_list = []
        for key in users_dict:
            user = users_dict.get(key)
            users_list.append(user)
        # return render_template('retrieving.html', count=len(users_list), users_list=users_list) # vulnerable
        if session['type'] == 'staff':  # edited to prevent path traversal
            response = make_response(render_template('retrieving.html', count=len(users_list), users_list=users_list))
            return response
        else:
            resp = make_response(redirect(url_for('index')))
            return resp
    else:
        flash("You have been logged out due to 30 minutes of inactivity. Please re-login again.")
        resp = make_response(redirect(url_for('login')))
        return resp


# Update user
@app.route('/updateU/<int:id>/', methods=['GET', 'POST'])
def update_user(id):
    error = ''
    recaptchaerror = ''
    update_user_form = CreateUserForm(request.form)
    if request.method == 'POST':
        recaptchaerror = "recaptcha not submitted"
    if request.method == 'POST' and update_user_form.validate():
        users_dict = {}
        db = shelve.open('user.db', 'c')
        users_dict = db['users']

        users_email_list = []
        for key in users_dict:
            user = users_dict.get(key)
            users_email_list.append(user.get_emails())

        user = users_dict.get(id)
        users_email_list.remove(user.get_emails())

        recaptchaerror = ''

        if update_user_form.emails.data in users_email_list:
            error = "email address already in use!"

        else:
            user.set_first_name(update_user_form.first_name.data)
            user.set_last_name(update_user_form.last_name.data)
            user.set_gender(update_user_form.gender.data)
            user.set_emails(update_user_form.emails.data)
            user.set_title(update_user_form.title.data)

            salt = bcrypt.gensalt()
            hashed = bcrypt.hashpw(update_user_form.password.data.encode('utf8'), salt)
            user.set_password(hashed)
            user.set_confirm_password(hashed)
            user.set_salt(salt)

            db['users'] = users_dict
            db.close()
            if session['type'] == "staff":
                response = make_response(redirect(url_for('retrieving_users')))
                return response
            elif session['type'] == "user":
                responze = make_response(redirect(url_for('profile')))
                return responze
            else:
                response = make_response(redirect(url_for('login')))
                return response
        resp = make_response(
            render_template('updateU.html', form=update_user_form, error=error, recaptchaerror=recaptchaerror))
        return resp

    else:
        users_dict = {}
        db = shelve.open('user.db', 'r')
        users_dict = db['users']
        db.close()

        user = users_dict.get(id)
        update_user_form.first_name.data = user.get_first_name()
        update_user_form.last_name.data = user.get_last_name()
        update_user_form.gender.data = user.get_gender()
        update_user_form.title.data = user.get_title()
        update_user_form.emails.data = user.get_emails()
        update_user_form.password.data = user.get_password()

        resp = make_response(
            render_template('updateU.html', form=update_user_form, error=error, recaptchaerror=recaptchaerror))
        return resp


# Delete user
@app.route('/deleteUser/<int:id>', methods=['POST'])
def delete_user(id):
    users_dict = {}
    db = shelve.open('user.db', 'w')
    users_dict = db['users']

    users_dict.pop(id)

    db['users'] = users_dict
    db.close()

    # session['user_deleted'] = user.get_first_name() + ' ' + user.get_last_name()
    if session['type'] == 'staff':
        response = make_response(redirect(url_for('retrieving_users')))
        return response

    elif session['type'] == 'user':
        session.pop('name', None)
        resp = make_response(redirect(url_for('index')))
        return resp


# End Login & Register


# Start Order


# Create
@app.route('/createOrder', methods=['GET', 'POST'])
def create_order():
    create_order_form = CreateOrderForm(request.form)
    if request.method == 'POST' and create_order_form.validate():
        order_dict = {}
        db = shelve.open('order.db', 'c')

        try:
            order_dict = db['Order']
        except:
            print("Error in retrieving Order from storage.db.")

        if len(order_dict) > 0:
            Order.Order.count_id = list(order_dict.keys())[-1]

        order = Order.Order(order_item, create_order_form.meat.data,
                            create_order_form.sauce.data, create_order_form.remarks.data, order_price, session['email'])
        order_dict[order.get_order_id()] = order
        db['Order'] = order_dict

        db.close()

        response = make_response(redirect(url_for('retrieve_order')))
        return response
    resp = make_response(render_template('createOrder.html', form=create_order_form, order_item=order_item))
    return resp


# Retrieve
@app.route('/retrieveOrder', methods=["GET", "POST"])
def retrieve_order():
    if not session.get('type'):
        session['type'] = 'guest'
    if session['type'] != 'guest':
        order_dict = {}
        db = shelve.open('order.db', 'r')
        order_dict = db['Order']
        db.close()

        order_list = []
        for key in order_dict:
            order = order_dict.get(key)
            order_list.append(order)

        total = 0
        count = 0
        for item in order_list:
            if item.get_email() == session['email']:
                total += item.get_price()
                count += 1

        if request.method == "POST":
            session['create_order'] = order.get_order_id()

        response = make_response(render_template('retrieveOrder.html', count=count, order_list=order_list, total=total))
        return response
    else:
        resp = make_response(redirect(url_for('index')))
        return resp


# Update
@app.route('/updateOrder/<int:id>/', methods=['GET', 'POST'])
def update_order(id):
    update_order_form = CreateOrderForm(request.form)
    if request.method == 'POST' and update_order_form.validate():
        order_dict = {}
        db = shelve.open('order.db', 'w')
        order_dict = db['Order']

        order = order_dict.get(id)
        order.set_meat(update_order_form.meat.data)
        order.set_sauce(update_order_form.sauce.data)
        order.set_remarks(update_order_form.remarks.data)

        db['Order'] = order_dict
        db.close()

        response = make_response(redirect(url_for('retrieve_order')))
        return response
    else:
        order_dict = {}
        db = shelve.open('order.db', 'r')
        order_dict = db['Order']
        db.close()

        order = order_dict.get(id)
        update_order_form.meat.data = order.get_meat()
        update_order_form.sauce.data = order.get_sauce()
        update_order_form.remarks.data = order.get_remarks()
        order_item = order.get_order_item()

        resp = make_response(render_template('updateOrder.html', form=update_order_form, order_item=order_item))
        return resp


# Delete
@app.route('/deleteOrder/<int:id>', methods=['POST'])
def deleteOrder(id):
    order_dict = {}
    db = shelve.open('order.db', 'w')
    order_dict = db['Order']

    order_dict.pop(id)

    db['Order'] = order_dict
    db.close()

    resp = make_response(redirect(url_for('retrieve_order')))
    return resp


# End Order

# start 2FA
@app.route('/generate', methods=['GET', 'POST'])
def generate():
    global otp
    if not session.get('type'):
        session['type'] = 'guest'
    try:
        if request.method == 'GET' and validated_user:
            response = make_response(render_template('generate.html'))
            return response
            # return render_template('generate.html')
    except:
        responze = make_response(redirect(url_for('login')))
        return responze
        # return redirect(url_for('login'))

    phone_number = request.form['phone_number']
    channel = request.form['channel']

    error = None
    if not phone_number:
        error = 'Phone Number is required'
    if channel != 'voice' and channel != 'sms':
        error = 'Invalid channel'
    if error is None:
        session['phone_number'] = phone_number
        otp = random.randint(1000, 9999)
        print(otp)
        if otp:
            if channel == 'sms':
                try:
                    message = client.messages.create(
                        body='Your OTP is -' + str(otp),
                        from_="+12282564761",
                        to="+65" + phone_number
                    )

                except:
                    error = "invalid phone number"
            else:
                try:
                    call = client.calls.create(
                        twiml=f"<Response><Say voice='alice'>Your one-time password is {otp}</Say><Pause length='1'/><Say>Your one-time password is {otp}</Say><Pause length='1'/><Say>Goodbye</Say></Response>",
                        to="+65" + phone_number,
                        from_="+12282564761"
                    )

                except:
                    error = "invalid phone number"
            if error:
                responses = make_response(render_template('generate.html', error=error))
                return responses
                # return render_template('generate.html', error=error)

            responsez = make_response(redirect(url_for('validate')))
            return responsez
            # return redirect(url_for('validate'))
        error = 'Something went wrong, could not generate OTP'

    resp = make_response(redirect(url_for('generate')))
    return resp
    # return redirect(url_for('generate'))


@app.route('/validate', methods=['GET', 'POST'])
def validate():
    if not session.get('type'):
        session['type'] = 'guest'
    try:
        if request.method == 'GET' and validated_user and otp:
            response = make_response(render_template('validate.html'))
            return response
            # return render_template('validate.html')
    except:
        responze = make_response(redirect(url_for('login')))
        return responze
        # return redirect(url_for('login'))

    otp_code = request.form['otp_code']
    error = None
    if not otp_code:
        error = 'OTP code is required'
    if 'phone_number' in session:
        phone_number = session['phone_number']
    else:
        error = 'Please request a new OTP'
    if error is None:
        phone_number = session.get('phone_number')
        print(otp_code)
        print(otp)
        if str(otp_code) == str(otp):
            status = True
        else:
            error = "invalid OTP"
            status = False
        if status is True:
            del session['phone_number']
            session['name'] = validated_user.get_first_name()
            session['type'] = validated_user.get_type()
            session['email'] = validated_user.get_emails()
            session.pop('guest', None)
            responses = make_response(redirect(url_for('index')))
            return responses
            # return redirect(url_for('index'))
        elif status is False:

            responsez = make_response(render_template('validate.html', error=error))
            return responsez
            # return render_template('validate.html', error=error)
        error = 'Something went wrong, could not validate OTP'

    resp = make_response(redirect(url_for('validate')))
    return resp


# End 2FA

# start encryption
def get_fixed_key():
    # use fixed AES key, 256 bits
    return b"abcdefghijklmnopqrstuvwxyzabcdef"


def encrypt(key, message):
    obj = AES.new(key, AES.MODE_CBC, b'This is an IV456')
    ciphertext = obj.encrypt(pad(message, AES.block_size))
    return ciphertext


def decrypt(key, ciphertext):
    obj2 = AES.new(key, AES.MODE_CBC, b'This is an IV456')
    message = unpad(obj2.decrypt(ciphertext), AES.block_size)
    return message


# Handling error 404 and displaying relevant web page
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404


# Handling error 500 and displaying relevant web page
@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# if __name__ == '__main__':
#     # Build a sample db on the fly, if one does not exist yet.
#     app_dir = os.path.realpath(os.path.dirname(__file__))
#     database_path = os.path.join(app_dir, app.config['DATABASE_FILE'])
#     if not os.path.exists(database_path):
#         build_sample_db()
#     app.run(debug=True)
