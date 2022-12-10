from flask import Flask,request,flash,render_template,make_response,redirect,url_for
from flask_login import LoginManager,login_required,logout_user,current_user,login_user
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from app.Forms import *
from app.user import User

app = Flask(__name__)
app.secret_key = 'NahidaKawaii'
login_manager = LoginManager()
login_manager.init_app(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
db = SQLAlchemy(app)
migrate = Migrate(app, db)


@app.before_request
def create_tables():
    with app.app_context():
        db.create_all()
        
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    if request.method == 'POST':
        username = request.form['email']
        password = request.form['password']
        print(password)
        user = User.query.filter_by(username=username).first()
        if user is None or not user.check_password(password):
            flash('Invalid username or password')
            return redirect(url_for('login'))
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
        user = User(username=username)
        print(password)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        return redirect(url_for('login'))
    return render_template('regi.html', form=create_user_form)



@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("Logout successful!")
    return redirect(url_for("login"))
