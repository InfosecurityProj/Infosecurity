from wtforms import Form, SubmitField, StringField, SelectField, TextAreaField, validators, PasswordField, ValidationError,BooleanField,TextField
from wtforms.fields.html5 import EmailField, DateField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError,InputRequired,Required
from flask_wtf import FlaskForm
from string import punctuation
import phonenumbers

# --------------------------------
# Testing
# --------------------------------




# reservation form

class CreateReserveForm(Form):
    name = StringField("Name:", [validators.Length(min=1, max=20), validators.InputRequired("Please enter your name")])
    email = EmailField("Email:", [validators.InputRequired("Please enter your email"), validators.Email("This field requires a valid email address")])
    number = StringField("Number:", [validators.InputRequired(message="Please enter your number")])
    party_size = SelectField("Party Size:", [validators.InputRequired(message="Please select your party size")], choices=[('', 'Select'), ("1", 1), ("2", 2), ("3", 3), ("4", 4), ("5", 5)], default='')
    date = StringField("Date:", [validators.InputRequired("Please select the date")])
    time = SelectField("Time:", [validators.InputRequired("Please select the time")], choices=[('', 'Select Time'), ('9AM - 10AM', '9AM - 10AM'), ('10AM - 11AM', '10AM - 11AM'), ('11AM - 12PM', '11AM - 12PM'), ('12PM - 1PM', '12PM - 1PM'), ('1PM - 2PM', '1PM - 2PM'), ('2PM - 3PM', '2PM - 3PM'), ('3PM - 4PM', '3PM - 4PM'), ('4PM - 5PM', '4PM - 5PM'), ('5PM - 6PM', '5PM - 6PM'), ('6PM - 7PM', '6PM - 7PM'), ('7PM - 8PM', '7PM - 8PM'), ('8PM - 9PM', '8PM - 9PM'), ('9PM-10PM', '9PM-10PM')])

    def validate_number(form, field):
        try:
            int(field.data)
        except ValueError:
            raise ValidationError("Contact must be in digits")
        if len(field.data) > 8:
            raise ValidationError('Invalid phone number.')
        try:
            input_number = phonenumbers.parse(field.data)
            if not (phonenumbers.is_valid_number(input_number)):
                raise ValidationError('Invalid phone number.')
        except:
            input_number = phonenumbers.parse("+65" + field.data)
            if not (phonenumbers.is_valid_number(input_number)):
                raise ValidationError('Invalid phone number.')


# order form
class CreateOrderForm(Form):
    meat = SelectField('Meat', [validators.DataRequired()], choices=[('', 'Select Meat'), ('C', 'Chicken'), ('M', 'Mutton'), ('F', 'Fish'), ('V', 'Vegetable')],
                      default='')
    sauce = SelectField('Sauce', [validators.DataRequired()],
                        choices=[('', 'Select Sauce'), ('C', 'Chilli'), ('T', 'Tomato')], default='')
    remarks = TextAreaField('Remarks', [validators.Length(min=0, max=50),validators.Optional()])

class CreateDrinkForm(Form):
    # water = SelectField('Water', [validators.DataRequired()], choices=[('', 'Plain Water?'), ('Y', 'Yes'), ('N', 'No')],
    #                   default='')
    # straw = SelectField('Straw', [validators.DataRequired()],
    #                     choices=[('', 'Straw?'), ('Y', 'Yes'), ('N', 'No')], default='')
    # remarks = TextAreaField('Remarks', [validators.Length(min=0, max=50),validators.Optional()])
    drinks = SelectField('Drinks', [validators.DataRequired()], choices=[('', 'Select Drinks'), ('Co', 'Coke'), ('S', 'Sprite'), ('P', 'Plain Water'), ('N', 'None')],
                      default='')
    straw = SelectField('Straw', [validators.DataRequired()],
                        choices=[('', 'Straw'), ('Yes', 'Yes'), ('NO', 'No')], default='')
    remarks = TextAreaField('Remarks', [validators.Length(min=0, max=50),validators.Optional()])

# user form
class CreateUserForm(Form):
    first_name = StringField('First Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    last_name = StringField('Last Name', [validators.Length(min=1, max=150), validators.DataRequired()])
    gender = SelectField('Gender', [validators.DataRequired()],
                         choices=[('', 'Select'), ('F', 'Female'), ('M', 'Male')], default='')
    title = SelectField('Title', [validators.DataRequired()],
                        choices=[('', 'Select'), ('Mister', 'Mr'), ('Mistress', 'Mrs'), ('Miss', 'Ms'),
                                 ('Madam', 'Mdm')], default='')
    email = StringField('Email', [validators.DataRequired(), validators.Email()])
    password = PasswordField('Password', [validators.InputRequired()])
    confirm_password = PasswordField('Confirm Password', [validators.DataRequired(), validators.input_required(),
                                                          validators.EqualTo("password",
                                                                             message='Passwords must match')])
    username = StringField('Username', [validators.Length(min=1, max=150), validators.DataRequired()])

    def validate_password(self, Form):
        symbols = set(punctuation)
        if not Form.validate(self):
            return False
        if len(str(self.password.data)) < 8:
            self.password.errors.append("Password length should be at least 8")
            return False
        if len(str(self.password.data)) > 21:
            self.password.errors.append('length should be not be greater than 20')
            return False
        if not any(char.isdigit() for char in self.password.data):
            self.password.errors.append('Password should have at least one numeral')
            return False
        if not any(char.isupper() for char in self.password.data):
            self.password.errors.append('Password should have at least one uppercase letter')
            return False
        if not any(char.islower() for char in self.password.data):
            self.password.errors.append('Password should have at least one lowercase letter')
            return False
        if not any(char in symbols for char in self.password.data):
            self.password.errors.append('Password should have at least one of the symbols $@#&')
            return False
        return True

class ResetPasswordForm(FlaskForm):
    password = PasswordField('Password', [
        validators.InputRequired(),
        validators.Length(min=8, message='Password must be at least 8 characters long'),
        validators.Regexp(r'[A-Za-z0-9@#$%^&+=]', message='Password must contain at least one uppercase letter, one lowercase letter, one digit and one special character')
    ])
    confirm_password = PasswordField('Confirm Password', [
        validators.DataRequired(),
        validators.InputRequired(),
        validators.EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Reset Password')

class RequestResetForm(FlaskForm):
    email = StringField('Email',
                        validators=[validators.DataRequired(), validators.Email()])
    submit = SubmitField('Request Password Reset')

    # def validate_email(self, email):
    #     user = user.query.filter_by(email=email.data).first()
    #     if user is None:
    #         raise ValidationError('There is no account with that email. You must register first.')
