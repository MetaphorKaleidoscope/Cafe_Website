from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField, BooleanField
from wtforms.validators import DataRequired, URL
from flask_ckeditor import CKEditorField
from wtforms import validators


# #WTForm
class CreateCafeForm(FlaskForm):
    name = StringField("Cafeteria name", validators=[DataRequired()])
    map_url = StringField("Cafeteria map URL", validators=[DataRequired(), URL()])
    img_url = StringField("Cafeteria Image URL", validators=[DataRequired(), URL()])
    author = StringField("author", validators=[DataRequired()])
    location = StringField("Cafeteria location", validators=[DataRequired()])
    seats = StringField("Cafeteria seats (0-100)", validators=[DataRequired()])
    has_toilet = BooleanField("has_toilet", validators=[DataRequired(False)])
    has_wifi = BooleanField("has_wifi", validators=[DataRequired(False)])
    has_sockets = BooleanField("has_sockets", validators=[DataRequired(False)])
    can_take_calls = BooleanField("can_take_calls", validators=[DataRequired(False)])
    coffee_price = StringField("coffee_price (€ 0.00)", validators=[DataRequired()], default='£')
    submit = SubmitField("SUBMIT CAFE")


class RegisterForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), validators.Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField(label="SIGN ME UP!")


class LoginForm(FlaskForm):
    email = EmailField(label='Email', validators=[DataRequired(), validators.Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField(label="LET ME IN!")


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField(label="SUBMIT COMMENT")
