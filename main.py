# Cafe website to work remotely
# A website of lists cafes with wifi and power for remote working

from flask import Flask, render_template, redirect, url_for, flash
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreateCafeForm, RegisterForm, LoginForm, CommentForm
from flask_gravatar import Gravatar
import os  # Issues with take data for db table file
from dotenv import load_dotenv
from functools import wraps
from flask import abort


basedir = os.path.abspath(os.path.dirname(__file__))  # Issues with take data for db table file
app = Flask(__name__)
load_dotenv('.env')
SECRET_KEY = os.getenv('SECRET_KEY')
app.config['SECRET_KEY'] = SECRET_KEY
ckeditor = CKEditor(app)
Bootstrap(app)

# #CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] =\
        'sqlite:///' + os.path.join(basedir, 'cafes.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

gravatar = Gravatar(app, size=100, rating='g', default='retro', force_default=False, force_lower=False, use_ssl=False,
                    base_url=None)


@login_manager.user_loader
def load_user(user_id):
    return RegisterUser.query.get(int(user_id))


# Only administration
def admin_only(f):
    @wraps(f)
    def decorate_function(*args, **kwargs):
        if current_user.id is not 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)
    return decorate_function


# #CONFIGURE TABLES
class RegisterUser(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    cafes = relationship('Cafe', back_populates='users')
    comments = relationship('CommentUser', back_populates='users')


class Cafe(db.Model):
    __tablename__ = "cafe_website"
    id = db.Column(db.Integer, primary_key=True)
    author = db.Column(db.String(250), db.ForeignKey('users.name'))
    users = relationship('RegisterUser', back_populates='cafes')
    name = db.Column(db.String(250), unique=True, nullable=False)
    map_url = db.Column(db.String(500), nullable=False)
    img_url = db.Column(db.String(500), nullable=False)
    location = db.Column(db.String(250), nullable=False)
    seats = db.Column(db.String(250), nullable=False)
    has_toilet = db.Column(db.Boolean, nullable=False)
    has_wifi = db.Column(db.Boolean, nullable=False)
    has_sockets = db.Column(db.Boolean, nullable=False)
    can_take_calls = db.Column(db.Boolean, nullable=False)
    coffee_price = db.Column(db.String(250), nullable=True)
    comments = relationship('CommentUser', back_populates='cafe_website')


class CommentUser(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    cafe_id = db.Column(db.Integer,  db.ForeignKey('cafe_website.id'))
    comment = db.Column(db.Text, nullable=False)
    author = db.Column(db.String(250), db.ForeignKey('users.name'))
    users = relationship('RegisterUser', back_populates='comments')
    cafe_website = relationship('Cafe', back_populates='comments')


with app.app_context():  # Add after add a table  or table name
    db.create_all()
    db.session.commit()


@app.route('/')
def get_all_cafes():
    cafes = Cafe.query.all()
    return render_template("index.html", all_cafes=cafes)


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        password_hash = generate_password_hash(form.password.data, method='pbkdf2:sha256', salt_length=8)
        email = form.email.data
        user = RegisterUser.query.filter_by(email=email).first()
        if not user:
            with app.app_context():
                db.create_all()
                new_user = RegisterUser(email=email, password=password_hash, name=form.name.data)
                db.session.add(new_user)
                db.session.commit()
                # Log and authenticate user after adding details to database
                login_user(new_user)
                return redirect(url_for("get_all_cafes"))
        else:
            flash("You've already signed up with that email, log in instead!")
            return render_template("login.html", form=form)
    return render_template("register.html", form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get('password')
        user = RegisterUser.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                login_user(user)
                return redirect(url_for("get_all_cafes"))
            else:
                flash("Wrong password -Try Again!")
        else:
            flash("That email doesn't Exist! -Try Again!")
            return render_template("login.html", form=form)
    return render_template("login.html", form=form)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('get_all_cafes'))


@app.route("/cafe/<int:cafe_id>", methods=['GET', 'POST'])
def show_cafe(cafe_id):
    form_comment = CommentForm()
    requested_cafe = Cafe.query.get(cafe_id)
    requested_comments = requested_cafe.comments
    if form_comment.validate_on_submit():
        if 'UserMixin' not in str(current_user):
            with app.app_context():
                db.create_all()
                new_comment = CommentUser(cafe_id=cafe_id, comment=request.form.get('comment'), users=current_user)
                db.session.add(new_comment)
                db.session.commit()
                return redirect(url_for("get_all_cafes"))
        else:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
    return render_template("cafe.html", cafe=requested_cafe, form=form_comment, comments=requested_comments)


@app.route("/new-cafe", methods=['GET', 'POST'])
@login_required
@admin_only
def add_new_cafe():
    form = CreateCafeForm()
    if form.validate_on_submit():
        with app.app_context():
            db.create_all()
            new_cafe = Cafe(
                name=form.name.data,
                location=form.location.data,
                img_url=form.img_url.data,
                author=current_user.name,
                map_url=form.map_url.data,
                seats=form.seats.data,
                has_toilet=form.has_toilet.data,
                has_wifi=form.has_wifi.data,
                has_sockets=form.has_sockets.data,
                can_take_calls=form.can_take_calls.data,
                coffee_price=form.coffee_price.data
            )
            db.session.add(new_cafe)
            db.session.commit()
            return redirect(url_for("get_all_cafes"))
    return render_template("make-cafe.html", form=form)


@app.route("/edit-cafe/<int:cafe_id>", methods=['GET', 'POST'])
@login_required
@admin_only
def edit_cafe(cafe_id):
    cafe = Cafe.query.get(cafe_id)
    edit_form = CreateCafeForm(
        name=cafe.name,
        location=cafe.location,
        img_url=cafe.img_url,
        author=cafe.author,
        map_url=cafe.map_url,
        seats=cafe.seats,
        has_toilet=cafe.has_toilet,
        has_wifi=cafe.has_wifi,
        has_sockets=cafe.has_sockets,
        can_take_calls=cafe.can_take_calls,
        coffee_price=cafe.coffee_price
    )
    if edit_form.validate_on_submit():
        cafe.name = edit_form.name.data
        cafe.location = edit_form.location.data
        cafe.img_url = edit_form.img_url.data
        cafe.author = edit_form.author.data
        cafe.map_url = edit_form.map_url.data
        cafe.seats = edit_form.seats.data
        cafe.has_toilet = edit_form.has_toilet.data
        cafe.has_wifi = edit_form.has_wifi.data
        cafe.has_sockets = edit_form.has_sockets.data
        cafe.can_take_calls = edit_form.can_take_calls.data
        cafe.coffee_price = edit_form.coffee_price.data
        db.session.commit()
        return redirect(url_for("show_cafe", cafe_id=cafe_id))

    return render_template("make-cafe.html", form=edit_form, is_edit=True)


@app.route("/delete/<int:cafe_id>")
@login_required
@admin_only
def delete_cafe(cafe_id):
    cafe_to_delete = Cafe.query.get(cafe_id)
    db.session.delete(cafe_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_cafes'))


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
