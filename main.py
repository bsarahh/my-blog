from datetime import date
from flask import Flask, render_template, redirect, url_for, flash, request, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from flask_gravatar import Gravatar
from flask_login import UserMixin, current_user, login_user, LoginManager, logout_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_wtf import FlaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from wtforms import SubmitField, StringField
from wtforms.validators import DataRequired, Length
from functools import wraps
from forms import CreatePostForm, LeaveComment

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)
gravatar = Gravatar(app,
                    size=100,
                    rating='g',
                    default='retro',
                    force_default=False,
                    force_lower=False,
                    use_ssl=False,
                    base_url=None)
##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Flask Login Stuff
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class RegisterForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired(), Length(min=4)])
    name = StringField("Full Name", validators=[DataRequired()])
    sign_up = SubmitField("Sign me up!")


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = StringField("Password", validators=[DataRequired(), Length(min=4)])
    sign_in = SubmitField("Let me in!")

class BlogPost(db.Model):
    __tablename__ = "blog_post"
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    author = relationship("User", back_populates="post")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    comments = relationship("Comment", back_populates="parent_post")

class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(100))
    post = relationship("BlogPost", back_populates="author")
    comments = relationship("Comment", back_populates="comment_author")

class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    commenter_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    comment_author = relationship("User", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_post.id"))
    parent_post = relationship("BlogPost", back_populates="comments")
    text = db.Column(db.Text, nullable=False)


db.create_all()




def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if hasattr(current_user, "id"):
            if current_user.id != 1:
                return abort(403)
            return f(*args, **kwargs)
        else:
            return abort(403)

    return decorated_function


@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated,
                           current_user=current_user)


@app.route('/register', methods=["GET", "POST"])
def register():
    register_form = RegisterForm()
    if request.method == "POST":
        if User.query.filter_by(email=register_form.email.data).first():
            # User already exists
            flash("You've already signed up with that email, log in instead!")
            return redirect(url_for('login'))
        hashed_password = generate_password_hash(
            password=register_form.password.data,
            method='pbkdf2:sha256',
            salt_length=8
        )
        new_user = User(
            email=register_form.email.data,
            name=register_form.name.data,
            password=hashed_password
        )
        db.session.add(new_user)
        db.session.commit()
        login_user(new_user)
        return redirect(url_for('get_all_posts'))
    return render_template("register.html",
                           form=register_form,
                           logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    log_in_form = LoginForm()
    if request.method == "POST":
        email = log_in_form.email.data
        entered_password = log_in_form.password.data
        user = User.query.filter_by(email=email).first()
        if user:
            # Check the hash
            if check_password_hash(user.password, entered_password):
                login_user(user)
                print(user.id)
                return redirect(url_for("get_all_posts"))
            else:
                flash("Password incorrect, try again.")
        else:
            flash("The email doesn't exist please try again.")

    return render_template("login.html",
                           form=log_in_form,
                           logged_in=current_user.is_authenticated)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for("get_all_posts"))


@app.route("/post/<int:post_id>", methods = ["POST", "GET"])
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = LeaveComment()
    if request.method == "POST":
        if current_user.is_authenticated:
            new_comment = Comment(
                text = comment_form.comment_space.data,
                post_id = post_id,
                commenter_id = current_user.id,
            )

            db.session.add(new_comment)
            db.session.commit()
        else :
            flash("You need to log in or register to comment!")
            return redirect(url_for("login"))
    return render_template("post.html", post=requested_post, logged_in=current_user.is_authenticated,
                           current_user=current_user, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
