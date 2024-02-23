import os
import smtplib
from datetime import date
from functools import wraps
from forms import CreatePostForm, RegisterForm, LoginForm, CommentForm
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, abort, render_template, redirect, url_for, flash, request, session
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy

load_dotenv("./.env")

MY_EMAIL = os.getenv("MY_EMAIL")
MY_PASS = os.getenv("MY_PASS")
RECEIVE_EMAIL = os.getenv("RECEIVE_EMAIL")

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv("FLASK_KEY")
ckeditor = CKEditor(app)
Bootstrap5(app)

# Config of Flask-Login
login_manager = LoginManager(app)

year = date.today().year


# Load the user from the database by id.
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def admin_only(f):
    """
    'admin_only' decorator adds more functionality for routes, only admin can edit or delete a post.
    The Admin here recognized by id of (1).
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If id is not 1 then return abort with 403 error
        if current_user.id != 1:
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


def not_logged_in(f):
    """This decorator prevents logged-in user from accessing login and register routes."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.is_authenticated:
            return redirect(url_for("get_all_posts"))
        return f(*args, **kwargs)

    return decorated_function


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv("DATABASE_URL")
db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    """Creates 'blog_posts' table in our database"""
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.relationship("User", back_populates="posts")  # relation  1
    author_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)  # fk: id of the author of post (user)
    img_url = db.Column(db.String(250), nullable=False)
    comments = db.relationship("Comment", back_populates="post")


class User(UserMixin, db.Model):
    """Creates 'users' table in our database"""
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(250), nullable=False)
    posts = db.relationship("BlogPost", back_populates="author")  # relation 1, each author can have many posts.
    comments = db.relationship("Comment", back_populates="commenter")  # relation 2, user can have many comments.


class Comment(db.Model):
    """Creates the 'comments' table in our database"""
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(250), nullable=False)
    post = db.relationship("BlogPost", back_populates="comments")
    post_id = db.Column(db.Integer, db.ForeignKey("blog_posts.id"), nullable=False)
    commenter_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)  # foreign_key: id of the commenter
    commenter = db.relationship("User", back_populates="comments")  # relation 2


with app.app_context():
    db.create_all()


@app.route('/')
def get_all_posts():
    """Home route, this function renders the 'index.html' template."""
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html",
                           all_posts=posts,
                           logged_in=current_user.is_authenticated,
                           year=year)


@app.route('/register', methods=["GET", "POST"])
@not_logged_in
def register():
    """Registration is done under this route. This function handles all registration operation."""
    register_form = RegisterForm()
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        name = request.form.get("name")
        user_exist = User.query.filter_by(email=email).first()
        if user_exist:  # if true
            flash("User Already Exists. Try Logging In")
        else:
            # create a new user object to add it to the database
            new_user = User(
                email=email,
                password=generate_password_hash(password=password, method="pbkdf2:sha256", salt_length=8),
                name=name
            )
            db.session.add(new_user)
            db.session.commit()
            get_user = User.query.filter_by(email=new_user.email).first()
            login_user(get_user)  # logs in the newly registered user
            flash("Registered, logged in")
            session.pop("_flashes", None)
            return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=register_form, logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
@not_logged_in
def login():
    """Responsible about the functionality of the login operation."""
    login_form = LoginForm()
    if login_form.validate_on_submit():
        email = request.form.get('email')
        password = request.form.get("password")
        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(pwhash=user.password, password=password):
                flash("login success")
                login_user(user)  # login the user and redirect to the home page
                session.pop("_flashes", None)
                return redirect(url_for("get_all_posts"))
        else:
            flash("Bad Credentials")
        session.pop("_flashes", None)
    return render_template("login.html", form=login_form, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    """Handles logout operation by clearing the current session."""
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>", methods=["GET", "POST"])
def show_post(post_id):
    comment_form = CommentForm()
    post_comments = Comment.query.filter_by(post_id=post_id).all()
    requested_post = db.get_or_404(BlogPost, post_id)
    if request.method == "POST":
        comment_text = request.form.get("comment")
        post_id = post_id
        commenter_id = current_user.id
        new_comment = Comment(
            text=comment_text,
            post_id=post_id,
            commenter_id=commenter_id
        )
        db.session.add(new_comment)
        db.session.commit()
        return redirect(url_for("show_post", post_id=post_id))

    return render_template("post.html",
                           post=requested_post,
                           form=comment_form,
                           current_user=current_user,
                           comment_list=post_comments,
                           user=User,
                           logged_in=current_user.is_authenticated)


@app.route("/new-post", methods=["GET", "POST"])
@admin_only
@login_required
def add_new_post():
    """Only Admin can create a new post, the functionality of the project was build about this scenario."""
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
    return render_template(
        template_name_or_list="make-post.html",
        form=form,
        current_user=current_user,
        logged_in=current_user.is_authenticated
    )


@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@admin_only
@login_required
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
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
    return render_template("make-post.html", form=edit_form, is_edit=True, current_user=current_user)


@app.route("/delete/<int:post_id>")
@admin_only
@login_required
def delete_post(post_id):
    """Only Admin can create an edit a post, the functionality of the project was build about this scenario."""
    post_to_delete = db.get_or_404(BlogPost, post_id)
    comments_on_post = Comment.query.filter_by(post_id=post_id).all()
    # posts contain comments, so we need to delete comments to be able to delete a post because of the relationships.
    for comment in comments_on_post:
        db.session.delete(comment)
        db.session.commit()
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html", logged_in=current_user.is_authenticated)


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        form = request.form
        sender_name = form["name"]
        sender_email = form["email"]
        sender_phone_number = form["phone"]
        sender_message = form["message"]

        # Email content
        email_subject = "New message from your blog contact form"
        email_body = f"""
            Hi {sender_name},\n
            Thank you for reaching out through our contact form. Here is the message we received:\n
            Name: {sender_name}\n
            Email: {sender_email}\n
            Phone number: {sender_phone_number}\n
            Message: {sender_message}\n
            We will get back to you shortly.
        """

        # Create email headers
        email_message = f"Subject: {email_subject}\n\n{email_body}"

        # Send the email via SMTP
        with smtplib.SMTP("smtp.gmail.com", port=587) as connection:
            connection.starttls()  # Encrypts the email
            try:
                connection.login(user=MY_EMAIL, password=MY_PASS)
            except smtplib.SMTPAuthenticationError:
                app.logger.warning("Couldn't get access to the gmail account!")
                return render_template(
                    template_name_or_list="contact.html",
                    logged_in=current_user.is_authenticated,
                    msg_sent=False
                )
            else:
                connection.sendmail(
                    from_addr=MY_EMAIL,
                    to_addrs=RECEIVE_EMAIL,
                    msg=email_message
                )

                return render_template(
                    template_name_or_list="contact.html",
                    logged_in=current_user.is_authenticated,
                    msg_sent=True
                )

    return render_template("contact.html", logged_in=current_user.is_authenticated)


if __name__ == "__main__":
    app.run(debug=False)
