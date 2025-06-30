import os
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, jsonify
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
from sqlalchemy.exc import OperationalError
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo 
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_migrate import Migrate
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_limiter.errors import RateLimitExceeded
from dotenv import load_dotenv
from datetime import datetime
from utils import send_reset_email, verify_reset_token, generate_reset_token, mail

load_dotenv()

app = Flask(__name__)

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=5)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME")
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

if not app.config["SECRET_KEY"]:
    raise ValueError("No SECRET_KEY set for Flask application")

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail.init_app(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

@app.before_request
def warm_db():
    if request.endpoint in ('static', None) or request.path == '/favicon.ico':
        return
    
    try:
        db.session.execute(text("SELECT 1"))
    except OperationalError:
        app.logger.warning("Database is waking up or unreachable")

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    date_joined = db.Column(db.DateTime, default=datetime.now())

transaction_labels = db.Table("transaction_labels",
    db.Column("transaction_id", db.Integer, db.ForeignKey("transaction.id"), primary_key=True),
    db.Column("label_id", db.Integer, db.ForeignKey("label.id"), primary_key=True)
)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    date = db.Column(db.DateTime, default=datetime.now())
    description = db.Column(db.String(100), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(10), nullable=False)
    labels = db.relationship("Label", secondary=transaction_labels, backref="transactions")

class Label(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(50), nullable=False)

class Goal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    target_amount = db.Column(db.Float, nullable=False)
    saved_amount = db.Column(db.Float, default=0)
    status = db.Column(db.String(20), default="active")

with app.app_context():
    db.create_all()

REDIS_URL = os.getenv("REDIS_URL")
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per day"], storage_uri=REDIS_URL)
limiter.init_app(app)

@app.errorhandler(RateLimitExceeded)
def ratelimit_handler(e):
    return jsonify({
        "error": "Too many requests. Please slow down",
        "message": str(e.description)
    }), 429

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Forms
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=50)])
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Register")

class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField("New Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm New Password", validators=[DataRequired(), EqualTo("new_password")])
    submit = SubmitField("Change Password")

class ForgotPasswordForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Request Password Reset")

class ResetPasswordForm(FlaskForm):
    password = PasswordField("New Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm New Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Reset Password")

@app.route("/")
def home():
    return render_template("landing.html")

@app.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def register():
    form = RegisterForm()
    if request.method == "POST":    
        if form.validate_on_submit():
            existing_user = User.query.filter(
                (User.username == form.username.data) | (User.email == form.email.data)
            ).first()

            if existing_user:
                if existing_user.username == form.username.data:
                    flash("Username already exists", "danger")
                else:
                    flash("Email already registered", "danger")
                return redirect(url_for("register"))
            
            hashed_pw = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
            user = User(username=form.username.data, email=form.email.data, password=hashed_pw)
            db.session.add(user)
            db.session.commit()

            flash("Registration successful, please login", "success")
            return redirect(url_for("login"))
        else:
            flash("Form validation failed, please check your input", "danger")
    
    return render_template("register.html", form=form)

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data.strip()).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user)
            db.session.commit()
            flash("Login successful", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Incorrect username or password", "danger")

    return render_template("login.html", form=form)

@app.route("/dashboard", methods=["POST", "GET"])
@login_required
@limiter.limit("20 per minute")
def dashboard():
    if request.method == "POST":
        if "description" in request.form:
            desc = request.form["description"].strip().lower()
            label_names = request.form.get("label", "").split(", ")
            amount = float(request.form["amount"])
            ttype = request.form["type"]

            labels = []
            for label_name in label_names:
                label_name = label_name.strip().lower()
                if not label_name:
                    continue
                label = Label.query.filter_by(user_id=current_user.id, name=label_name).first()
                if not label:
                    label = Label(name=label_name, user_id=current_user.id)
                    db.session.add(label)
                    db.session.commit()
                labels.append(label)

            new_t = Transaction(description=desc, amount=amount, type=ttype, user_id=current_user.id, labels=labels)
            db.session.add(new_t)
            db.session.commit()

            for label in labels:
                goal = Goal.query.filter_by(user_id=current_user.id, name=label.name).first()
                if goal:
                    if ttype == "income":
                        goal.saved_amount += amount
                    elif ttype == "expense":
                        goal.saved_amount -= amount
                    goal.saved_amount = max(goal.saved_amount, 0)
                    if goal.saved_amount >= goal.target_amount and goal.status != "completed":
                        goal.status = "completed"
                        flash(f"Congratulations! Goal '{goal.name}' completed", "success")
                    elif goal.saved_amount < goal.target_amount and goal.status == "completed":
                        goal.status = "active"
                    db.session.commit()
            flash("Transaction added successfully", "success")
            return redirect(url_for("dashboard"))
            
        elif "goal_name" in request.form:
            name = request.form["goal_name"].strip().lower()
            target = float(request.form["goal_target_amount"])
            goal = Goal(name=name, target_amount=target, user_id=current_user.id)
            db.session.add(goal)
            db.session.commit()
            flash("Goal created successfully", "success")
            return redirect(url_for("dashboard"))

    query = Transaction.query.filter_by(user_id=current_user.id)
    start_date = request.args.get("start_date")
    end_date = request.args.get("end_date")
    ttype = request.args.get("type")
    search = request.args.get("query")

    if start_date:
        query = query.filter(Transaction.date >= start_date)
    if end_date:
        query = query.filter(Transaction.date <= end_date)
    if ttype:
        query = query.filter(Transaction.type == ttype)
    if search:
        query = query.filter(Transaction.description.ilike(f"%{search.strip().lower()}%"))

    transactions = query.order_by(Transaction.date.desc()).all()
    balance = sum(t.amount if t.type == "income" else -t.amount for t in transactions)
    goals = Goal.query.filter_by(user_id=current_user.id).all()
    for goal in goals:
        goal.progress = round((goal.saved_amount / goal.target_amount) * 100, 1) if goal.target_amount > 0 else 0
    user_labels = Label.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", transactions=transactions, balance=balance, goals=goals, user_labels=user_labels)

@app.route("/delete/goal/<int:gid>", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def delete_goal(gid):
    goal = Goal.query.filter_by(id=gid, user_id=current_user.id).first_or_404()
    if not goal:
        abort(404)

    db.session.delete(goal)
    db.session.commit()
    flash("Goal deleted", "info")
    return redirect(url_for("dashboard"))

@app.route("/profile")
@login_required
@limiter.limit("10 per minute")
def profile():
    return render_template("profile.html", user=current_user)

@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out", "info")
    return redirect(url_for("home"))

@app.route("/add", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def add_transaction():
    desc = request.form["description"].strip().lower()
    label_names = request.form.get("label", "").split(", ")
    amount = float(request.form["amount"])
    ttype = request.form["type"]

    labels = []
    for label_name in label_names:
        label_name = label_name.strip().lower()
        if not label_name:
            continue

        label = Label.query.filter_by(user_id=current_user.id, name=label_name).first()
        if not label:
            label = Label(name=label_name, user_id=current_user.id)
            db.session.add(label)
            db.session.commit()
        labels.append(label) 

    new_t = Transaction(description=desc, amount=amount, type=ttype, user_id=current_user.id, labels=labels)
    db.session.add(new_t)
    db.session.commit()

    for label in labels:
        goal = Goal.query.filter_by(user_id=current_user.id, name=label.name).first()
        if goal:
            if ttype == "income":
                goal.saved_amount += amount
            elif ttype == "expense":
                goal.saved_amount -= amount
            goal.saved_amount = max(goal.saved_amount, 0)
            if goal.saved_amount >= goal.target_amount and goal.status != "completed":
                goal.status = "completed"
                flash(f"Congratulations! Goal '{goal.name}' completed", "success")
            elif goal.saved_amount < goal.target_amount and goal.status == "completed":
                goal.status = "active"
            db.session.commit()           

    flash("Transaction added successfully", "success")
    return redirect(url_for("dashboard"))

@app.route("/edit/transaction/<int:tid>", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute")
def edit_transaction(tid):
    transaction = Transaction.query.filter_by(id=tid, user_id=current_user.id).first_or_404()

    if request.method == "POST":
        for label in transaction.labels:
            goal = Goal.query.filter_by(user_id=current_user.id, name=label.name).first()
            if goal:
                if transaction.type == "income":
                    goal.saved_amount -= transaction.amount
                elif transaction.type == "expense":
                    goal.saved_amount += transaction.amount

        transaction.description = request.form["description"].strip().lower()
        transaction.amount = float(request.form["amount"])
        transaction.type = request.form["type"]

        label_names = request.form.get("label", "").split(", ")
        transaction.labels.clear()

        for label_name in label_names:
            label_name = label_name.strip().lower()
            if not label_name:
                continue
            label = Label.query.filter_by(user_id=current_user.id, name=label_name).first()
            if not label:
                label = Label(name=label_name, user_id=current_user.id)
                db.session.add(label)
                db.session.commit()
            transaction.labels.append(label)

        db.session.commit()

        for label in transaction.labels:
            goal = Goal.query.filter_by(user_id=current_user.id, name=label.name).first()
            if goal:
                if transaction.type == "income":
                    goal.saved_amount += transaction.amount
                elif transaction.type == "expense":
                    goal.saved_amount -= transaction.amount
                goal.saved_amount = max(goal.saved_amount, 0)
                if goal.saved_amount >= goal.target_amount and goal.status != "completed":
                    goal.status = "completed"
                elif goal.saved_amount < goal.target_amount and goal.status == "completed":
                    goal.status = "active"
                db.session.commit()
        flash("Transaction upated successfully", "success")
        return redirect(url_for("dashboard"))
    
    label_string = ", ".join([label.name for label in transaction.labels])
    return render_template("dashboard.html", transaction=transaction, label_string=label_string)

@app.route("/delete/transaction/<int:tid>", methods=["POST"])
@login_required
@limiter.limit("10 per minute")
def delete_transaction(tid):
    transaction = Transaction.query.filter_by(id=tid, user_id=current_user.id).first_or_404()
    if not transaction:
       abort(404)

    for label in transaction.labels:
        goal = Goal.query.filter_by(user_id=current_user.id, name=label.name).first()
        if goal:
            if transaction.type == "income":
                goal.saved_amount -= transaction.amount
            elif transaction.type == "expense":
                goal.saved_amount += transaction.amount
            goal.saved_amount = max(goal.saved_amount, 0)
            if goal.saved_amount >= goal.target_amount and goal.status != "completed":
                goal.status = "completed"
            elif goal.saved_amount < goal.target_amount and goal.status == "completed":\
                goal.status = "active"
            db.session.commit()

    db.session.delete(transaction)
    db.session.commit()
    flash("Transaction deleted", "info")
    return redirect(url_for("dashboard"))

@app.route("/change_password", methods=["GET", "POST"])
@login_required
@limiter.limit("2 per minute")
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if bcrypt.check_password_hash(current_user.password, form.current_password.data):
            hashed_pw = bcrypt.generate_password_hash(form.new_password.data).decode("utf-8")
            current_user.password = hashed_pw
            db.session.commit()
            flash("Your password has been updated", "success")
            return redirect(url_for("profile"))
        else:
            flash("Incorrect current password", "danger")
    return render_template("change_password.html", form=form)

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = generate_reset_token(user.email)
            reset_url = url_for("reset_password", token=token, _external=True)
            send_reset_email(user.email, reset_url)
            flash(f"A password reset email has been sent to your registered email: {user.email}", "info")
        else:
            flash("Email not found", "danger")
        return redirect(url_for("login"))
    return render_template("forgot_password.html", form=form)

@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = verify_reset_token(token)
    if not email:
        flash("The reset link is invalid or has expired", "danger")
        return redirect(url_for("forgot_password"))
    
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first_or_404()
        hashed_pw = bcrypt.generate_password_hash(form.password.data).decode("utf-8")
        user.password = hashed_pw
        db.session.commit()
        flash("Your password has been updated, you can now login", "success")
        return redirect(url_for("login"))
    return render_template("reset_password.html", form=form)

if __name__ == "__main__":
    app.run(debug=True)