import os
from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo 
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from flask_migrate import Migrate
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("SQLALCHEMY_DATABASE_URI")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message_category = "info"

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    date_joined = db.Column(db.DateTime, default=datetime.now())

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    date = db.Column(db.DateTime, default=datetime.now())
    description = db.Column(db.String(100), nullable=False)
    label = db.Column(db.String(100))
    amount = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(10), nullable=False)

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

@app.route("/")
def home():
    return render_template("landing.html")

@app.route("/register", methods=["GET", "POST"])
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
def dashboard():
    transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.date.desc()).all()
    balance = sum(t.amount if t.type == "income" else -t.amount for t in transactions)
    goals = Goal.query.filter_by(user_id=current_user.id).all()
    user_labels = Label.query.filter_by(user_id=current_user.id).all()
    return render_template("dashboard.html", transactions=transactions, balance=balance, goals=goals, user_labels=user_labels)

@app.route("/goals", methods=["GET", "POST"])
@login_required
def goals():
    if request.method == "POST":
        name = request.form["name"]
        target = float(request.form["target_amount"])
        goal = Goal(name=name, target_amount=target, user_id=current_user.id)
        db.session.add(goal)
        db.session.commit()
        flash("Goal created successfully", "success")
        return redirect(url_for("goals"))
    
    user_goals = Goal.query.filter_by(user_id=current_user.id).all()
    for goal in user_goals:
        if goal.target_amount > 0:
            goal.progress = round((goal.saved_amount / goal.target_amount) * 100, 1)
        else:
            goal.progress = 0

    return render_template("goals.html", goals=user_goals)

@app.route("/delete/goal/<int:gid>", methods=["POST"])
@login_required
def delete_goal(gid):
    goal = Goal.query.filter_by(id=gid, user_id=current_user.id).first_or_404()
    db.session.delete(goal)
    db.session.commit()
    flash("Goal deleted", "info")
    return redirect(url_for("goals"))

@app.route("/profile")
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
def add_transaction():
    desc = request.form["description"]
    label_name = request.form["label"].strip()
    amount = float(request.form["amount"])
    ttype = request.form["type"]

    label = Label.query.filter_by(user_id=current_user.id, name=label_name).first()
    if not label and label_name:
        label = Label(name=label_name, user_id=current_user.id)
        db.session.add(label)
        db.session.commit()

    new_t = Transaction(description=desc, label=label.name, amount=amount, type=ttype, user_id=current_user.id)
    db.session.add(new_t)
    db.session.commit()

    goal = Goal.query.filter_by(user_id=current_user.id, name=label.name).first()
    if goal:
        if ttype == "income":
            goal.saved_amount += amount
        elif ttype == "expense":
            goal.saved_amount -= amount

        goal.saved_amount = max(goal.saved_amount, 0)

        if goal.saved_amount >= goal.target_amount:
            if goal.status != "completed":
                goal.status = "completed"
                flash(f"Congratulations! Goal '{goal.name}' completed", "success")
        else:
            if goal.status == "completed":
                goal.status = "active"

        db.session.commit()

    return redirect(url_for("dashboard"))

@app.route("/delete/transaction/<int:tid>", methods=["POST"])
@login_required
def delete_transaction(tid):
    transaction = Transaction.query.filter_by(id=tid, user_id=current_user.id).first_or_404()
    db.session.delete(transaction)
    db.session.commit()
    flash("Transaction deleted", "info")
    return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(debug=True)