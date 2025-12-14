from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, url_for
from flask_session import Session
from datetime import datetime
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from models import User

app = Flask(__name__, template_folder='templates', static_folder='static')

app.config["SECRET_KEY"] = "secretkey"

# Enable debug mode
app.config["DEBUG"] = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///idguardian.db")

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    # model method that returns user by their id
    return User.get_by_id(int(user_id))

# Home page
@app.route('/')
@login_required
def home():
    return render_template("home.html")

# log user in
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "GET":
        logout_user()
        return render_template("login.html")
    else:
        identifier = request.form.get("identifier")
        password = request.form.get("password")

        # Check if identifier or password weren't provided
        if not identifier:
            flash("You must provide your username or national id", "error")
            return redirect("/login")
        elif not password:
            flash("You must provide your password", "error")
            return redirect("/login")
        else:

            # Try username
            user = User.get_by_username(identifier)
            # If no user was found, try national id
            if not user:
                user = User.get_by_national_id(identifier)
            if not user:
                flash("Invalid credentials", "error")
                return redirect("/login")
            if user.verify_password(password):
                login_user(user)
                return redirect("/")
            else:
                flash("Invalid credentials", "error")
                return redirect("/login")

# log user out           
@app.route("/logout")
def logout():
    logout_user()
    return redirect("/login")

@app.route("/register", methods=["GET", "POST"])
def register():
    return render_template("register.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    return render_template("reset-password.html")


if __name__ == "__main__":
    app.run(debug=True)


