import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///jumpstart.db")


@app.route("/")
@login_required
def index():
    return redirect("/survey")


@app.route("/school", methods=["GET", "POST"])
@login_required
def school():
    return render_template("school.html")


@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()
    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            flash("Must provide username.")
            return redirect("/login")
        # Ensure password was submitted
        elif not request.form.get("password"):
            flash("Must provide password.")
            return redirect("/login")
        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Invalid username/password.")
            return redirect("/login")
        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        # Redirect user to home page
        flash("Successfully logged in.")
        return redirect("/")
    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""
    # Forget any user_id
    session.clear()
    # Redirect user to login form
    return redirect("/")


@app.route("/survey", methods=["GET", "POST"])
@login_required
def survey():
    return render_template("survey.html")


@app.route("/endsurvey", methods=["GET", "POST"])
@login_required
def endsurvey():
    return render_template("endsurvey.html")


@app.route("/takesurvey", methods=["GET", "POST"])
@login_required
def takesurvey():
    if request.method == "GET":
        return render_template("dailysurvey.html")
    else:
        return redirect("/endsurvey")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        # firstname = request.form.get("first-name")
        # lastname = request.form.get("last-name")
        # schoolname = request.form.get("school-name")
        # age = request.form.get("age")
        if not username:
            flash("Must provide username.")
            return redirect("/register")
        elif not password:
            flash("Must provide password.")
            return redirect("/register")
        elif password != confirmation:
            flash("Passwords don't match.")
            return redirect("/register")
        elif db.execute("SELECT username FROM users WHERE username = ?", (username)):
            flash("Username taken.")
            return redirect("/register")
        pw = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash) VALUES (:username, :oof)", username=username, oof=pw)
        return redirect("/")

@app.route("/info", methods=["GET", "POST"])
@login_required
def info():
    return render_template("info.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)