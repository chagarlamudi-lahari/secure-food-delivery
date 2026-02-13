from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import pyotp
from security.intrusion_detection import detect_brute_force, log_attack
from security.encryption_utils import encrypt_data, decrypt_data
from security.access_control import check_access
from security.otp_auth import generate_otp, verify_otp

app = Flask(__name__)
app.secret_key = "secretkey123"

# Database connection
def get_db():
    return sqlite3.connect("database/users.db")

# Create table
def create_table():
    db = get_db()
    db.execute("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        username TEXT UNIQUE,
        email BLOB,
        password BLOB,
        failed INTEGER DEFAULT 0,
        blocked INTEGER DEFAULT 0
    )
    """)
    db.commit()


create_table()

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET","POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"] 
        password = request.form["password"]

        hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        encrypted_email = encrypt_data(email)

        db = get_db()
        try:
            db.execute(
                "INSERT INTO users(username,email,password) VALUES(?,?,?)",
                (username, encrypted_email, hashed)
            )
            db.commit()
            return redirect("/login")
        except Exception as e:
            print("REGISTRATION ERROR:", e)
            return f"Registration error: {e}"


    return render_template("register.html")


@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=?",
            (username,)
        ).fetchone()

        if user is None:
            return "User not found"

        if bcrypt.checkpw(password.encode(), user[2]):
            otp = generate_otp()
            session["otp"] = otp
            session["user"] = username
    
            # 🔐 Store role here
            session["role"] = user[6]  # temporary default role
            print("Generated OTP:", otp) 
            
            return redirect("/otp")

        else:
            if detect_brute_force(username):
               log_attack(f"Brute force detected for {username}")
               return "Account blocked due to suspicious activity"

            log_attack(f"Failed login attempt for {username}")
            return "Wrong password"

            return "Wrong password"

    return render_template("login.html")

@app.route("/otp", methods=["GET", "POST"])
def otp():
    if request.method == "POST":
        entered_otp = request.form["otp"]

        if verify_otp(session.get("otp"), entered_otp):
            session.pop("otp", None)
            return redirect("/dashboard")
        else:
            log_attack(f"OTP verification failed for {session.get('user')}")
            return "Wrong OTP"

    return render_template("otp.html")



@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/restaurants")
def restaurants():
    return render_template("restaurants.html")


@app.route("/orders")
def orders():
    return render_template("orders.html")

@app.route("/payment")
def payment():
    return render_template("payment.html")


@app.route("/admin")
def admin():
    db = get_db()
    users = db.execute(
        "SELECT username, failed, blocked FROM users"
    ).fetchall()

    return render_template("admin.html", users=users)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/security-log")
def security_log():
    if "user" not in session:
        return redirect("/login")

    try:
        with open("monitoring/security_logs.txt", "r") as file:
            logs = file.readlines()
    except:
        logs = ["No security logs found."]

    return render_template("security_log.html", logs=logs)

app.run(debug=True)
