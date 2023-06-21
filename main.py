from datetime import timedelta
import hashlib
import time
from flask import (
    Flask,
    make_response,
    request,
    jsonify,
    render_template,
    session,
    redirect,
    url_for,
)
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import LargeBinary, text
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    create_refresh_token,
    get_jwt,
    jwt_required,
    get_jwt_identity,
    set_access_cookies,
    set_refresh_cookies,
    unset_jwt_cookies,
)
import requests
import os
import json

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SECRET_KEY"] = "your_secret_key"
app.config["JWT_SECRET_KEY"] = "your_jwt_secret_key"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(seconds=10)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=60)
app.config["JWT_COOKIE_CSRF_PROTECT"] = False

for key in app.config:
    print(f"{key} = {app.config[key]}")

SERIALIZED_DATA_DIR = "./data"

db = SQLAlchemy(app)
jwt = JWTManager(app)

sqlinjection = False
owaspzap = True


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)
    chat_hash = db.Column(LargeBinary(64), nullable=True)  # This will store the hash
    
@app.before_first_request
def create_tables():
    db.create_all()

@app.route("/register", methods=["GET"])
def register():
    return render_template("register.html")


@app.route("/register", methods=["POST"])
def register_post():
    username = request.form["username"]
    password = request.form["password"]

    if sqlinjection:
        # This creates an SQL injection vulnerability.
        query = text(
            f"INSERT INTO user (username, password) VALUES ('{username}', '{password}')"
        )
        db.session.execute(query)
    else:
        # This is the safe way to insert a new user using SQLAlchemy's ORM.
        user = User(username=username, password=password)
        db.session.add(user)

    db.session.commit()

    return redirect(url_for("login"))


@app.route("/login", methods=["GET"])
def login():
    return render_template("login.html")


@app.route("/login", methods=["POST"])
def login_post():
    data = request.form
    username = data["username"]
    password = data["password"]

    user = None
    if sqlinjection:
        query = text(
            f"SELECT * FROM user WHERE username='{username}' AND password='{password}'"  # noqa: E501
        )
        result = db.session.execute(query)
        user = result.first()
    else:
        user = User.query.filter_by(username=username, password=password).first()

    if user:
        resp = make_response(redirect(url_for("home")))
        access_token = create_access_token(identity=username)
        refresh_token = create_refresh_token(identity=username)
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        return resp
    else:
        session["error"] = "Invalid credentials."
        return render_template("login.html", error=session["error"]), 401


@app.route("/logout", methods=["GET"])
@jwt_required()
def logout():
    resp = make_response(redirect(url_for("login")))
    unset_jwt_cookies(resp)
    session.clear()
    return resp


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return redirect(url_for("refresh"))


@app.after_request
def add_security_headers(response):
    if owaspzap:
        # response.headers["Server"] = "Hidden"
        # response.headers["Content-Security-Policy"] = "default-src 'self' https://mitsuha.tailf8ebe.ts.net http://host.docker.internal:5000 https://localhost:5000"
        # response.headers["X-Content-Type-Options"] = "nosniff"
        # response.headers["X-XSS-Protection"] = "1; mode=block"
        # response.headers["X-Frame-Options"] = "SAMEORIGIN"
        # response.headers["Permissions-Policy"] = "geolocation=(), midi=(), notifications=(), push=(), sync-xhr=(), microphone=(), camera=(), magnetometer=(), gyroscope=(), speaker=(self), vibrate=(), fullscreen=(self), payment=()"
        if request.path == "/login" or request.path == "/register":
            response.cache_control.max_age = 300
        else:
            response.cache_control.no_store = True
    return response


@app.route("/refresh", methods=["GET"])
@jwt_required(refresh=True, verify_type=False)
def refresh():
    session["refresh"] = True
    current_user = get_jwt_identity()
    access_token = create_access_token(identity=current_user)
    resp = make_response(redirect(url_for("chat")))
    set_access_cookies(resp, access_token)
    return resp


@app.route("/", methods=["GET"])
@jwt_required(optional=True)
def home():
    current_user = get_jwt_identity()
    if current_user:
        return redirect(url_for("chat"))
    else:
        return render_template("home.html")


@app.route("/chat", methods=["GET", "POST"])
@jwt_required()
def chat():
    username = get_jwt_identity()
    user = User.query.filter_by(username=username).first() # Get the user
    filename = os.path.join(SERIALIZED_DATA_DIR, f"{username}.json")
    if os.path.exists(filename):
        # Calculate the hash of the file
        hasher = hashlib.sha256()
        with open(filename, "rb") as f:
            buf = f.read()
            hasher.update(buf)
        current_hash = hasher.digest()  # This is the current hash of the file

        # If the hash in the database and the calculated hash don't match,
        # it means the file may have been tampered with
        if user.chat_hash != current_hash:
            return "Error: chat data file integrity could not be verified.", 500

        # Load the chat data if the hashes match
        with open(filename, "r") as f:
            chat_data = json.load(f)
            session["chat"] = chat_data.get("messages", [])
    else:
        session["chat"] = []


    if request.method == "POST":
        message = request.form["message"]

        headers = {
            "Authorization": f"Bearer {os.environ.get('OPENAI_API_KEY')}",
            "Content-Type": "application/json",
        }

        data = {
            "model": "gpt-3.5-turbo",
            "messages": session["chat"] + [{"role": "user", "content": message}],
        }

        response = requests.post(
            "https://api.openai.com/v1/chat/completions", headers=headers, json=data
        )

        response_message = response.json()["choices"][0]["message"]["content"]
        if response_message.startswith("GPT-3: "):
            response_message = response_message[7:]

        # Add new chat message to the session
        session["chat"].append({"role": "user", "content": message})
        session["chat"].append({"role": "assistant", "content": response_message})

        # Save chat history to a JSON file
        chat_data = {
            "username": username,
            "model": "gpt-3.5-turbo",
            "messages": session["chat"],
        }

        if not os.path.exists(SERIALIZED_DATA_DIR):
            os.makedirs(SERIALIZED_DATA_DIR)
        
        userjson = f"{username}.json"
        with open(os.path.join(SERIALIZED_DATA_DIR, userjson), "w") as f:
            json.dump(chat_data, f)
        
        hasher = hashlib.sha256()
        with open(os.path.join(SERIALIZED_DATA_DIR, userjson), "rb") as f:
            buf = f.read()
            hasher.update(buf)
        file_hash = hasher.digest()  # This is the hash of the file

        # Update the user record with the hash
        user = User.query.filter_by(username=username).first()
        user.chat_hash = file_hash
        db.session.commit()

    refresh = session.get("refresh", False)
    session.pop("refresh", None)
    resp = make_response(
        render_template("chat.html", chat=session["chat"], refresh=refresh)
    )

    token_expiry = get_jwt()["exp"]
    current_time = time.time()
    if token_expiry - current_time <= 5 * 60:
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        set_access_cookies(resp, access_token)

    return resp


@app.route("/session", methods=["GET"])
@jwt_required()
def get_session():
    return jsonify(dict(session))


@app.route("/jwt", methods=["GET"])
@jwt_required(verify_type=False)
def demonstration_jwt():
    refresh = request.args.get("refresh", default=False, type=bool)
    token_expiry = get_jwt()["exp"]
    current_time = time.time()
    remaining_time = token_expiry - current_time
    if refresh:
        current_user = get_jwt_identity()
        access_token = create_access_token(identity=current_user)
        response = make_response(
            f"Token time remaining was {str(timedelta(seconds=int(remaining_time)))}. Was refreshed"  # noqa: E501
        )
        set_access_cookies(response, access_token)
        return response
    else:
        return f"Token time remaining {str(timedelta(seconds=int(remaining_time)))[2:]}"


if __name__ == "__main__":
    app.run(debug=True, port=5002)
