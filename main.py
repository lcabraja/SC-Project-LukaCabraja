from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import text
import requests
import os
import json

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SECRET_KEY"] = "your_secret_key"  # Change this to a secure, random string
db = SQLAlchemy(app)

sqlinjection = True

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)


@app.before_first_request
def create_tables():
    db.create_all()


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User(username=username, password=password)
        db.session.add(user)
        db.session.commit()

        # return jsonify({"message": "User registered successfully."}), 201
        return redirect(url_for("login"))
    else:
        return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        data = request.form
        username = data["username"]
        password = data["password"]

        user = None
        if sqlinjection:
            # This creates an SQL injection vulnerability.
            query = text(
                f"SELECT * FROM user WHERE username='{username}' AND password='{password}'"
            )
            result = db.session.execute(query)
            user = result.first()
        else:
            # This fixes the SQL injection vulnerability.
            user = User.query.filter_by(username=username, password=password).first()

        if user:
            session["username"] = username
            return redirect(url_for("home"))
        else:
            return "Invalid credentials.", 401
    else:
        return render_template("login.html")


@app.route("/logout", methods=["GET"])
def logout():
    # Remove 'username' from the session if it exists
    session.pop("username", None)
    return redirect(url_for("home"))


@app.route("/")
def home():
    if "username" in session:
        return render_template("chat.html")
    else:
        return render_template("home.html")


@app.route("/chat", methods=["GET", "POST"])
def chat():
    # Load chat history from JSON file
    filename = os.path.join("./data", f'{session["username"]}.json')
    if os.path.exists(filename):
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
            "username": session.get("username"),
            "model": "gpt-3.5-turbo",
            "messages": session["chat"],
        }

        if not os.path.exists("./data"):
            os.makedirs("./data")
        with open(os.path.join("./data", f'{session["username"]}.json'), "w") as f:
            json.dump(chat_data, f)

    return render_template("chat.html", chat=session["chat"])


@app.route("/session", methods=["GET"])
def get_session():
    return jsonify(dict(session))


if __name__ == "__main__":
    app.run(debug=True)
