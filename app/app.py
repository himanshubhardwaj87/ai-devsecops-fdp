"""ShopLite - a DELIBERATELY VULNERABLE demo service.

Teaching material for the FDP session "AI-Driven DevSecOps".
Every flaw below is intentional so the pipeline has something to find.
Never deploy this. It binds to all interfaces and runs in debug mode on purpose.
"""
import hashlib
import pickle
import sqlite3
import subprocess

import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)

# Flaw 1: credentials committed to source control (fake values, real pattern).
app.config["SECRET_KEY"] = "shoplite-prod-secret-2026"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
DB_PASSWORD = "Sup3rS3cretPassw0rd!"

DB_PATH = "shoplite.db"


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # Flaw 2: MD5 is not a password hash.
    digest = hashlib.md5(password.encode()).hexdigest()
    # Flaw 3: SQL built by string formatting -> SQL injection on the login path.
    query = f"SELECT id FROM users WHERE name = '{username}' AND pw = '{digest}'"
    row = get_db().execute(query).fetchone()
    return jsonify({"ok": row is not None})


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # Flaw 4: user input reaches a shell -> command injection.
    output = subprocess.check_output(f"ping -n 1 {host}", shell=True)
    return output


@app.route("/cart/restore", methods=["POST"])
def restore_cart():
    # Flaw 5: unpickling attacker-controlled bytes -> remote code execution.
    cart = pickle.loads(request.data)
    return jsonify({"items": len(cart)})


@app.route("/config", methods=["POST"])
def load_config():
    # Flaw 6: yaml.load without a safe loader can construct arbitrary objects.
    config = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify({"keys": list(config)})


if __name__ == "__main__":
    # Flaw 7: debug console exposed on every network interface.
    app.run(host="0.0.0.0", port=5000, debug=True)
