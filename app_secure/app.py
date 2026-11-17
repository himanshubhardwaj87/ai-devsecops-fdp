"""ShopLite - the remediated version of the demo service.

Same endpoints as app/app.py with each flaw fixed, so the pipeline can be
re-run to show the gate turning green.
"""
import ipaddress
import json
import os
import socket
import sqlite3

import yaml
from flask import Flask, jsonify, request
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Fix 1: secrets come from the environment (or a secret manager), never the repo.
app.config["SECRET_KEY"] = os.environ["SHOPLITE_SECRET_KEY"]

DB_PATH = os.environ.get("SHOPLITE_DB_PATH", "shoplite.db")
MAX_BODY_BYTES = 64 * 1024


def get_db():
    return sqlite3.connect(DB_PATH)


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    # Fix 3: parameterised query - user input is never part of the SQL text.
    row = get_db().execute(
        "SELECT pw_hash FROM users WHERE name = ?", (username,)
    ).fetchone()
    # Fix 2: salted, slow password hash verified in constant time.
    ok = row is not None and check_password_hash(row[0], password)
    return jsonify({"ok": ok})


@app.route("/ping")
def ping():
    raw_host = request.args.get("host", "127.0.0.1")
    try:
        # Fix 4: validate input and avoid the shell entirely.
        host = str(ipaddress.ip_address(raw_host))
    except ValueError:
        return jsonify({"error": "host must be an IP address"}), 400
    try:
        with socket.create_connection((host, 80), timeout=2):
            reachable = True
    except OSError:
        reachable = False
    return jsonify({"host": host, "reachable": reachable})


@app.route("/cart/restore", methods=["POST"])
def restore_cart():
    if len(request.data) > MAX_BODY_BYTES:
        return jsonify({"error": "payload too large"}), 413
    try:
        # Fix 5: JSON is data only - it cannot execute code when parsed.
        cart = json.loads(request.data)
    except json.JSONDecodeError:
        return jsonify({"error": "cart must be valid JSON"}), 400
    if not isinstance(cart, list):
        return jsonify({"error": "cart must be a list"}), 400
    return jsonify({"items": len(cart)})


@app.route("/config", methods=["POST"])
def load_config():
    try:
        # Fix 6: safe_load only builds plain Python data types.
        config = yaml.safe_load(request.data)
    except yaml.YAMLError:
        return jsonify({"error": "config must be valid YAML"}), 400
    if not isinstance(config, dict):
        return jsonify({"error": "config must be a mapping"}), 400
    return jsonify({"keys": list(config)})


if __name__ == "__main__":
    # Fix 7: no debug console, loopback only; a real deployment sits behind a WSGI server.
    app.run(host="127.0.0.1", port=5000, debug=False)
