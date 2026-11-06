"""Recipe Box API — BE104 course skeleton.

A working Flask + SQLite CRUD API for recipes. It stores data perfectly —
and it trusts everyone. There is no authentication and no authorization yet.
That is the point: you will add both, lesson by lesson, in Units 2 and 3.
"""

import sqlite3

from werkzeug.security import generate_password_hash, check_password_hash

from flask import Flask, g, jsonify, request, current_app
from functools import wraps

from dotenv import load_dotenv

import os

import jwt
from datetime import datetime, timedelta

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret")

print("JWT_SECRET loaded?", JWT_SECRET is not None)

DATABASE = "recipes.db"

app = Flask(__name__)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db

def hash_password(raw_password: str) -> str:
    return generate_password_hash(raw_password, method="pbkdf2:sha256")

def verify_password(stored_hash: str, candidate_password: str) -> bool:
    return check_password_hash(stored_hash, candidate_password)

@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def recipe_to_dict(row):
    return {
        "id": row["id"],
        "title": row["title"],
        "ingredients": row["ingredients"],
        "instructions": row["instructions"],
        "is_public": bool(row["is_public"]),
    }

def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return jsonify({"error": "authentication required"}), 401

        token = auth_header.split(" ", 1)[1]

        try:
            payload = jwt.decode(
                token,
                JWT_SECRET,
                algorithms=["HS256"],
            )
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "token expired, please log in again"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "invalid token"}), 401

        # Store user info on `g` for downstream use
        g.current_user_id = payload.get("sub")
        g.current_is_admin = payload.get("role", "user") == "admin"

        return fn(*args, **kwargs)

    return wrapper

@app.get("/")
def hello():
    return jsonify({"message": "Recipe Box API", "recipes": "/recipes"})


@app.get("/recipes")
@require_auth
def list_recipes():
    user_id = g.current_user_id
    
    rows = get_db().execute("SELECT * FROM recipes ORDER BY id").fetchall()
    return jsonify([recipe_to_dict(r) for r in rows])

@app.post("/register")
def register():
    data = request.get_json(silent=True) or {}

    username = str(data.get("username") or "").strip()
    email = str(data.get("email") or "").strip().lower()
    password = str(data.get("password") or "")

    if not username or not email or not password:
        return jsonify({"error": "username, email, and password are required"}), 400

    hashed = hash_password(password)
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')",
            (username, email, hashed),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "username or email already registered"}), 409

    return jsonify({
        "id": cur.lastrowid,
        "username": username,
        "email": email,
        "role": "user",
    }), 201

@app.post("/login")
def login():
    data = request.get_json(silent=True) or {}
    
    identifier = str(data.get("username") or data.get("email") or "").strip()
    password = str(data.get("password") or "")

    if not identifier or not password:
        return jsonify({"error": "Invalid credentials"}), 401

    db = get_db()
    row = db.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ? OR email = ?",
        (identifier, identifier.lower()),
    ).fetchone()

    if row is None or not verify_password(row["password_hash"], password):
        return jsonify({"error": "Invalid credentials"}), 401

    # 🧾 Build JWT payload — no secrets here
    payload = {
        "sub": str(row["id"]),  # user id as STRING
        "role": row["role"],  # user role
        "exp": datetime.utcnow() + timedelta(hours=1),  # expires in 1 hour
    }

    # 🔏 Sign token with your secret
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")

    return jsonify({
        "user": {
            "id": row["id"],
            "username": row["username"],
            "role": row["role"],
        },
        "token": token,
    }), 200

@app.get("/recipes/<int:recipe_id>")
def get_recipe(recipe_id):
    db = get_db()
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,),
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    # Public recipe? Anyone can see it, no auth needed.
    if row["is_public"]:
        return jsonify(recipe_to_dict(row))

    # From here on, it's a private recipe → need to authenticate.
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return jsonify({"error": "authentication required for private recipe"}), 401

    token = auth_header.split(" ", 1)[1]

    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=["HS256"],
        )
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "token expired, please log in again"}), 401
    except jwt.InvalidTokenError:
        return jsonify({"error": "invalid token"}), 401

    user_id = payload.get("sub")

    # Only the owner can see a private recipe
    if str(row["owner_id"]) != str(user_id):
        return jsonify({"error": "forbidden: not the recipe owner"}), 403

    return jsonify(recipe_to_dict(row))


@app.post("/recipes")
@require_auth
def create_recipe():
    user_id = g.current_user_id

    data = request.get_json(silent=True)
    if not data or not data.get("title") or not data.get("ingredients"):
        return jsonify({"error": "title and ingredients are required"}), 400

    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO recipes (title, ingredients, instructions, is_public, owner_id)"
            " VALUES (?, ?, ?, ?, ?)",
            (
                data["title"],
                data["ingredients"],
                data.get("instructions", ""),
                1 if data.get("is_public", True) else 0,
                user_id,
            ),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?", (cur.lastrowid,)
    ).fetchone()
    return jsonify(recipe_to_dict(row)), 201
 
@app.patch("/recipes/<int:recipe_id>")
@require_auth
def update_recipe(recipe_id):
    user_id = g.current_user_id
    is_admin = g.current_is_admin

    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "a JSON body is required"}), 400

    # ❌ Clients are not allowed to change ownership
    if "owner_id" in data:
        return jsonify({"error": "owner_id cannot be changed"}), 400

    db = get_db()

    # 1) Load the recipe from the DB
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,),
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    is_owner = str(row["owner_id"]) == str(user_id)

    # 2) Enforce ownership from the stored row
    if not (is_owner or is_admin):
        return jsonify({"error": "forbidden: not the recipe owner or admin"}), 403

    # 3) Build the update
    fields, values = [], []
    for column in ("title", "ingredients", "instructions"):
        if column in data:
            fields.append(f"{column} = ?")
            values.append(data[column])
    if "is_public" in data:
        fields.append("is_public = ?")
        values.append(1 if data["is_public"] else 0)

    if not fields:
        return jsonify({"error": "nothing to update"}), 400

    values.append(recipe_id)

    try:
        cur = db.execute(
            f"UPDATE recipes SET {', '.join(fields)} WHERE id = ?",
            values,
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "a recipe with that title already exists"}), 409

    if cur.rowcount == 0:
        return jsonify({"error": "recipe not found"}), 404

    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,),
    ).fetchone()
    return jsonify(recipe_to_dict(row))

@app.delete("/recipes/<int:recipe_id>")
@require_auth
def delete_recipe(recipe_id):
    user_id = g.current_user_id
    is_admin = g.current_is_admin

    db = get_db()

    # 1) Load the recipe
    row = db.execute(
        "SELECT * FROM recipes WHERE id = ?",
        (recipe_id,),
    ).fetchone()
    if row is None:
        return jsonify({"error": "recipe not found"}), 404

    # 2) Enforce ownership
    is_owner = str(row["owner_id"]) == str(user_id)
    if not (is_owner or is_admin):
        return jsonify({"error": "forbidden: not the recipe owner or admin"}), 403

    # 3) Owner/admin is allowed → delete
    cur = db.execute("DELETE FROM recipes WHERE id = ?", (recipe_id,))
    db.commit()

    return "", 204

if __name__ == "__main__":
   app.run(port=5001, debug=True)
