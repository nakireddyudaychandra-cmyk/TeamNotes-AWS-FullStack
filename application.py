"""TeamNotes - Flask backend for the templates in ./templates.

Elastic Beanstalk looks for a WSGI callable named `application`.
Config via environment variables:
  SECRET_KEY   session signing key (set a real one in production)
  DB_PATH      SQLite file path (default: teamnotes.db)
  S3_BUCKET    if set, attachments go to S3; otherwise saved in ./uploads
  AWS_REGION   optional, used by boto3
"""
import os
import sqlite3
import uuid
from datetime import datetime
from functools import wraps

from flask import (Flask, flash, g, redirect, render_template, request,
                   send_from_directory, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.environ.get("DB_PATH", os.path.join(BASE_DIR, "teamnotes.db"))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
S3_BUCKET = os.environ.get("S3_BUCKET")

application = app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-change-me")
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB uploads

STATUSES = ("open", "in-progress", "done")

_s3 = None
if S3_BUCKET:
    import boto3
    _s3 = boto3.client("s3", region_name=os.environ.get("AWS_REGION"))
else:
    os.makedirs(UPLOAD_DIR, exist_ok=True)


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            body TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            due_date TEXT,
            s3_key TEXT,
            filename TEXT,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            detail TEXT,
            timestamp TEXT NOT NULL
        );
        """
    )
    db.commit()
    db.close()


init_db()


def log_activity(action, detail):
    db = get_db()
    db.execute(
        "INSERT INTO activity (user_id, action, detail, timestamp) VALUES (?,?,?,?)",
        (session["user_id"], action, detail,
         datetime.utcnow().strftime("%Y-%m-%d %H:%M")),
    )
    db.commit()


# -------------------------------------------------------------------- auth
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return redirect(url_for("dashboard" if "user_id" in session else "login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        if not username or not password:
            flash("Username and password are required.")
        else:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?,?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
                flash("Account created. Please log in.")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already taken.")
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = get_db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("dashboard"))
        flash("Invalid username or password.")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --------------------------------------------------------------- dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    uid = session["user_id"]
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "")

    sql = "SELECT * FROM notes WHERE user_id = ?"
    params = [uid]
    if q:
        sql += " AND (title LIKE ? OR body LIKE ?)"
        params += [f"%{q}%", f"%{q}%"]
    if status in STATUSES:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY id DESC"
    notes = db.execute(sql, params).fetchall()

    counts = {
        r["status"]: r["c"]
        for r in db.execute(
            "SELECT status, COUNT(*) AS c FROM notes WHERE user_id = ? GROUP BY status",
            (uid,),
        )
    }
    activity = db.execute(
        "SELECT * FROM activity WHERE user_id = ? ORDER BY id DESC LIMIT 8", (uid,)
    ).fetchall()

    return render_template("dashboard.html", notes=notes, counts=counts,
                           activity=activity, q=q, status=status)


# ------------------------------------------------------------------- notes
def _get_own_note(note_id):
    return get_db().execute(
        "SELECT * FROM notes WHERE id = ? AND user_id = ?",
        (note_id, session["user_id"]),
    ).fetchone()


@app.route("/notes/new", methods=["POST"])
@login_required
def new_note():
    title = request.form["title"].strip()
    body = request.form.get("body", "").strip()
    status = request.form.get("status", "open")
    due_date = request.form.get("due_date") or None
    if not title:
        flash("Title is required.")
        return redirect(url_for("dashboard"))
    if status not in STATUSES:
        status = "open"

    s3_key = filename = None
    file = request.files.get("attachment")
    if file and file.filename:
        filename = secure_filename(file.filename)
        s3_key = f"{session['user_id']}/{uuid.uuid4().hex}_{filename}"
        if _s3:
            _s3.upload_fileobj(file, S3_BUCKET, s3_key)
        else:
            path = os.path.join(UPLOAD_DIR, s3_key)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            file.save(path)

    db = get_db()
    db.execute(
        "INSERT INTO notes (user_id, title, body, status, due_date, s3_key, "
        "filename, created_at) VALUES (?,?,?,?,?,?,?,?)",
        (session["user_id"], title, body, status, due_date, s3_key, filename,
         datetime.utcnow().isoformat()),
    )
    db.commit()
    log_activity("created", title)
    flash("Note added.")
    return redirect(url_for("dashboard"))


@app.route("/notes/<int:note_id>/update", methods=["POST"])
@login_required
def update_note(note_id):
    note = _get_own_note(note_id)
    status = request.form.get("status")
    if note and status in STATUSES:
        db = get_db()
        db.execute("UPDATE notes SET status = ? WHERE id = ?", (status, note_id))
        db.commit()
        log_activity("updated", f"{note['title']} -> {status}")
    return redirect(url_for("dashboard"))


@app.route("/notes/<int:note_id>/delete", methods=["POST"])
@login_required
def delete_note(note_id):
    note = _get_own_note(note_id)
    if note:
        if note["s3_key"]:
            if _s3:
                _s3.delete_object(Bucket=S3_BUCKET, Key=note["s3_key"])
            else:
                try:
                    os.remove(os.path.join(UPLOAD_DIR, note["s3_key"]))
                except OSError:
                    pass
        db = get_db()
        db.execute("DELETE FROM notes WHERE id = ?", (note_id,))
        db.commit()
        log_activity("deleted", note["title"])
        flash("Note deleted.")
    return redirect(url_for("dashboard"))


@app.route("/notes/<int:note_id>/download")
@login_required
def download_file(note_id):
    note = _get_own_note(note_id)
    if not note or not note["s3_key"]:
        flash("File not found.")
        return redirect(url_for("dashboard"))
    if _s3:
        url = _s3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": S3_BUCKET,
                "Key": note["s3_key"],
                "ResponseContentDisposition":
                    f'attachment; filename="{note["filename"]}"',
            },
            ExpiresIn=300,
        )
        return redirect(url)
    return send_from_directory(UPLOAD_DIR, note["s3_key"], as_attachment=True,
                               download_name=note["filename"])


if __name__ == "__main__":
    app.run(debug=True)
