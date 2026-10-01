import hmac
import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("DATA_DIR", str(BASE_DIR / "data"))).expanduser()
BOOKS_DIR = DATA_DIR / "books"
DB_PATH = DATA_DIR / "books.sqlite3"

DATA_DIR.mkdir(parents=True, exist_ok=True)
BOOKS_DIR.mkdir(parents=True, exist_ok=True)

SECRET_KEY = os.getenv("SECRET_KEY")
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "owner")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")

if not SECRET_KEY:
    raise RuntimeError("Добавьте SECRET_KEY в файл .env")
if not ADMIN_PASSWORD_HASH:
    raise RuntimeError("Добавьте ADMIN_PASSWORD_HASH в файл .env")

app = Flask(__name__)
app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=500 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("COOKIE_SECURE", "false").lower()
    in {"1", "true", "yes", "on"},
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

CSRFProtect(app)

ALLOWED_EXTENSIONS = {".pdf", ".epub"}
MAX_BOOK_SIZE = 500 * 1024 * 1024


def init_db():
    connection = sqlite3.connect(DB_PATH)
    try:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS books (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                author TEXT NOT NULL DEFAULT '',
                description TEXT NOT NULL DEFAULT '',
                original_filename TEXT NOT NULL,
                stored_filename TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """)
        connection.commit()
    finally:
        connection.close()


init_db()


def get_db():
    if "db" not in g:
        connection = sqlite3.connect(DB_PATH, timeout=15)
        connection.row_factory = sqlite3.Row
        g.db = connection
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    connection = g.pop("db", None)
    if connection is not None:
        connection.close()


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("is_admin"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


@app.get("/")
def index():
    books = get_db().execute("SELECT * FROM books ORDER BY id DESC").fetchall()
    return render_template("index.html", books=books)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("is_admin"):
        return redirect(url_for("admin"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        username_ok = hmac.compare_digest(username, ADMIN_USERNAME)
        password_ok = (
            check_password_hash(ADMIN_PASSWORD_HASH, password)
            if len(password) <= 1024
            else False
        )

        if username_ok and password_ok:
            session.clear()
            session["is_admin"] = True
            session.permanent = True
            flash("Вы вошли в панель управления.", "success")
            return redirect(url_for("admin"))

        flash("Неверный логин или пароль.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.post("/logout")
@admin_required
def logout():
    session.clear()
    flash("Вы вышли из панели управления.", "success")
    return redirect(url_for("index"))


@app.get("/admin")
@admin_required
def admin():
    books = get_db().execute("SELECT * FROM books ORDER BY id DESC").fetchall()
    return render_template("admin.html", books=books)


def _save_uploaded_book(uploaded_file, file_path, book_data):
    try:
        uploaded_file.save(file_path)

        db = get_db()
        db.execute(
            """
            INSERT INTO books (
                title, author, description,
                original_filename, stored_filename, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            book_data,
        )
        db.commit()
    except Exception:
        try:
            file_path.unlink(missing_ok=True)
        except OSError:
            app.logger.exception("Не удалось удалить незаписанный файл")
        raise


@app.post("/admin/books")
@admin_required
def add_book():
    title = " ".join((request.form.get("title") or "").split())
    author = " ".join((request.form.get("author") or "").split())
    description = (request.form.get("description") or "").strip()

    if not title:
        flash("Укажите название книги.", "error")
        return redirect(url_for("admin"))

    if len(title) > 200 or len(author) > 200 or len(description) > 5000:
        flash("Проверьте длину названия, автора и описания.", "error")
        return redirect(url_for("admin"))

    uploaded_file = request.files.get("book_file")
    if not uploaded_file or not uploaded_file.filename:
        flash("Выберите файл книги.", "error")
        return redirect(url_for("admin"))

    # Убираем из имени файла путь, который может прислать браузер.
    original_filename = uploaded_file.filename.replace("\\", "/").rsplit("/", 1)[-1]
    original_filename = "".join(
        char for char in original_filename if ord(char) >= 32 and ord(char) != 127
    ).strip()

    extension = Path(original_filename).suffix.lower()

    if not original_filename or extension not in ALLOWED_EXTENSIONS:
        flash("Можно загружать только файлы PDF или EPUB.", "error")
        return redirect(url_for("admin"))

    uploaded_file.stream.seek(0, os.SEEK_END)
    file_size = uploaded_file.stream.tell()
    uploaded_file.stream.seek(0)

    if file_size == 0:
        flash("Файл пустой.", "error")
        return redirect(url_for("admin"))

    if file_size > MAX_BOOK_SIZE:
        flash("Размер книги не должен превышать 500 МБ.", "error")
        return redirect(url_for("admin"))

    stored_filename = f"{uuid.uuid4().hex}{extension}"
    file_path = BOOKS_DIR / stored_filename

    _save_uploaded_book(
        uploaded_file,
        file_path,
        (
            title,
            author,
            description,
            original_filename,
            stored_filename,
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
        ),
    )

    flash("Книга опубликована.", "success")
    return redirect(url_for("admin"))


@app.post("/admin/books/<int:book_id>/delete")
@admin_required
def delete_book(book_id):
    db = get_db()
    book = db.execute(
        "SELECT stored_filename FROM books WHERE id = ?",
        (book_id,),
    ).fetchone()

    if book is None:
        abort(404)

    db.execute("DELETE FROM books WHERE id = ?", (book_id,))
    db.commit()

    try:
        (BOOKS_DIR / book["stored_filename"]).unlink(missing_ok=True)
    except OSError:
        app.logger.exception("Не удалось удалить файл книги")

    flash("Книга удалена.", "success")
    return redirect(url_for("admin"))


@app.get("/books/<int:book_id>/download")
def download_book(book_id):
    book = (
        get_db()
        .execute(
            "SELECT * FROM books WHERE id = ?",
            (book_id,),
        )
        .fetchone()
    )

    if book is None:
        abort(404)

    extension = Path(book["stored_filename"]).suffix.lower()
    mimetype = {
        ".pdf": "application/pdf",
        ".epub": "application/epub+zip",
    }.get(extension)

    if mimetype is None:
        abort(404)

    response = send_from_directory(
        str(BOOKS_DIR),
        book["stored_filename"],
        as_attachment=True,
        download_name=book["original_filename"],
        mimetype=mimetype,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@app.errorhandler(413)
def file_too_large(_error):
    return "Файл слишком большой. Максимальный размер книги — 500 МБ.", 413


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
