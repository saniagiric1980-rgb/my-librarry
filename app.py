import base64
import hmac
import json
import os
import uuid
from datetime import datetime, timezone, timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import quote, urlparse

import requests
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_wtf import CSRFProtect
from werkzeug.security import check_password_hash


BASE_DIR = Path(__file__).resolve().parent
load_dotenv(BASE_DIR / ".env")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "owner").strip()
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH", "").strip()
SECRET_KEY = os.getenv("SECRET_KEY", "").strip()
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "").strip()
GITHUB_REPO = os.getenv("GITHUB_REPO", "").strip()
GITHUB_PATH = os.getenv("GITHUB_PATH", "books.json").strip().lstrip("/")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "main").strip()

if not ADMIN_PASSWORD_HASH:
    raise RuntimeError("Не задана переменная ADMIN_PASSWORD_HASH")

if len(SECRET_KEY) < 32:
    raise RuntimeError("SECRET_KEY должен содержать минимум 32 символа")

if not GITHUB_TOKEN:
    raise RuntimeError("Не задана переменная GITHUB_TOKEN")

if not GITHUB_REPO or "/" not in GITHUB_REPO:
    raise RuntimeError("GITHUB_REPO должен иметь формат owner/repository")


app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "templates"),
    static_folder=str(BASE_DIR / "static"),
)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

CSRFProtect(app)


class GitHubStorageError(Exception):
    """Ошибка чтения или записи books.json на GitHub."""


def github_headers():
    return {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {GITHUB_TOKEN}",
        "X-GitHub-Api-Version": "2022-11-28",
        "Content-Type": "application/json",
    }


def github_file_url(with_ref=False):
    encoded_path = quote(GITHUB_PATH, safe="/")
    url = f"https://api.github.com/repos/{GITHUB_REPO}/contents/{encoded_path}"
    if with_ref:
        url += f"?ref={quote(GITHUB_BRANCH, safe='')}"
    return url


def read_books_from_github():
    try:
        response = requests.get(
            github_file_url(with_ref=True),
            headers=github_headers(),
            timeout=15,
        )
    except requests.RequestException as error:
        raise GitHubStorageError("Не удалось подключиться к GitHub") from error

    if response.status_code == 404:
        return [], None

    if response.status_code != 200:
        raise GitHubStorageError(f"GitHub вернул ошибку {response.status_code}")

    try:
        file_data = response.json()
        encoded_content = file_data["content"].replace("\n", "")
        decoded_content = base64.b64decode(encoded_content).decode("utf-8")
        books = json.loads(decoded_content)
    except (ValueError, KeyError, TypeError) as error:
        raise GitHubStorageError("Файл books.json имеет неправильный формат") from error

    if not isinstance(books, list):
        raise GitHubStorageError("books.json должен содержать список книг")

    return books, file_data.get("sha")


def load_books():
    books, _sha = read_books_from_github()
    return books


def save_books_to_github(books):
    _current_books, sha = read_books_from_github()

    json_content = json.dumps(books, ensure_ascii=False, indent=2).encode("utf-8")
    encoded_content = base64.b64encode(json_content).decode("ascii")

    payload = {
        "message": "Обновить каталог книг",
        "content": encoded_content,
        "branch": GITHUB_BRANCH,
    }
    if sha:
        payload["sha"] = sha

    try:
        response = requests.put(
            github_file_url(with_ref=False),
            headers=github_headers(),
            json=payload,
            timeout=20,
        )
    except requests.RequestException as error:
        raise GitHubStorageError("Не удалось сохранить данные на GitHub") from error

    if response.status_code not in {200, 201}:
        if response.status_code == 409:
            raise GitHubStorageError("Файл books.json изменился. Повторите попытку.")
        raise GitHubStorageError(
            f"GitHub не сохранил файл. Код: {response.status_code}"
        )


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if session.get("is_admin") is not True:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def valid_book_url(value):
    if not value or len(value) > 2000:
        return False

    try:
        parsed = urlparse(value)
        return (
            parsed.scheme in {"http", "https"}
            and bool(parsed.netloc)
            and bool(parsed.hostname)
        )
    except ValueError:
        return False


def clean_text(value, max_length):
    value = (value or "").strip()
    return value[:max_length]


def get_books_or_503():
    try:
        return load_books()
    except GitHubStorageError:
        app.logger.exception("Ошибка чтения книг из GitHub")
        abort(503)


@app.get("/")
def index():
    return render_template("index.html", books=get_books_or_503())


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("is_admin") is True:
        return redirect(url_for("admin"))

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        username_ok = hmac.compare_digest(username, ADMIN_USERNAME)

        try:
            password_ok = (
                len(password) <= 1024
                and check_password_hash(ADMIN_PASSWORD_HASH, password)
            )
        except (ValueError, TypeError):
            password_ok = False

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
    return render_template("admin.html", books=get_books_or_503())


@app.post("/admin/books")
@admin_required
def add_book():
    title = clean_text(" ".join((request.form.get("title") or "").split()), 200)
    author = clean_text(" ".join((request.form.get("author") or "").split()), 200)
    description = clean_text(request.form.get("description"), 5000)
    book_url = clean_text(request.form.get("book_url"), 2000)

    if not title:
        flash("Укажите название книги.", "error")
        return redirect(url_for("admin"))

    if not valid_book_url(book_url):
        flash("Укажите правильную ссылку на книгу.", "error")
        return redirect(url_for("admin"))

    try:
        books = load_books()
        books.insert(0, {
            "id": uuid.uuid4().hex,
            "title": title,
            "author": author,
            "description": description,
            "book_url": book_url,
            "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        })
        save_books_to_github(books)
    except GitHubStorageError:
        app.logger.exception("Ошибка добавления книги")
        flash("Не удалось сохранить книгу. Проверьте настройки GitHub.", "error")
        return redirect(url_for("admin"))

    flash("Книга опубликована.", "success")
    return redirect(url_for("admin"))


@app.post("/admin/books/<book_id>/delete")
@admin_required
def delete_book(book_id):
    try:
        books = load_books()
        old_count = len(books)
        books = [book for book in books if str(book.get("id")) != str(book_id)]

        if len(books) == old_count:
            abort(404)

        save_books_to_github(books)
    except GitHubStorageError:
        app.logger.exception("Ошибка удаления книги")
        flash("Не удалось удалить книгу.", "error")
        return redirect(url_for("admin"))

    flash("Книга удалена.", "success")
    return redirect(url_for("admin"))


@app.get("/books/<book_id>/download")
def download_book(book_id):
    for book in get_books_or_503():
        if str(book.get("id")) == str(book_id):
            book_url = book.get("book_url", "")
            if valid_book_url(book_url):
                return redirect(book_url)
            abort(404)
    abort(404)


@app.get("/robots.txt")
def robots_txt():
    content = (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /admin\n"
        "Disallow: /login\n"
    )
    return content, 200, {"Content-Type": "text/plain; charset=utf-8"}


@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.errorhandler(503)
def service_unavailable(_error):
    return (
        "Временно не удалось получить список книг. Попробуйте обновить страницу позже.",
        503,
    )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)