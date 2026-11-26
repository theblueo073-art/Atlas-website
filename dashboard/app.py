import base64
import ipaddress
import hashlib
import hmac
import json
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import time
from email.message import EmailMessage
from functools import wraps
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, urlopen

# Add ATLAS project root to Python import path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
from dotenv import load_dotenv

load_dotenv(PROJECT_ROOT / ".env")
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from flask import (
    Flask,
    abort,
    g,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
# ATLAS scanning modules
from discovery.asset_discovery import validate_target, resolve_domain
from discovery.host_discovery import discover_hosts
from scanner.port_scanner import scan_ports
from enumeration.service_enum import enumerate_services

app = Flask(__name__)

DATA_DIR = Path(os.environ.get("ATLAS_DATA_DIR", Path.home() / ".local/share/atlas"))
DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
PROFILE_UPLOAD_DIR = Path(os.environ.get("ATLAS_PROFILE_DIR", DATA_DIR / "profiles"))


def load_secret_key():
    configured_key = os.environ.get("SECRET_KEY")
    if configured_key:
        return configured_key

    key_path = DATA_DIR / "flask-secret"
    try:
        descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        return key_path.read_text(encoding="utf-8")

    key = secrets.token_hex(32)
    with os.fdopen(descriptor, "w", encoding="utf-8") as key_file:
        key_file.write(key)
    return key


app.config.update(
    SECRET_KEY=load_secret_key(),
    DATABASE_PATH=os.environ.get("ATLAS_DATABASE_PATH", str(DATA_DIR / "users.sqlite3")),
    PROFILE_UPLOAD_DIR=str(PROFILE_UPLOAD_DIR),
    MAX_CONTENT_LENGTH=3 * 1024 * 1024 + 64 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("ATLAS_COOKIE_SECURE") == "1",
)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def create_users_table(connection):
    connection.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE COLLATE NOCASE,
            password_hash TEXT,
            profile_image TEXT,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )


def init_db():
    with sqlite3.connect(app.config["DATABASE_PATH"]) as connection:
        connection.row_factory = sqlite3.Row
        users_exist = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'users'"
        ).fetchone()
        if not users_exist:
            create_users_table(connection)
        else:
            columns = {
                row["name"]: row
                for row in connection.execute("PRAGMA table_info(users)")
            }
            if columns["email"]["notnull"] or columns["password_hash"]["notnull"]:
                connection.execute("ALTER TABLE users RENAME TO users_before_social_auth")
                create_users_table(connection)
                connection.execute(
                    """
                    INSERT INTO users (id, email, password_hash, created_at)
                    SELECT id, email, password_hash, created_at
                    FROM users_before_social_auth
                    """
                )
                connection.execute("DROP TABLE users_before_social_auth")
            elif "profile_image" not in columns:
                connection.execute("ALTER TABLE users ADD COLUMN profile_image TEXT")

        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS pending_signups (
                email TEXT PRIMARY KEY COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS social_identities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                provider TEXT NOT NULL,
                subject TEXT NOT NULL,
                UNIQUE(provider, subject)
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS password_resets (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                token_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )

        # ATLAS scan history
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                results TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )


@app.teardown_appcontext
def close_db(_error=None):
    database = g.pop("db", None)
    if database is not None:
        database.close()


def csrf_is_valid():
    expected_token = session.get("csrf_token", "")
    submitted_token = request.form.get("csrf_token", "")
    return bool(expected_token and submitted_token) and secrets.compare_digest(
        expected_token, submitted_token
    )


def safe_next_url(target):
    if not target:
        return url_for("dashboard")

    parsed = urlsplit(target)
    if parsed.scheme or parsed.netloc or not parsed.path.startswith("/") or parsed.path.startswith("//"):
        return url_for("dashboard")
    if "\\" in parsed.path:
        return url_for("dashboard")
    return target


def send_verification_email(email, code):
    username = os.environ.get("ATLAS_SMTP_USERNAME")
    password = os.environ.get("ATLAS_SMTP_PASSWORD")
    if not username or not password:
        raise RuntimeError("ATLAS_SMTP_USERNAME and ATLAS_SMTP_PASSWORD must be configured.")

    sender = os.environ.get("ATLAS_MAIL_FROM", "atlassupportengine@gmail.com")
    message = EmailMessage()
    message["Subject"] = "Your ATLAS verification code"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Your ATLAS verification code is {code}. It expires in 10 minutes."
    )

    host = os.environ.get("ATLAS_SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("ATLAS_SMTP_PORT", "465"))
    with smtplib.SMTP_SSL(
        host, port, context=ssl.create_default_context(), timeout=10
    ) as smtp:
        smtp.login(username, password)
        smtp.send_message(message)


def send_password_reset_email(email, reset_url):
    username = os.environ.get("ATLAS_SMTP_USERNAME")
    password = os.environ.get("ATLAS_SMTP_PASSWORD")
    if not username or not password:
        raise RuntimeError("ATLAS_SMTP_USERNAME and ATLAS_SMTP_PASSWORD must be configured.")

    sender = os.environ.get("ATLAS_MAIL_FROM", "atlassupportengine@gmail.com")
    message = EmailMessage()
    message["Subject"] = "Reset your ATLAS password"
    message["From"] = sender
    message["To"] = email
    message.set_content(
        f"Use this link to reset your ATLAS password. It expires in 30 minutes:\n\n{reset_url}"
    )

    host = os.environ.get("ATLAS_SMTP_HOST", "smtp.gmail.com")
    port = int(os.environ.get("ATLAS_SMTP_PORT", "465"))
    with smtplib.SMTP_SSL(
        host, port, context=ssl.create_default_context(), timeout=10
    ) as smtp:
        smtp.login(username, password)
        smtp.send_message(message)


def new_verification_code():
    return f"{secrets.randbelow(1_000_000):06d}"


def hash_verification_code(code):
    key = app.config["SECRET_KEY"].encode("utf-8")
    return hmac.new(key, code.encode("ascii"), hashlib.sha256).hexdigest()


def oauth_settings(provider):
    providers = {
        "google": {
            "client_id": "GOOGLE_CLIENT_ID",
            "client_secret": "GOOGLE_CLIENT_SECRET",
            "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
            "scope": "openid email profile",
        },
        "linkedin": {
            "client_id": "LINKEDIN_CLIENT_ID",
            "client_secret": "LINKEDIN_CLIENT_SECRET",
            "authorize_url": "https://www.linkedin.com/oauth/v2/authorization",
            "token_url": "https://www.linkedin.com/oauth/v2/accessToken",
            "userinfo_url": "https://api.linkedin.com/v2/userinfo",
            "scope": "openid profile email",
        },
        "x": {
            "client_id": "X_CLIENT_ID",
            "client_secret": "X_CLIENT_SECRET",
            "authorize_url": "https://x.com/i/oauth2/authorize",
            "token_url": "https://api.x.com/2/oauth2/token",
            "userinfo_url": "https://api.x.com/2/users/me",
            "scope": "users.read",
            "pkce": True,
        },
    }
    settings = providers.get(provider)
    if settings is None:
        abort(404)
    client_id = os.environ.get(settings["client_id"])
    client_secret = os.environ.get(settings["client_secret"])
    if not client_id or (provider != "x" and not client_secret):
        return None
    return {**settings, "client_id_value": client_id, "client_secret_value": client_secret}


def oauth_redirect_uri(provider):
    public_url = os.environ.get("ATLAS_PUBLIC_URL", "").rstrip("/")
    if public_url:
        return f"{public_url}{url_for('oauth_callback', provider=provider)}"
    return request.url_root.rstrip("/") + url_for("oauth_callback", provider=provider)


def fetch_oauth_json(url, *, data=None, access_token=None, basic_auth=None):
    headers = {"Accept": "application/json"}
    if data is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if access_token:
        headers["Authorization"] = f"Bearer {access_token}"
    if basic_auth:
        encoded_credentials = base64.b64encode(
            f"{basic_auth[0]}:{basic_auth[1]}".encode("utf-8")
        ).decode("ascii")
        headers["Authorization"] = f"Basic {encoded_credentials}"
    outbound_request = Request(
        url,
        data=urlencode(data).encode("ascii") if data is not None else None,
        headers=headers,
    )
    with urlopen(outbound_request, timeout=10) as response:
        payload = json.loads(response.read())
    if not isinstance(payload, dict):
        raise ValueError("The OAuth provider returned an invalid response.")
    return payload


def login_required(view):
    @wraps(view)
    def wrapped_view(**kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return view(**kwargs)

    return wrapped_view


@app.context_processor
def inject_csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf_token"]}


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/signup", methods=["GET", "POST"])
def signup():
    next_url = safe_next_url(request.values.get("next"))
    if "user_id" in session:
        return redirect(next_url)

    error = None
    if request.method == "POST":
        if not csrf_is_valid():
            abort(400)

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email) or len(email) > 254:
            error = "Enter a valid email address."
        elif len(password) < 12 or len(password) > 128:
            error = "Use a password between 12 and 128 characters."
        else:
            database = get_db()
            existing_user = database.execute(
                "SELECT 1 FROM users WHERE email = ?", (email,)
            ).fetchone()
            if existing_user:
                error = "An account with that email already exists."
            else:
                code = new_verification_code()
                database.execute(
                    """
                    INSERT INTO pending_signups
                        (email, password_hash, otp_hash, expires_at, created_at, attempts)
                    VALUES (?, ?, ?, ?, ?, 0)
                    ON CONFLICT(email) DO UPDATE SET
                        password_hash = excluded.password_hash,
                        otp_hash = excluded.otp_hash,
                        expires_at = excluded.expires_at,
                        created_at = excluded.created_at,
                        attempts = 0
                    """,
                    (
                        email,
                        generate_password_hash(password),
                        hash_verification_code(code),
                        int(time.time()) + 600,
                        int(time.time()),
                    ),
                )
                database.commit()
                try:
                    send_verification_email(email, code)
                except (OSError, RuntimeError, smtplib.SMTPException, ValueError):
                    app.logger.exception("Could not send an ATLAS signup verification email")
                    database.execute("DELETE FROM pending_signups WHERE email = ?", (email,))
                    database.commit()
                    error = "We couldn't send a verification email. Please try again later."
                else:
                    session["pending_signup_email"] = email
                    session["signup_next"] = next_url
                    return redirect(url_for("verify_email"))

    return render_template(
        "auth.html",
        title="Create your account",
        description="Sign up to access your ATLAS security dashboard.",
        submit_label="Create account",
        alternate_prompt="Already have an account?",
        alternate_label="Log in",
        alternate_url=url_for("login", next=next_url),
        error=error,
        next_url=next_url,
    )


@app.route("/verify-email", methods=["GET", "POST"])
def verify_email():
    email = session.get("pending_signup_email")
    if not email:
        return redirect(url_for("signup"))

    error = None
    if request.method == "POST":
        if not csrf_is_valid():
            abort(400)

        code = request.form.get("code", "").strip()
        database = get_db()
        pending = database.execute(
            "SELECT * FROM pending_signups WHERE email = ?", (email,)
        ).fetchone()
        if pending is None:
            session.pop("pending_signup_email", None)
            return redirect(url_for("signup"))
        if int(time.time()) > pending["expires_at"]:
            database.execute("DELETE FROM pending_signups WHERE email = ?", (email,))
            database.commit()
            session.pop("pending_signup_email", None)
            session.pop("signup_next", None)
            error = "That verification code expired. Start signup again."
        elif pending["attempts"] >= 5:
            database.execute("DELETE FROM pending_signups WHERE email = ?", (email,))
            database.commit()
            session.pop("pending_signup_email", None)
            session.pop("signup_next", None)
            error = "Too many incorrect codes. Start signup again."
        elif not re.fullmatch(r"\d{6}", code) or not hmac.compare_digest(
            pending["otp_hash"], hash_verification_code(code)
        ):
            attempts = pending["attempts"] + 1
            database.execute(
                "UPDATE pending_signups SET attempts = ? WHERE email = ?",
                (attempts, email),
            )
            database.commit()
            error = "That code is incorrect. Please try again."
        else:
            try:
                cursor = database.execute(
                    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                    (email, pending["password_hash"]),
                )
                database.execute("DELETE FROM pending_signups WHERE email = ?", (email,))
                database.commit()
            except sqlite3.IntegrityError:
                database.rollback()
                session.pop("pending_signup_email", None)
                session.pop("signup_next", None)
                error = "An account with that email already exists."
            else:
                next_url = safe_next_url(session.get("signup_next"))
                session.clear()
                session["user_id"] = cursor.lastrowid
                session["csrf_token"] = secrets.token_urlsafe(32)
                return redirect(next_url)

    return render_template("verify.html", email=email, error=error)


@app.post("/resend-verification")
def resend_verification():
    if not csrf_is_valid():
        abort(400)
    email = session.get("pending_signup_email")
    if not email:
        return redirect(url_for("signup"))

    database = get_db()
    pending = database.execute(
        "SELECT created_at FROM pending_signups WHERE email = ?", (email,)
    ).fetchone()
    if pending is None:
        session.pop("pending_signup_email", None)
        return redirect(url_for("signup"))
    now = int(time.time())
    if now - pending["created_at"] < 60:
        return render_template(
            "verify.html",
            email=email,
            error="Please wait a minute before requesting another code.",
        )

    code = new_verification_code()
    database.execute(
        """
        UPDATE pending_signups
        SET otp_hash = ?, expires_at = ?, created_at = ?, attempts = 0
        WHERE email = ?
        """,
        (hash_verification_code(code), now + 600, now, email),
    )
    database.commit()
    try:
        send_verification_email(email, code)
    except (OSError, RuntimeError, smtplib.SMTPException, ValueError):
        app.logger.exception("Could not resend an ATLAS signup verification email")
        return render_template(
            "verify.html",
            email=email,
            error="We couldn't send a verification email. Please try again later.",
        )
    return render_template(
        "verify.html",
        email=email,
        message="A new verification code was sent.",
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    next_url = safe_next_url(request.values.get("next"))
    if "user_id" in session:
        return redirect(next_url)

    error = None
    if request.method == "POST":
        if not csrf_is_valid():
            abort(400)

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if (
            user is None
            or user["password_hash"] is None
            or not check_password_hash(user["password_hash"], password)
        ):
            error = "Invalid email or password."
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(next_url)

    return render_template(
        "auth.html",
        title="Welcome back",
        description="Log in to continue to your ATLAS dashboard.",
        submit_label="Log in",
        alternate_prompt="New to ATLAS?",
        alternate_label="Create an account",
        alternate_url=url_for("signup", next=next_url),
        error=error,
        next_url=next_url,
    )


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    message = None
    if request.method == "POST":
        if not csrf_is_valid():
            abort(400)

        message = "If an account exists for that email, we'll send a password reset link."
        email = request.form.get("email", "").strip().lower()
        user = get_db().execute(
            "SELECT id FROM users WHERE email = ?", (email,)
        ).fetchone()
        now = int(time.time())
        if user:
            database = get_db()
            previous_reset = database.execute(
                "SELECT created_at FROM password_resets WHERE user_id = ?",
                (user["id"],),
            ).fetchone()
            if previous_reset is None or now - previous_reset["created_at"] >= 60:
                token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(token.encode("ascii")).hexdigest()
                database.execute(
                    """
                    INSERT INTO password_resets (user_id, token_hash, expires_at, created_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        token_hash = excluded.token_hash,
                        expires_at = excluded.expires_at,
                        created_at = excluded.created_at
                    """,
                    (user["id"], token_hash, now + 1800, now),
                )
                database.commit()

                public_url = os.environ.get("ATLAS_PUBLIC_URL", "").rstrip("/")
                reset_path = url_for("reset_password", token=token)
                reset_url = f"{public_url}{reset_path}" if public_url else url_for(
                    "reset_password", token=token, _external=True
                )
                try:
                    send_password_reset_email(email, reset_url)
                except (OSError, RuntimeError, smtplib.SMTPException, ValueError):
                    app.logger.exception("Could not send an ATLAS password reset email")
                    database.execute(
                        "DELETE FROM password_resets WHERE user_id = ? AND token_hash = ?",
                        (user["id"], token_hash),
                    )
                    database.commit()

    return render_template("password_reset.html", mode="request", message=message)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    error = None
    reset_valid = False
    if request.method == "POST":
        if not csrf_is_valid():
            abort(400)

        database = get_db()
        database.execute("BEGIN IMMEDIATE")
        reset = database.execute(
            "SELECT user_id, expires_at FROM password_resets WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if reset is None or int(time.time()) > reset["expires_at"]:
            database.rollback()
            error = "This password reset link is invalid or has expired."
        else:
            reset_valid = True
            password = request.form.get("password", "")
            password_confirmation = request.form.get("password_confirmation", "")
            if len(password) < 12 or len(password) > 128:
                error = "Use a password between 12 and 128 characters."
            elif password != password_confirmation:
                error = "The passwords do not match."
            else:
                database.execute(
                    "UPDATE users SET password_hash = ? WHERE id = ?",
                    (generate_password_hash(password), reset["user_id"]),
                )
                database.execute(
                    "DELETE FROM password_resets WHERE user_id = ?",
                    (reset["user_id"],),
                )
                database.commit()
                return redirect(url_for("login"))
            database.rollback()
    else:
        reset = get_db().execute(
            "SELECT expires_at FROM password_resets WHERE token_hash = ?",
            (token_hash,),
        ).fetchone()
        if reset is None or int(time.time()) > reset["expires_at"]:
            error = "This password reset link is invalid or has expired."
        else:
            reset_valid = True

    return render_template(
        "password_reset.html",
        mode="reset",
        token=token,
        error=error,
        reset_valid=reset_valid,
    )


@app.get("/auth/<provider>")
def social_login(provider):
    if provider == "instagram":
        return redirect("https://www.instagram.com/accounts/login/")

    settings = oauth_settings(provider)
    if settings is None:
        return render_template(
            "auth.html",
            title="Sign-in unavailable",
            description="This sign-in provider has not been configured for ATLAS.",
            submit_label="Continue",
            alternate_prompt="",
            alternate_label="",
            alternate_url="#",
            error=f"{provider.title()} sign-in is not configured yet.",
            next_url=url_for("dashboard"),
        ), 503

    state = secrets.token_urlsafe(32)
    session[f"oauth_state_{provider}"] = state
    parameters = {
        "client_id": settings["client_id_value"],
        "redirect_uri": oauth_redirect_uri(provider),
        "response_type": "code",
        "scope": settings["scope"],
        "state": state,
    }
    if settings.get("pkce"):
        verifier = secrets.token_urlsafe(48)
        session[f"oauth_verifier_{provider}"] = verifier
        challenge = base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        ).rstrip(b"=").decode("ascii")
        parameters.update(
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    return redirect(f"{settings['authorize_url']}?{urlencode(parameters)}")


@app.get("/auth/<provider>/callback")
def oauth_callback(provider):
    settings = oauth_settings(provider)
    if settings is None:
        abort(503)
    expected_state = session.pop(f"oauth_state_{provider}", None)
    submitted_state = request.args.get("state", "")
    if not expected_state or not hmac.compare_digest(expected_state, submitted_state):
        abort(400)
    if request.args.get("error"):
        return redirect(url_for("login"))
    code = request.args.get("code", "")
    if not code:
        abort(400)

    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": oauth_redirect_uri(provider),
        "client_id": settings["client_id_value"],
    }
    if settings["client_secret_value"]:
        token_data["client_secret"] = settings["client_secret_value"]
    if settings.get("pkce"):
        verifier = session.pop(f"oauth_verifier_{provider}", None)
        if not verifier:
            abort(400)
        token_data["code_verifier"] = verifier

    try:
        token = fetch_oauth_json(
            settings["token_url"],
            data=token_data,
            basic_auth=(
                (settings["client_id_value"], settings["client_secret_value"])
                if provider == "x" and settings["client_secret_value"]
                else None
            ),
        )
        access_token = token.get("access_token")
        if not access_token:
            raise ValueError("The OAuth provider did not return an access token.")
        profile = fetch_oauth_json(
            settings["userinfo_url"],
            access_token=access_token,
        )
    except (HTTPError, URLError, TimeoutError, ValueError):
        app.logger.exception("OAuth sign-in failed for provider %s", provider)
        return render_template(
            "auth.html",
            title="Sign-in failed",
            description="We couldn't complete sign-in with this provider.",
            submit_label="Continue",
            alternate_prompt="",
            alternate_label="",
            alternate_url="#",
            error="Please try again.",
            next_url=url_for("login"),
        ), 502

    if provider == "x":
        subject = (profile.get("data") or {}).get("id")
        email = None
    else:
        subject = profile.get("sub")
        email = (
            profile.get("email")
            if profile.get("email_verified") is True
            and isinstance(profile.get("email"), str)
            else None
        )
    if not isinstance(subject, str) or not subject:
        abort(502)

    database = get_db()
    identity = database.execute(
        """
        SELECT users.id
        FROM social_identities
        JOIN users ON users.id = social_identities.user_id
        WHERE social_identities.provider = ? AND social_identities.subject = ?
        """,
        (provider, subject),
    ).fetchone()
    if identity:
        user_id = identity["id"]
    else:
        user = (
            database.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            if email
            else None
        )
        if user:
            user_id = user["id"]
        else:
            user_id = database.execute(
                "INSERT INTO users (email) VALUES (?)", (email,)
            ).lastrowid
        database.execute(
            "INSERT INTO social_identities (user_id, provider, subject) VALUES (?, ?, ?)",
            (user_id, provider, subject),
        )
        database.commit()

    session.clear()
    session["user_id"] = user_id
    session["csrf_token"] = secrets.token_urlsafe(32)
    return redirect(url_for("dashboard"))


@app.post("/logout")
def logout():
    if not csrf_is_valid():
        abort(400)
    session.clear()
    return redirect(url_for("home"))

# ==========================================
# ATLAS SCAN EXECUTION
# ==========================================

@app.post("/scan")
@login_required
def run_scan():

    # Verify CSRF protection
    if not csrf_is_valid():
        abort(400)

    target = request.form.get("target", "").strip()
    scan_type = request.form.get("scan_type", "").strip()
    authorized = request.form.get("authorized")

    # Require explicit authorization confirmation
    if authorized != "yes":
        return "You must confirm authorization before scanning.", 400

    if not target:
        return "Please enter a target.", 400

    # Supported scanning operations
    allowed_scans = {
        "asset_discovery",
        "host_discovery",
        "port_scanning",
        "service_enumeration",
    }

    if scan_type not in allowed_scans:
        return "Invalid scan type.", 400

    results = []

    try:

        # 1. ASSET DISCOVERY
        if scan_type == "asset_discovery":

            validation = validate_target(target)

            if not validation["valid"]:
                return "Invalid or unreachable target.", 400

            results = validation

            if validation["type"] == "domain":
                results["resolved_addresses"] = resolve_domain(target)

        # 2. HOST DISCOVERY
        elif scan_type == "host_discovery":

            network = ipaddress.ip_network(target, strict=False)

            if not network.is_private:
                return "Host discovery is currently restricted to private lab networks.", 400

            if network.num_addresses > 256:
                return "Network range is too large. Maximum: 256 addresses.", 400

            results = discover_hosts(str(network))

        # 3. PORT SCANNING
        elif scan_type == "port_scanning":

            address = ipaddress.ip_address(target)

            if not address.is_private:
                return "Port scanning is currently restricted to private lab IP addresses.", 400

            results = scan_ports(str(address))

        # 4. SERVICE ENUMERATION
        elif scan_type == "service_enumeration":

            address = ipaddress.ip_address(target)

            if not address.is_private:
                return "Service enumeration is currently restricted to private lab IP addresses.", 400

            results = enumerate_services(str(address))

        # Save results in the database
        database = get_db()

        database.execute(
            """
            INSERT INTO scans (
                user_id,
                target,
                scan_type,
                status,
                results
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session["user_id"],
                target,
                scan_type,
                "completed",
                json.dumps(results),
            ),
        )

        database.commit()

        return redirect(url_for("dashboard", scan="success"))

    except ValueError:
        return "Invalid target format.", 400

    except Exception:
        app.logger.exception("ATLAS scan failed")
        return "An unexpected scanning error occurred.", 500

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_db().execute(
        "SELECT id, email, profile_image FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    # Retrieve all scans belonging to the logged-in user.
    scan_rows = get_db().execute(
        """
        SELECT id, target, scan_type, status, results, created_at
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        """,
        (session["user_id"],),
    ).fetchall()

    scans = []
    assets = {}
    open_ports = set()
    detected_services = set()

    for row in scan_rows:
        scan = dict(row)

        try:
            scan["results_data"] = json.loads(scan["results"])
        except (TypeError, ValueError):
            scan["results_data"] = None

        results = scan["results_data"]
        target = scan["target"]
        scan_type = scan["scan_type"]

        # Host Discovery
        if scan_type == "host_discovery" and isinstance(results, list):
            for address in results:
                assets.setdefault(address, {
                    "target": address,
                    "ports": set(),
                    "services": set(),
                })

        # Asset Discovery
        elif scan_type == "asset_discovery" and isinstance(results, dict):
            if results.get("valid"):
                if results.get("type") == "ip_address":
                    assets.setdefault(target, {
                        "target": target,
                        "ports": set(),
                        "services": set(),
                    })

                elif results.get("type") == "domain":
                    assets.setdefault(target, {
                        "target": target,
                        "ports": set(),
                        "services": set(),
                    })

                    for address in results.get("resolved_addresses", []):
                        assets.setdefault(address, {
                            "target": address,
                            "ports": set(),
                            "services": set(),
                        })

        # Port Scanning
        elif scan_type == "port_scanning" and isinstance(results, list):
            asset = assets.setdefault(target, {
                "target": target,
                "ports": set(),
                "services": set(),
            })

            for item in results:
                if isinstance(item, dict) and item.get("port"):
                    port_key = (
                        target,
                        item.get("protocol", "tcp"),
                        str(item["port"]),
                    )

                    open_ports.add(port_key)
                    asset["ports"].add(str(item["port"]))

        # Service Enumeration
        elif scan_type == "service_enumeration" and isinstance(results, list):
            asset = assets.setdefault(target, {
                "target": target,
                "ports": set(),
                "services": set(),
            })

            for item in results:
                if not isinstance(item, dict) or not item.get("port"):
                    continue

                service_key = (
                    target,
                    item.get("protocol", "tcp"),
                    str(item["port"]),
                    item.get("service", "unknown"),
                )

                detected_services.add(service_key)
                asset["services"].add(
                    item.get("service", "unknown")
                )

                open_ports.add((
                    target,
                    item.get("protocol", "tcp"),
                    str(item["port"]),
                ))

        scans.append(scan)

    # Prepare assets for display in the dashboard.
    attack_surface_assets = []

    for asset in assets.values():
        attack_surface_assets.append({
            "target": asset["target"],
            "ports": sorted(asset["ports"]),
            "services": sorted(asset["services"]),
        })

    # Security findings remain zero until a genuine
    # vulnerability/finding detection module is implemented.
    metrics = {
        "assets": len(assets),
        "open_ports": len(open_ports),
        "services": len(detected_services),
        "findings": 0,
    }

    return render_template(
        "dashboard.html",
        user=user,
        scans=scans[:10],
        metrics=metrics,
        attack_surface_assets=attack_surface_assets,
        profile_message=request.args.get("profile"),
        profile_error=None,
    )

    scan_rows = get_db().execute(
        """
        SELECT id, target, scan_type, status, results, created_at
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 10
        """,
        (session["user_id"],),
    ).fetchall()

    scans = []

    for row in scan_rows:
        scan = dict(row)
        try:
            scan["results_data"] = json.loads(scan["results"])
        except (TypeError, ValueError):
            scan["results_data"] = None

        scans.append(scan)

@app.post("/profile")
@login_required
def update_profile():
    if not csrf_is_valid():
        abort(400)
    database = get_db()
    user = database.execute(
        "SELECT id, email, profile_image FROM users WHERE id = ?",
        (session["user_id"],),
    ).fetchone()
    if user is None:
        abort(404)

    action = request.form.get("profile_action")
    new_image = None
    if action == "photo":
        uploaded = request.files.get("photo")
        if uploaded is None or not uploaded.filename:
            profile_error = "Choose a profile photo to upload."
        else:
            image_data = uploaded.stream.read(3 * 1024 * 1024 + 1)
            signatures = {
                ".jpg": (b"\xff\xd8\xff", "image/jpeg"),
                ".jpeg": (b"\xff\xd8\xff", "image/jpeg"),
                ".png": (b"\x89PNG\r\n\x1a\n", "image/png"),
                ".gif": (b"GIF87a", "image/gif"),
                ".webp": (b"RIFF", "image/webp"),
            }
            extension = Path(uploaded.filename).suffix.lower()
            file_type = signatures.get(extension)
            valid_signature = bool(
                file_type
                and image_data.startswith(file_type[0])
                and (extension != ".webp" or image_data[8:12] == b"WEBP")
            )
            if len(image_data) > 3 * 1024 * 1024:
                profile_error = "Profile photos must be 3 MB or smaller."
            elif not valid_signature:
                profile_error = "Use a valid JPG, PNG, GIF, or WEBP image."
            else:
                upload_dir = Path(app.config["PROFILE_UPLOAD_DIR"])
                upload_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
                new_image = f"{user['id']}_{secrets.token_hex(16)}{extension}"
                image_path = upload_dir / new_image
                descriptor = os.open(
                    image_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
                )
                with os.fdopen(descriptor, "wb") as image_file:
                    image_file.write(image_data)
                profile_error = None
    elif action == "avatar":
        profile_error = None
    else:
        abort(400)

    if profile_error:
        return render_template(
            "dashboard.html",
            user=user,
            profile_message=None,
            profile_error=profile_error,
        ), 400

    database.execute(
        "UPDATE users SET profile_image = ? WHERE id = ?",
        (new_image, user["id"]),
    )
    database.commit()
    old_image = user["profile_image"]
    if old_image and old_image != new_image and Path(old_image).name == old_image:
        old_path = Path(app.config["PROFILE_UPLOAD_DIR"]) / old_image
        if old_path.is_file():
            old_path.unlink()
    return redirect(url_for("dashboard", profile="updated"))


@app.get("/profile-image")
@login_required
def profile_image():
    user = get_db().execute(
        "SELECT profile_image FROM users WHERE id = ?", (session["user_id"],)
    ).fetchone()
    if user is None or not user["profile_image"]:
        abort(404)
    filename = user["profile_image"]
    if Path(filename).name != filename:
        abort(404)
    extension = Path(filename).suffix.lower()
    mime_types = {
        ".gif": "image/gif",
        ".jpeg": "image/jpeg",
        ".jpg": "image/jpeg",
        ".png": "image/png",
        ".webp": "image/webp",
    }
    response = send_from_directory(
        app.config["PROFILE_UPLOAD_DIR"],
        filename,
        mimetype=mime_types.get(extension, "application/octet-stream"),
        max_age=3600,
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


Path(app.config["DATABASE_PATH"]).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=os.environ.get("FLASK_DEBUG") == "1",
    )

