import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import urlsplit

from dashboard.app import app, init_db
from werkzeug.security import generate_password_hash


class AuthenticationFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_config = {
            key: app.config[key]
            for key in ("DATABASE_PATH", "SECRET_KEY", "TESTING")
        }
        app.config.update(
            DATABASE_PATH=str(Path(self.temp_dir.name) / "users.sqlite3"),
            SECRET_KEY="test-only-secret",
            TESTING=True,
        )
        init_db()
        self.client = app.test_client()

    def tearDown(self):
        app.config.update(self.original_config)
        self.temp_dir.cleanup()

    def csrf_token(self):
        with self.client.session_transaction() as session:
            return session["csrf_token"]

    def signup(self):
        self.client.get("/signup")
        return self.client.post(
            "/signup",
            data={
                "csrf_token": self.csrf_token(),
                "email": "analyst@example.com",
                "password": "a-long-test-password",
            },
        )

    def test_dashboard_requires_login_and_signup_opens_it(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertIn("/login", response.location)

        response = self.signup()
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/dashboard")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)

    def test_login_rejects_bad_password_and_accepts_correct_password(self):
        self.signup()
        self.client.post("/logout", data={"csrf_token": self.csrf_token()})
        self.client.get("/login")

        invalid_response = self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token(),
                "email": "analyst@example.com",
                "password": "wrong-password",
            },
        )
        self.assertEqual(invalid_response.status_code, 200)
        self.assertIn(b"Invalid email or password.", invalid_response.data)

        valid_response = self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token(),
                "email": "analyst@example.com",
                "password": "a-long-test-password",
            },
        )
        self.assertEqual(valid_response.status_code, 302)
        self.assertEqual(valid_response.location, "/dashboard")

    def test_signup_rejects_weak_password_and_logout_requires_csrf(self):
        self.client.get("/signup")
        response = self.client.post(
            "/signup",
            data={
                "csrf_token": self.csrf_token(),
                "email": "analyst@example.com",
                "password": "short",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Use a password between 12 and 128 characters.", response.data)
        self.assertEqual(self.client.post("/logout").status_code, 400)

    def test_auth_page_uses_social_icons_and_no_instagram_warning(self):
        response = self.client.get("/login")
        page = response.data

        self.assertIn(b'fa-brands fa-google', page)
        self.assertIn(b'fa-brands fa-linkedin-in', page)
        self.assertIn(b'Continue with Google', page)
        self.assertIn(b'Continue with LinkedIn', page)
        self.assertEqual(page.count(b'class="social-button"'), 2)
        self.assertIn(b'name="email"', page)
        self.assertIn(b'name="password"', page)
        self.assertIn(b'data-password-toggle="password"', page)
        self.assertIn(b'class="eye-slash"', page)
        self.assertIn(b'/static/js/auth.js', page)
        self.assertLess(page.index(b'name="password"'), page.index(b'Continue with Google'))
        self.assertNotIn(b'Instagram opens its sign-in page', page)
        self.assertNotIn(b'or use email', page)

        signup_page = self.client.get("/signup").data
        self.assertIn(b'Continue with Google', signup_page)
        self.assertIn(b'Continue with LinkedIn', signup_page)
        self.assertIn(b'name="email"', signup_page)
        self.assertIn(b'name="password"', signup_page)

    def test_password_reset_link_changes_password_and_is_single_use(self):
        with sqlite3.connect(app.config["DATABASE_PATH"]) as database:
            database.execute(
                "INSERT INTO users (email, password_hash) VALUES (?, ?)",
                ("analyst@example.com", generate_password_hash("old-test-password")),
            )

        self.client.get("/forgot-password")
        with patch("dashboard.app.send_password_reset_email") as send_reset_email:
            response = self.client.post(
                "/forgot-password",
                data={
                    "csrf_token": self.csrf_token(),
                    "email": "analyst@example.com",
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"If an account exists for that email", response.data)
        send_reset_email.assert_called_once()

        reset_path = urlsplit(send_reset_email.call_args.args[1]).path
        reset_page = self.client.get(reset_path)
        self.assertEqual(reset_page.status_code, 200)
        self.assertIn(b'name="password_confirmation"', reset_page.data)
        response = self.client.post(
            reset_path,
            data={
                "csrf_token": self.csrf_token(),
                "password": "new-test-password",
                "password_confirmation": "new-test-password",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.location, "/login")

        reused_link = self.client.get(reset_path)
        self.assertIn(b"This password reset link is invalid or has expired.", reused_link.data)

        self.client.get("/login")
        login_response = self.client.post(
            "/login",
            data={
                "csrf_token": self.csrf_token(),
                "email": "analyst@example.com",
                "password": "new-test-password",
            },
        )
        self.assertEqual(login_response.status_code, 302)
        self.assertEqual(login_response.location, "/dashboard")

    def test_password_reset_request_does_not_reveal_unknown_email(self):
        self.client.get("/forgot-password")
        response = self.client.post(
            "/forgot-password",
            data={
                "csrf_token": self.csrf_token(),
                "email": "unknown@example.com",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"If an account exists for that email", response.data)


if __name__ == "__main__":
    unittest.main()
