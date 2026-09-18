r"""Focused offline verification tests; no .env, real SMTP, or compression work.

Run: .\.venv\Scripts\python.exe tests\test_email_verification.py
The legacy test_app.py runner has no selector; this standalone runner avoids
executing its general suite. All credentials and codes here are synthetic.
"""
import importlib
import os
from pathlib import Path
import re
import smtplib
import sqlite3
import sys
import tempfile
import types
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


class EmailVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Suppress both dotenv implementations before importing application
        # configuration. Never inspect the developer's .env or environment.
        dotenv = types.ModuleType("dotenv")
        dotenv.load_dotenv = lambda *args, **kwargs: None
        cls.bootstrap = tempfile.TemporaryDirectory(prefix="afc-email-bootstrap-")
        with patch.dict(os.environ, {
                "AFC_SECRET_KEY": "offline-test-signing-key-000000000000"}, clear=True):
            previous_dotenv = sys.modules.get("dotenv")
            sys.modules["dotenv"] = dotenv
            try:
                cls.config = importlib.import_module("config")
            finally:
                if previous_dotenv is None:
                    sys.modules.pop("dotenv", None)
                else:
                    sys.modules["dotenv"] = previous_dotenv
            cls.config.DATABASE_PATH = str(Path(cls.bootstrap.name) / "bootstrap.sqlite3")
            cls.config.RESULT_STORAGE_DIR = str(Path(cls.bootstrap.name) / "results")
            cls.appmod = importlib.import_module("app")
            cls.db = importlib.import_module("db")
            cls.auth = importlib.import_module("auth")
            cls.sender = importlib.import_module("email_sender")

    @classmethod
    def tearDownClass(cls):
        cls.bootstrap.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="afc-email-test-")
        self.addCleanup(self.tmp.cleanup)
        self.app = self.appmod.create_app(
            db_path=str(Path(self.tmp.name) / "test.sqlite3"), testing=True)
        self.app.config["CSRF_PROTECT"] = True
        self.config_patch = patch.multiple(
            self.config, EMAIL_VERIFICATION_REQUIRED=True,
            EMAIL_CODE_TTL_SECONDS=300, EMAIL_CODE_MAX_ATTEMPTS=5,
            EMAIL_RESEND_SECONDS=60, SMTP_HOST="smtp.gmail.com", SMTP_PORT=465,
            SMTP_USERNAME="synthetic-smtp-user@example.test",
            SMTP_APP_PASSWORD="synthetic-app-password", SMTP_FROM="sender@example.test")
        self.config_patch.start()
        self.addCleanup(self.config_patch.stop)
        self.smtp_patch = patch.object(self.sender.smtplib, "SMTP_SSL")
        self.smtp_factory = self.smtp_patch.start()
        self.addCleanup(self.smtp_patch.stop)
        self.smtp = self.smtp_factory.return_value.__enter__.return_value
        # Even a regression to an unmocked SMTP transport cannot send mail.
        socket_patch = patch("socket.create_connection", side_effect=AssertionError("Network forbidden"))
        socket_patch.start()
        self.addCleanup(socket_patch.stop)
        self.client = self.app.test_client()
        self.password = "synthetic-account-password"

    def post(self, path, data=None, client=None, follow_redirects=False):
        client = client or self.client
        client.get("/login")  # Issue a CSRF token without sending email.
        with client.session_transaction() as sess:
            token = sess["_csrf_token"]
        return client.post(path, data={**(data or {}), "csrf_token": token},
                           follow_redirects=follow_redirects)

    def register(self, username="pending-user", email="pending@example.test", client=None):
        return self.post("/register", {"username": username, "email": email,
                         "password": self.password, "confirm": self.password}, client=client)

    def sign_in(self, client=None, password=None):
        return self.post("/login", {"username": "pending-user",
                         "password": password or self.password}, client=client)

    def code(self):
        msg = self.smtp.send_message.call_args.args[0]
        return re.search(r"code is ([0-9]{6})", msg.get_content()).group(1)

    def user(self):
        with self.app.app_context():
            return dict(self.db.get_user_by_username("pending-user"))

    def row(self):
        with self.app.app_context():
            row = self.db.get_email_verification(self.user()["id"])
            return dict(row) if row else None

    def allow_resend(self):
        with self.app.app_context():
            conn = self.db.get_db()
            conn.execute("UPDATE email_verification_codes SET sent_at=sent_at-61")
            conn.commit()

    def assert_pending(self, client=None):
        self.assertFalse(self.user()["email_verified"])
        with (client or self.client).session_transaction() as sess:
            self.assertNotIn("user_id", sess)
            self.assertIn("pending_verification_user_id", sess)
        with self.app.app_context():
            count = self.db.get_db().execute(
                "SELECT COUNT(*) AS n FROM users WHERE username='pending-user'").fetchone()["n"]
            self.assertEqual(count, 1)

    def test_pending_creation_and_mocked_ssl_delivery(self):
        response = self.register()
        self.assertEqual(response.location, "/verify-email")
        self.assert_pending()
        self.smtp_factory.assert_called_once_with("smtp.gmail.com", 465, timeout=15)
        self.smtp.login.assert_called_once_with(self.config.SMTP_USERNAME, self.config.SMTP_APP_PASSWORD)
        self.assertEqual(self.smtp.send_message.call_count, 1)
        from werkzeug.security import check_password_hash
        self.assertNotEqual(self.row()["code_hash"], self.code())
        self.assertTrue(check_password_hash(self.row()["code_hash"], self.code()))
        page = self.client.get("/verify-email")
        self.assertIn(b"Resend verification code", page.data)
        self.assertNotIn(self.code().encode(), page.data)

    def test_pending_access_and_old_authenticated_cookie_denied(self):
        self.register()
        self.assertEqual(self.client.get("/dashboard").location.split("?")[0], "/login")
        self.assertEqual(self.client.get("/api/history").status_code, 401)
        self.assertEqual(self.client.post("/api/compress").status_code, 401)
        with self.app.app_context():
            epoch = self.db.session_epoch()
        # A pre-existing auth cookie must not bypass verification, even if the
        # deployment later disables verification for NEW registrations.
        self.config.EMAIL_VERIFICATION_REQUIRED = False
        with self.client.session_transaction() as sess:
            sess["user_id"] = self.user()["id"]
            sess["auth_epoch"] = epoch
        self.assertEqual(self.client.get("/api/history").status_code, 401)
        self.assertEqual(self.sign_in().location, "/verify-email")
        self.assert_pending()

    def test_smtp_authentication_failure_is_safe_and_retryable(self):
        raw = "provider-raw-secret-response"
        self.smtp.login.side_effect = smtplib.SMTPAuthenticationError(535, raw.encode())
        with self.assertLogs("email_sender", level="ERROR") as captured:
            with patch("secrets.randbelow", return_value=234567):
                self.assertEqual(self.register().location, "/verify-email")
        page = self.client.get("/verify-email").data.decode()
        self.assertIn("Your account is still pending", page)
        self.assertEqual(self.row()["expires_at"], 0)
        self.assert_pending()
        combined = page + " ".join(captured.output)
        for forbidden in (raw, self.config.SMTP_USERNAME, self.config.SMTP_APP_PASSWORD,
                          self.config.SMTP_FROM, self.password, "234567"):
            self.assertNotIn(forbidden, combined)
        self.assertIn("Google App Password", " ".join(captured.output))
        self.smtp.login.side_effect = None
        self.allow_resend()
        self.assertEqual(self.post("/verify-email/resend").location, "/verify-email")

    def test_smtp_timeout_and_provider_failures(self):
        for error in (TimeoutError("raw-timeout"), OSError("raw-network"),
                      smtplib.SMTPDataError(554, b"raw-provider-response")):
            with self.subTest(kind=type(error).__name__):
                self.smtp.send_message.side_effect = error
                with self.assertLogs("email_sender", level="ERROR") as captured:
                    if not self.smtp.send_message.call_count:
                        response = self.register()
                    else:
                        self.allow_resend()
                        response = self.post("/verify-email/resend")
                page = self.client.get("/verify-email") if response.status_code == 302 else response
                self.assertNotIn("raw-", page.data.decode() + " ".join(captured.output))
                self.assertEqual(self.row()["expires_at"], 0)
                self.assert_pending()

    def test_missing_smtp_configuration_names_only(self):
        self.config.SMTP_USERNAME = ""
        self.config.SMTP_APP_PASSWORD = ""
        self.config.SMTP_FROM = ""
        with self.assertLogs("email_sender", level="ERROR") as captured:
            self.register()
        self.smtp_factory.assert_not_called()
        self.assert_pending()
        output = " ".join(captured.output)
        for name in ("AFC_SMTP_USERNAME", "AFC_SMTP_APP_PASSWORD", "AFC_SMTP_FROM"):
            self.assertIn(name, output)
            self.assertNotIn(name.encode(), self.client.get("/verify-email").data)

    def test_pending_sign_in_recovers_after_failure(self):
        self.smtp_factory.side_effect = TimeoutError("synthetic-failure")
        with self.assertLogs("email_sender", level="ERROR"):
            self.register()
        other = self.app.test_client()
        self.assertEqual(self.sign_in(other, "wrong-password").status_code, 401)
        self.assertEqual(self.sign_in(other).location, "/verify-email")
        self.assert_pending(other)
        self.assertEqual(self.smtp_factory.call_count, 1)  # Login respects cooldown.
        self.smtp_factory.side_effect = None
        self.allow_resend()
        self.assertEqual(self.sign_in(other).location, "/verify-email")
        self.assertEqual(self.smtp.send_message.call_count, 1)

    def test_duplicate_pending_recovery_and_email_privacy(self):
        self.register()
        other = self.app.test_client()
        duplicate = self.register(client=other)
        self.assertEqual(duplicate.status_code, 400)
        self.assertIn(b"This account is awaiting email verification. Sign in to continue.", duplicate.data)
        with other.session_transaction() as sess:
            self.assertNotIn("pending_verification_user_id", sess)
        # Unproven username and email conflicts have identical generic copy;
        # no arbitrary email owner or verification state is disclosed.
        username_conflict = self.post("/register", {
            "username": "pending-user", "email": "other@example.test",
            "password": "wrong-password", "confirm": "wrong-password"}, client=other)
        email_conflict = self.register("another-user", client=other)
        for response in (username_conflict, email_conflict):
            self.assertIn(self.auth.REGISTRATION_UNAVAILABLE.encode(), response.data)
            self.assertNotIn(b"That email is already registered", response.data)
        self.assertEqual(self.smtp.send_message.call_count, 1)
        self.assert_pending()

    def test_database_uniqueness_race_is_safe(self):
        self.register()
        with self.app.app_context():
            uid = self.db.create_user("pending-user", "race@example.test", self.password, email_verified=False)
            self.assertIsNone(uid)
            uid = self.db.create_user("race-user", "pending@example.test", self.password, email_verified=False)
            self.assertIsNone(uid)
        # Simulate the pre-insert check losing a race without exposing SQL errors.
        with patch.object(self.auth, "validate_registration", return_value=None):
            self.assertEqual(self.register().status_code, 400)
        self.assert_pending()

    def test_resend_replaces_code_and_rejects_previous(self):
        self.register()
        old = self.code()
        self.allow_resend()
        # Even an RNG collision cannot reissue the immediately previous code.
        with patch("secrets.randbelow", return_value=int(old)):
            response = self.post("/verify-email/resend")
        self.assertEqual(response.location, "/verify-email")
        self.assertNotEqual(old, self.code())
        self.assertEqual(self.post("/verify-email", {"code": old}).status_code, 400)
        self.assertEqual(self.post("/verify-email", {"code": self.code()}).location, "/login")

    def test_resend_failure_invalidates_codes_and_remains_retryable(self):
        self.register()
        old = self.code()
        self.allow_resend()
        self.smtp.send_message.side_effect = TimeoutError("synthetic-timeout")
        with self.assertLogs("email_sender", level="ERROR"):
            response = self.post("/verify-email/resend")
        failed_code = self.code()
        self.assertEqual(response.status_code, 503)
        for code in (old, failed_code):
            self.assertEqual(self.post("/verify-email", {"code": code}).status_code, 400)
        self.assert_pending()
        self.assertEqual(self.post("/verify-email/resend").status_code, 429)
        self.smtp.send_message.side_effect = None
        self.allow_resend()
        self.assertEqual(self.post("/verify-email/resend").status_code, 302)

    def test_cooldown_shared_by_resend_login_and_other_sessions(self):
        self.register()
        original_hash = self.row()["code_hash"]
        self.assertEqual(self.post("/verify-email/resend").status_code, 429)
        self.assertEqual(self.sign_in(self.app.test_client()).location, "/verify-email")
        self.assertEqual(self.smtp.send_message.call_count, 1)
        self.assertEqual(self.row()["code_hash"], original_hash)

    def test_expired_incorrect_and_attempt_limit(self):
        self.register()
        correct = self.code()
        wrong = "%06d" % ((int(correct) + 1) % 1000000)
        for _ in range(self.config.EMAIL_CODE_MAX_ATTEMPTS):
            self.assertEqual(self.post("/verify-email", {"code": wrong}).status_code, 400)
        self.assertEqual(self.post("/verify-email", {"code": correct}).status_code, 429)
        self.allow_resend()
        self.post("/verify-email/resend")
        self.assertEqual(self.row()["attempt_count"], 0)
        expires = self.row()["expires_at"]
        with patch.object(self.auth, "time", types.SimpleNamespace(time=lambda: expires)):
            response = self.post("/verify-email", {"code": self.code()})
        self.assertEqual(response.status_code, 400)
        self.assertIn(b"expired", response.data)
        self.assert_pending()

    def test_duplicate_recovery_password_proof_uses_login_rate_limit(self):
        self.register()
        other = self.app.test_client()
        for _ in range(self.config.LOGIN_MAX_ATTEMPTS):
            self.post("/register", {"username": "pending-user", "email": "pending@example.test",
                      "password": "incorrect-password", "confirm": "incorrect-password"}, client=other)
        with patch.object(self.auth, "check_password_hash") as password_check:
            response = self.register(client=other)
            password_check.assert_not_called()
        self.assertIn(self.auth.REGISTRATION_UNAVAILABLE.encode(), response.data)
        self.assertEqual(self.sign_in(other).status_code, 429)

    def test_pending_state_survives_schema_initialization(self):
        self.register()
        previous = self.row()
        self.db.init_db(self.config.DATABASE_PATH, seed_admin=False)
        self.db.init_db(self.config.DATABASE_PATH, seed_admin=False)
        self.assertEqual(self.row(), previous)
        self.assert_pending()

    def test_code_consumed_once_only_target_verified_and_sign_in_unchanged(self):
        self.register()
        with self.app.app_context():
            other_uid = self.db.create_user("unrelated-user", "unrelated@example.test", self.password,
                                           email_verified=False)
        code = self.code()
        response = self.post("/verify-email", {"code": code})
        self.assertEqual(response.location, "/login")
        self.assertIn(b"Email verified", self.client.get("/login").data)
        self.assertTrue(self.user()["email_verified"])
        self.assertIsNone(self.row())
        with self.client.session_transaction() as sess:
            self.assertNotIn("user_id", sess)
            self.assertNotIn("pending_verification_user_id", sess)
        with self.app.app_context():
            self.assertFalse(self.db.get_user_by_id(other_uid)["email_verified"])
            self.assertEqual(self.db.consume_email_verification(self.user()["id"], code, 0), "unavailable")
        self.assertEqual(self.post("/verify-email", {"code": code}).location, "/login")
        self.assertEqual(self.sign_in().location, "/dashboard")
        self.assertEqual(self.client.get("/dashboard").status_code, 200)
        self.assertEqual(self.smtp.send_message.call_count, 1)

    def test_anonymous_csrf_expired_session_disabled_and_reset_session(self):
        self.assertEqual(self.post("/verify-email/resend").location, "/login")
        self.smtp_factory.assert_not_called()
        self.register()
        for endpoint in ("/verify-email", "/verify-email/resend"):
            self.assertEqual(self.client.post(endpoint, data={"code": self.code()}).status_code, 400)
        with self.client.session_transaction() as sess:
            sess["pending_verification_started_at"] = 0
        self.assertEqual(self.post("/verify-email/resend").location, "/login")
        self.sign_in()
        with self.client.session_transaction() as sess:
            sess["pending_verification_epoch"] = "obsolete-installation"
        self.assertEqual(self.post("/verify-email/resend").location, "/login")
        self.sign_in()
        with self.app.app_context():
            self.db.set_user_active(self.user()["id"], False)
        self.assertEqual(self.post("/verify-email", {"code": self.code()}).location, "/login")
        self.assertEqual(self.sign_in().status_code, 403)
        self.assertEqual(self.smtp.send_message.call_count, 1)

    def test_concurrent_consumption_and_resend_reservations(self):
        self.register()
        code = self.code()
        uid = self.user()["id"]
        now = int(self.auth.time.time())
        def consume(_):
            with self.app.app_context():
                return self.db.consume_email_verification(uid, code, now)
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(list(pool.map(consume, range(2))), ["verified", "unavailable"])
        with self.app.app_context():
            uid = self.db.create_user("concurrent-pending", "concurrent@example.test", self.password,
                                      email_verified=False)
        def reserve(_):
            with self.app.app_context():
                return self.db.reserve_email_verification(uid, now)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(reserve, range(2)))
        self.assertEqual(sum(bool(r.get("code")) for r in results), 1)
        self.assertEqual(sum(bool(r["retry_after"]) for r in results), 1)

    def test_existing_sqlite_migration_and_postgres_schema_alignment(self):
        path = str(Path(self.tmp.name) / "legacy.sqlite3")
        ddl = (ROOT / "schema.sql").read_text(encoding="utf-8")
        ddl = re.sub(r"^\s*email_verified\s+INTEGER[^\n]*\n", "", ddl, flags=re.M)
        ddl = re.sub(r"CREATE TABLE IF NOT EXISTS email_verification_codes \(.*?\);", "", ddl, flags=re.S)
        with closing(sqlite3.connect(path)) as conn:
            conn.executescript(ddl)
            conn.execute("INSERT INTO users (username,email,password_hash) VALUES ('legacy','legacy@example.test','synthetic-hash')")
            conn.commit()
        self.db.init_db(path, seed_admin=False)
        self.db.init_db(path, seed_admin=False)
        with closing(sqlite3.connect(path)) as conn:
            self.assertEqual(conn.execute("SELECT email_verified FROM users").fetchone()[0], 1)
            columns = {r[1]: r for r in conn.execute("PRAGMA table_info(email_verification_codes)")}
            self.assertEqual(set(columns), {"user_id", "code_hash", "expires_at", "attempt_count", "sent_at"})
            self.assertEqual(columns["attempt_count"][4], "0")
            fk = conn.execute("PRAGMA foreign_key_list(email_verification_codes)").fetchone()
            self.assertEqual((fk[2], fk[3], fk[4], fk[6]), ("users", "user_id", "id", "CASCADE"))
        pg = (ROOT / "schema_pg.sql").read_text(encoding="utf-8")
        table = re.search(r"CREATE TABLE IF NOT EXISTS email_verification_codes \((.*?)\);", pg, re.S).group(1)
        pg_columns = {line.strip().split()[0] for line in table.splitlines() if line.strip()}
        self.assertEqual(pg_columns, set(columns))
        self.assertIn("PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE", table)
        self.assertIn("attempt_count INTEGER NOT NULL DEFAULT 0", table)
        self.assertIn("ALTER TABLE users ADD COLUMN IF NOT EXISTS email_verified BOOLEAN NOT NULL DEFAULT TRUE", pg)
        self.assertIn("ALTER TABLE email_verification_codes ENABLE ROW LEVEL SECURITY", pg)
        self.assertIn("username             TEXT        NOT NULL UNIQUE", pg)
        self.assertIn("email                TEXT        NOT NULL UNIQUE", pg)


if __name__ == "__main__":
    unittest.main(verbosity=2)
