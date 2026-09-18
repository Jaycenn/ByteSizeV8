# Registration email verification

Enable verification after configuring SMTP. The application uses Gmail's
`smtp.gmail.com:465` through `SMTP_SSL`, with a 15-second connection timeout.

In your private `.env`, supply these settings yourself. These are placeholders;
do not commit populated values or share the App Password in logs or screenshots.

```dotenv
AFC_EMAIL_VERIFICATION=1
AFC_SMTP_HOST=smtp.gmail.com
AFC_SMTP_PORT=465
AFC_SMTP_USERNAME=
AFC_SMTP_APP_PASSWORD=
AFC_SMTP_FROM=
```

1. Turn on Google 2-Step Verification for the sending account.
2. Create a Google App Password at <https://myaccount.google.com/apppasswords>.
   Google documents the prerequisites and account restrictions at
   <https://support.google.com/accounts/answer/185833?hl=en>.
3. Set `AFC_SMTP_USERNAME` to that Gmail address and `AFC_SMTP_APP_PASSWORD`
   to the generated App Password, instead of your ordinary Gmail password.
   Set `AFC_SMTP_FROM` to the same address, or an authorized sender alias.
4. Restart the application. Existing process environment variables override
   `.env`; update any deployment environment settings as well. For Azure,
   store private values as secret-backed environment variables.

## Recovery and security

Registration with verification enabled creates a pending account and sends
the browser to `/verify-email`, including when delivery fails. It never creates
a workspace session. Signing in with the pending account's correct password
returns to verification. Use **Resend verification code** after the cooldown;
there is no need to register again.

Duplicate registration gives an explicit pending-account message only after
password proof, subject to the existing login rate limit. Other uniqueness
conflicts share generic recovery text, without identifying email ownership or
verification state. Username and email uniqueness still apply in the database,
including concurrent registrations.

The default code lifetime is five minutes, with five incorrect attempts per
code. Each delivery attempt, successful or failed, starts a shared per-account
cooldown of at least 60 seconds. Re-login does not reset it. Resend replaces the
previous code; failed delivery expires the replacement but retains the cooldown.
Codes remain password-hashed, and Werkzeug verifies their hashes using a
constant-time digest comparison. Checking and consuming a code are serialized
with replacement, so a successful code is usable once, even across workers.

Verification and resend require a CSRF token and a signed pending session bound
to the installation's session epoch. That session expires after the configured
session lifetime. Expired or older pending sessions can recover by signing in.
Disabled users cannot verify or resend. Pending accounts cannot authenticate,
even if verification is subsequently disabled for new registrations. Verified
users retain the existing login flow.

Browser errors contain retry instructions. Server diagnostics name missing
configuration keys or a fixed failure category; they do not print SMTP values,
codes, or provider exception text. A delivery failure does not establish whether
the local deployment has missing values, invalid credentials, or a network issue;
use the safe diagnostic category to guide the manual check.

## Database compatibility

No new columns or destructive migration are required. Both schemas already
have `users.email_verified` and `email_verification_codes` with `code_hash`,
`expires_at`, `attempt_count`, and `sent_at`. The schema comments now specify
that `sent_at` is the last delivery attempt, including failed delivery.

SQLite's existing startup migration adds missing verification objects and
defaults legacy users to verified; it preserves existing pending accounts and
codes. PostgreSQL uses the existing out-of-band, idempotent `schema_pg.sql`
setup, including `ADD COLUMN IF NOT EXISTS email_verified ... DEFAULT TRUE`.
If an older PostgreSQL installation lacks those objects, apply `schema_pg.sql`
through the Supabase SQL Editor before starting the updated application. A
database already using this branch's verification schema needs no SQL update.
Verification writes use SQLite write transactions or PostgreSQL per-user
transaction advisory locks. No live PostgreSQL migration was run by this change.

## Focused checks

From the repository root in PowerShell:

```powershell
.\.venv\Scripts\python.exe tests\test_email_verification.py
git check-ignore .env
git status --short
```

The standalone test runner disables `.env` loading, substitutes synthetic
configuration, creates temporary SQLite databases, mocks SMTP, and blocks
socket connections. It runs no compression operations. The legacy custom
`tests/test_app.py` runner has no focused selector and was not run. PostgreSQL
coverage checks schema alignment; it does not connect to a live PostgreSQL server.

To start the application for your own Gmail and browser checks:

```powershell
.\.venv\Scripts\python.exe app.py
```

Open the local address printed at startup. Perform these checks yourself:

1. Register with an inbox you control. Confirm that verification appears, the
   email arrives, and `/dashboard` and `/api/history` remain inaccessible.
2. Close/reopen the browser or sign in again with the pending account. Confirm
   that you return to verification. Re-registering with the same username and
   correct password should show the recovery message, without a new account.
3. Try resending immediately, then after 60 seconds. The first is limited; the
   second sends a new code. Confirm the old code fails, a wrong code fails, and
   an unused code fails after five minutes.
4. Enter the newest valid code. Confirm the app asks you to sign in, that sign-in
   opens the dashboard, and that the used code cannot be submitted again.
5. In a local test configuration, temporarily leave the App Password blank and
   restart. Register a different test nickname and confirm delivery fails safely,
   the account remains pending, and retry controls remain visible. Restore the
   App Password yourself, restart, wait for the cooldown, sign in, and resend.
6. Confirm an existing verified account still signs in normally. Inspect browser
   responses and application diagnostics for safe wording, with no credentials,
   verification codes, or raw SMTP exceptions.

The complete suite, compilation, JavaScript checks, `git diff --check`, guest
compression/file-picker/drag-and-drop checks, real Gmail, Azure deployment, and
final browser checks are intentionally left to the user. They were not run here.

If you want to perform the broader repository checks you reserved for yourself,
these commands are separate from the focused verification run above:

```powershell
.\.venv\Scripts\python.exe -m py_compile app.py auth.py email_sender.py config.py db.py tests\test_app.py tests\test_email_verification.py
node --check static/js/compress.js
node --check static/js/queue.js
git diff --check
.\.venv\Scripts\python.exe tests\test_app.py
```

Perform your guest-compression, file-picker, and drag-and-drop browser checks
afterward. Azure checks should use your existing deployment procedure and
configured target; this change does not deploy or supply a new deployment command.
