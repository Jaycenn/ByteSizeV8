"""Small SMTP sender for registration verification; credentials stay in env."""
import smtplib
from email.message import EmailMessage

import config


def send_verification_code(address, code):
    if not config.SMTP_USERNAME or not config.SMTP_APP_PASSWORD or not config.SMTP_FROM:
        raise RuntimeError("Email verification is enabled but SMTP credentials are missing.")
    msg = EmailMessage()
    msg["Subject"] = "Verify your ByteSize email"
    msg["From"] = config.SMTP_FROM
    msg["To"] = address
    msg.set_content("Your ByteSize verification code is %s. It expires in %d minutes.\n"
                    "If you did not create this account, ignore this email."
                    % (code, max(1, config.EMAIL_CODE_TTL_SECONDS // 60)))
    with smtplib.SMTP_SSL(config.SMTP_HOST, config.SMTP_PORT, timeout=15) as smtp:
        smtp.login(config.SMTP_USERNAME, config.SMTP_APP_PASSWORD)
        smtp.send_message(msg)
