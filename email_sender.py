"""Small SMTP sender for registration verification; credentials stay in env."""
import smtplib
import logging
from email.message import EmailMessage

import config

logger = logging.getLogger(__name__)


class EmailDeliveryError(RuntimeError):
    """Safe delivery failure; provider details must never leave this module."""


def send_verification_code(address, code):
    missing = [name for name in ("SMTP_HOST", "SMTP_USERNAME", "SMTP_APP_PASSWORD", "SMTP_FROM")
               if not getattr(config, name)]
    if missing:
        logger.error("Verification delivery unavailable: configure %s and restart the app.",
                     ", ".join("AFC_" + name for name in missing))
        raise EmailDeliveryError("Verification delivery unavailable.")
    if not 1 <= config.SMTP_PORT <= 65535:
        logger.error("Verification delivery unavailable: configure a valid AFC_SMTP_PORT.")
        raise EmailDeliveryError("Verification delivery unavailable.")
    try:
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
    except smtplib.SMTPAuthenticationError:
        logger.error("Verification delivery authentication failed. Check the SMTP configuration; "
                     "Gmail requires 2-Step Verification and a Google App Password.")
        raise EmailDeliveryError("Verification delivery unavailable.") from None
    except (smtplib.SMTPException, OSError, ValueError, UnicodeError):
        logger.error("Verification delivery failed. Check SMTP host, port, sender and network "
                     "connectivity, then retry after the cooldown.")
        raise EmailDeliveryError("Verification delivery unavailable.") from None
