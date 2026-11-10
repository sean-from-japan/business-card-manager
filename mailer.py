"""Send mail via SMTP when SMTP_HOST is set; otherwise save it to DATA_DIR/outbox for local use."""
import os
import smtplib
import sys
import time
from email.message import EmailMessage


def send(to: str, subject: str, body: str, data_dir: str) -> str:
    msg = EmailMessage()
    msg["To"] = to
    msg["From"] = os.environ.get("MAIL_FROM", "no-reply@localhost")
    msg["Subject"] = subject
    msg.set_content(body)

    host = os.environ.get("SMTP_HOST")
    if host:
        with smtplib.SMTP(host, int(os.environ.get("SMTP_PORT", "587")), timeout=15) as smtp:
            smtp.starttls()
            user = os.environ.get("SMTP_USER")
            if user:
                smtp.login(user, os.environ.get("SMTP_PASSWORD", ""))
            smtp.send_message(msg)
        print(f"mail sent to {to} via {host}", file=sys.stderr)
        return ""

    outbox = os.path.join(data_dir, "outbox")
    os.makedirs(outbox, exist_ok=True)
    path = os.path.join(outbox, f"{time.time_ns()}.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"To: {to}\nSubject: {subject}\n\n{body}\n")
    print(f"mail saved to {path} (SMTP_HOST not set)", file=sys.stderr)
    return path
