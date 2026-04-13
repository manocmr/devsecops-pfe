import argparse
import json
import os
import smtplib
import ssl
import sys
import urllib.request
from email.message import EmailMessage


def _env(name: str) -> str:
    v = os.getenv(name)
    return (v or "").strip()


def send_slack(webhook_url: str, text: str, timeout_s: int = 10) -> None:
    payload = json.dumps({"text": text}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        if resp.status < 200 or resp.status >= 300:
            raise RuntimeError(f"Slack webhook HTTP {resp.status}")


def send_email_smtp(
    smtp_host: str,
    smtp_port: int,
    smtp_user: str,
    smtp_pass: str,
    mail_from: str,
    mail_to: str,
    subject: str,
    body: str,
    timeout_s: int = 10,
) -> None:
    msg = EmailMessage()
    msg["From"] = mail_from
    msg["To"] = mail_to
    msg["Subject"] = subject
    msg.set_content(body)

    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_host, smtp_port, timeout=timeout_s) as server:
        server.ehlo()
        server.starttls(context=context)
        server.ehlo()
        if smtp_user:
            server.login(smtp_user, smtp_pass)
        server.send_message(msg)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--status", choices=["success", "failure"], required=True)
    p.add_argument("--app", default=_env("APP_NAME"))
    p.add_argument("--build-number", default=_env("BUILD_NUMBER"))
    p.add_argument("--build-url", default=_env("BUILD_URL"))
    args = p.parse_args(argv)

    app = args.app or "app"
    bn = args.build_number or "?"
    url = args.build_url or ""

    if args.status == "success":
        slack_text = f"DevSecOps OK : {app} build {bn}"
    else:
        slack_text = f"Échec DevSecOps : {app} #{bn} — {url}".strip()

    slack_webhook = _env("SLACK_WEBHOOK_URL")
    if slack_webhook:
        try:
            send_slack(slack_webhook, slack_text)
            print("Slack: sent")
        except Exception as e:
            print(f"Slack: failed ({e})", file=sys.stderr)

    mail_to = _env("SECURITY_ALERT_EMAIL")
    smtp_host = _env("SMTP_HOST")
    smtp_port = int(_env("SMTP_PORT") or "587")
    smtp_user = _env("SMTP_USER")
    smtp_pass = _env("SMTP_PASS")
    mail_from = _env("SMTP_FROM") or smtp_user

    if mail_to and smtp_host and mail_from:
        subject = (
            f"[DevSecOps] Pipeline {'OK' if args.status=='success' else 'ÉCHEC'} "
            f"{app} #{bn}"
        )
        body = (
            f"Statut: {args.status}\n"
            f"App: {app}\n"
            f"Build: {bn}\n"
            f"URL: {url}\n"
        )
        try:
            send_email_smtp(
                smtp_host=smtp_host,
                smtp_port=smtp_port,
                smtp_user=smtp_user,
                smtp_pass=smtp_pass,
                mail_from=mail_from,
                mail_to=mail_to,
                subject=subject,
                body=body,
            )
            print("Email: sent")
        except Exception as e:
            print(f"Email: failed ({e})", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
