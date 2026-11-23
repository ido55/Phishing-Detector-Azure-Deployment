"""Minimal web UI for the phishing detector: upload or paste an email, see the verdict, browse the scan history.

Local:  python app.py                      (SQLite in ./instance/history.db)
AWS:    gunicorn app:app                   (PostgreSQL on RDS, credentials from Secrets Manager)
Azure:  gunicorn app:app                   (PostgreSQL Flexible Server, DATABASE_URL from Key Vault)
"""
import json
import logging
import os
from datetime import datetime, timezone

from flask import Flask, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.engine import URL

import Phishing as detector

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
log = logging.getLogger("phishing-detector")

INSTANCE_ID = os.environ.get("INSTANCE_ID", "local")
AVAILABILITY_ZONE = os.environ.get("AVAILABILITY_ZONE", "")


def database_url():
    """DATABASE_URL wins; on AWS the RDS credentials come from Secrets Manager; otherwise local SQLite."""
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    if os.environ.get("DB_SECRET_ARN"):
        import boto3
        secret = json.loads(boto3.client("secretsmanager").get_secret_value(
            SecretId=os.environ["DB_SECRET_ARN"])["SecretString"])
        return URL.create("postgresql+psycopg2", username=secret["username"], password=secret["password"],
                          host=os.environ["DB_HOST"], port=int(os.environ.get("DB_PORT", 5432)),
                          database=os.environ["DB_NAME"], query={"sslmode": "require"})
    return "sqlite:///history.db"


app = Flask(__name__)
app.config.update(
    SQLALCHEMY_DATABASE_URI=database_url(),
    SQLALCHEMY_ENGINE_OPTIONS={"pool_pre_ping": True},  # survive RDS restarts / failovers
    MAX_CONTENT_LENGTH=5 * 1024 * 1024,
)
db = SQLAlchemy(app)


class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, index=True,
                           default=lambda: datetime.now(timezone.utc))
    filename = db.Column(db.String(255))
    sender = db.Column(db.String(320), index=True)
    subject = db.Column(db.String(500))
    score = db.Column(db.Integer, nullable=False)
    verdict = db.Column(db.String(20), nullable=False)
    findings = db.Column(db.JSON, nullable=False)
    instance_id = db.Column(db.String(64))  # which EC2 instance handled the scan


with app.app_context():
    try:
        db.create_all()
    except Exception:  # DB not reachable yet, or another instance is creating the table right now
        log.exception("Could not create database tables")
    db.engine.dispose()  # don't hand pooled connections to forked gunicorn workers


@app.context_processor
def server_info():
    return {"instance_id": INSTANCE_ID, "availability_zone": AVAILABILITY_ZONE,
            "labels": detector.VERDICT_LABELS}


def past_verdicts(sender):
    return db.session.scalars(db.select(Scan.verdict).where(Scan.sender == sender)
                              .order_by(Scan.id.desc()).limit(20)).all()


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/scan")
def scan():
    upload = request.files.get("email_file")
    if upload and upload.filename:
        raw, filename = upload.read().decode("utf-8", errors="replace"), upload.filename
    else:
        raw, filename = request.form.get("email_text", ""), "(pasted text)"
    if not raw.strip():
        return render_template("index.html", error="Upload a file or paste the email content first."), 400

    report = detector.analyze_text(raw, history=past_verdicts)
    record = Scan(filename=filename[:255], sender=report["sender"][:320], subject=report["subject"][:500],
                  score=report["score"], verdict=report["verdict"], findings=report["findings"],
                  instance_id=INSTANCE_ID)
    db.session.add(record)
    db.session.commit()
    # One line per scan, easy to search in CloudWatch Logs.
    log.info("scan_result id=%s verdict=%s score=%s indicators=%s sender=%s",
             record.id, record.verdict, record.score, len(record.findings), record.sender or "-")
    return redirect(url_for("result", scan_id=record.id))


@app.get("/scans/<int:scan_id>")
def result(scan_id):
    return render_template("result.html", scan=db.get_or_404(Scan, scan_id))


@app.get("/history")
def history():
    scans = db.session.scalars(db.select(Scan).order_by(Scan.id.desc()).limit(50)).all()
    return render_template("history.html", scans=scans)


@app.get("/health")
def health():
    # Deliberately shallow: if RDS has a problem we don't want the ALB to pull every instance out of service.
    return {"status": "ok", "instance": INSTANCE_ID, "az": AVAILABILITY_ZONE}


if __name__ == "__main__":
    app.run(debug=True)
