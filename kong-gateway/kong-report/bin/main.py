#!/usr/bin/env python3
"""main.py — CSOC-SSJ Kong Gateway Daily Report orchestrator (CT 2065).

Run daily via cron 04:15 (BKK), 15 min after kong-225 ships JSON.
  1. Load access.json + errors.json from /opt/csoc-kong-report/inbox/YYYY-MM-DD/
  2. build_context() → render() (html + text + subject)
  3. Save snapshot → /opt/csoc-kong-report/reports/archive/kong-daily-YYYY-MM-DD.{html,txt,subject}
  4. Cleanup snapshots > 365 days
  5. Send email via SMTP (multipart with HTML attachment for Gmail >102KB)

ENV required:
  SMTP_PASSWORD               — Gmail App Password (shared with FW report)

CLI:
  --date YYYY-MM-DD     override window (default: yesterday)
  --config PATH         config.yaml (default: alongside this script)
  --no-email            skip SMTP send (still saves snapshot)
  --no-save             skip snapshot save
  --preview-only        skip both — just print summary
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import smtplib
import ssl
import sys
import time
from datetime import datetime, timedelta
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, make_msgid
from pathlib import Path

import yaml
from jinja2 import Environment, FileSystemLoader, select_autoescape

THAI_MONTHS = ["มกราคม", "กุมภาพันธ์", "มีนาคม", "เมษายน", "พฤษภาคม", "มิถุนายน",
               "กรกฎาคม", "สิงหาคม", "กันยายน", "ตุลาคม", "พฤศจิกายน", "ธันวาคม"]


def setup_logging(cfg: dict) -> logging.Logger:
    lcfg = cfg.get("logging", {})
    level = getattr(logging, lcfg.get("level", "INFO").upper(), logging.INFO)
    log_path = lcfg.get("path", "/var/log/csoc-kong-report/cron.log")
    Path(log_path).parent.mkdir(parents=True, exist_ok=True)
    handlers = [logging.StreamHandler(sys.stdout)]
    try:
        handlers.append(logging.FileHandler(log_path))
    except OSError:
        pass
    logging.basicConfig(level=level,
                        format="%(asctime)s %(levelname)s %(message)s",
                        handlers=handlers, force=True)
    return logging.getLogger("csoc-kong-report")


def fmt_int(v) -> str:
    try:
        return f"{int(v):,}"
    except (TypeError, ValueError):
        return str(v)


def fmt_bytes(v) -> str:
    try:
        n = float(v)
    except (TypeError, ValueError):
        return str(v)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def fmt_ts_short(ts: str) -> str:
    """ISO 2026-06-25T00:00:16+07:00 → 06-25 00:00"""
    if not ts or not isinstance(ts, str):
        return "—"
    try:
        d = datetime.fromisoformat(ts)
        return d.strftime("%m-%d %H:%M")
    except ValueError:
        return ts[:16]


def basename(path: str) -> str:
    if not path:
        return "—"
    return os.path.basename(str(path))


def thai_date(date_iso: str) -> str:
    """2026-06-25 → 25 มิถุนายน 2569 (BE)"""
    try:
        d = datetime.strptime(date_iso, "%Y-%m-%d")
        return f"{d.day} {THAI_MONTHS[d.month - 1]} {d.year + 543}"
    except ValueError:
        return date_iso


def resolve_date(args) -> str:
    if args.date:
        return args.date
    return (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")


def load_inbox(inbox_root: str, date_iso: str, log: logging.Logger) -> tuple[dict, dict]:
    p = Path(inbox_root) / date_iso
    access_path = p / "access.json"
    errors_path = p / "errors.json"
    if not access_path.exists():
        log.error("missing access.json: %s", access_path)
        sys.exit(2)
    if not errors_path.exists():
        log.error("missing errors.json: %s", errors_path)
        sys.exit(2)
    with open(access_path) as f:
        access = json.load(f)
    with open(errors_path) as f:
        errors = json.load(f)
    log.info("loaded inbox/%s — access=%d B errors=%d B",
             date_iso, access_path.stat().st_size, errors_path.stat().st_size)
    return access, errors


def render(date_iso: str, access: dict, errors: dict, cfg: dict,
           templates_dir: str) -> dict:
    env = Environment(
        loader=FileSystemLoader(templates_dir),
        autoescape=select_autoescape(["html", "j2"]),
        trim_blocks=False, lstrip_blocks=False,
    )
    env.filters["fmt_int"] = fmt_int
    env.filters["fmt_bytes"] = fmt_bytes
    env.filters["fmt_ts_short"] = fmt_ts_short
    env.filters["basename"] = basename

    ctx = {
        "date_iso": date_iso,
        "date_th": thai_date(date_iso),
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S %z").strip(),
        "access": access,
        "errors": errors,
        "org": cfg.get("org", {"name": "สนง.สาธารณสุขจังหวัดมุกดาหาร"}),
        "generator": cfg.get("generator", "csoc-kong-report main.py v1"),
    }

    html = env.get_template("kong_report.html.j2").render(**ctx)
    text = env.get_template("kong_report.txt.j2").render(**ctx)
    subj_cfg = cfg.get("email", {}).get(
        "subject_template",
        "[CSOC-SSJ] Kong Daily {date_iso} — req={req} bytes={bytes} attacks={att} errors={err}",
    )
    subject = subj_cfg.format(
        date_iso=date_iso,
        req=fmt_int(access["totals"]["parsed"]),
        bytes=fmt_bytes(access["totals"]["bytes_sent"]),
        att=fmt_int(access.get("request_param_anomaly", {}).get("total_hits", 0)),
        err=fmt_int(errors["totals"]["parsed"]),
    )
    return {"html": html, "text": text, "subject": subject}


def save_snapshot(date_iso: str, html: str, text: str, subject: str,
                  snap_dir: str, retention_days: int,
                  log: logging.Logger) -> None:
    snap = Path(snap_dir)
    snap.mkdir(parents=True, exist_ok=True)
    html_path = snap / f"kong-daily-{date_iso}.html"
    text_path = snap / f"kong-daily-{date_iso}.txt"
    subj_path = snap / f"kong-daily-{date_iso}.subject"
    html_path.write_text(html, encoding="utf-8")
    text_path.write_text(text, encoding="utf-8")
    subj_path.write_text(subject, encoding="utf-8")
    log.info("saved snapshot → %s (html=%d, text=%d B)",
             html_path, len(html), len(text))

    if retention_days > 0:
        cutoff = time.time() - retention_days * 86400
        removed = 0
        for f in snap.glob("kong-daily-*.html"):
            if f.stat().st_mtime < cutoff:
                f.unlink()
                f.with_suffix(".txt").unlink(missing_ok=True)
                f.with_suffix(".subject").unlink(missing_ok=True)
                removed += 1
        if removed:
            log.info("pruned %d old snapshot(s) > %d days", removed, retention_days)


_INBOX_DAY_RE = re.compile(r"\d{4}-\d{2}-\d{2}")


def prune_inbox(inbox_root: str, retention_days: int,
                log: logging.Logger) -> None:
    """Prune inbox/YYYY-MM-DD/ day folders older than retention_days.
    inbox JSON เป็น source ของ kong_aggregate.py (Risk Portal trend) — เก็บถาวร."""
    if retention_days <= 0:
        return
    inbox = Path(inbox_root)
    if not inbox.is_dir():
        return
    cutoff = time.time() - retention_days * 86400
    removed = 0
    for d in inbox.iterdir():
        if not d.is_dir() or not _INBOX_DAY_RE.fullmatch(d.name):
            continue
        if d.stat().st_mtime < cutoff:
            shutil.rmtree(d, ignore_errors=True)
            removed += 1
    if removed:
        log.info("pruned %d old inbox day(s) > %d days", removed, retention_days)


def send_email(html: str, text: str, subject: str, email_cfg: dict,
               date_iso: str, log: logging.Logger) -> bool:
    smtp_pass = os.environ.get(email_cfg.get("smtp_pass_env", "SMTP_PASSWORD"), "")
    if not smtp_pass:
        log.error("SMTP password env %s not set — abort send",
                  email_cfg.get("smtp_pass_env"))
        return False

    msg = MIMEMultipart("mixed")
    msg["Subject"] = subject
    msg["From"] = formataddr((email_cfg.get("from_name", "CSOC SSJ Kong"),
                              email_cfg["from_addr"]))
    msg["To"] = ", ".join(email_cfg["recipients"])
    if email_cfg.get("reply_to"):
        msg["Reply-To"] = email_cfg["reply_to"]
    msg["Message-ID"] = make_msgid(domain="csoc-ssj.local")

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(text, "plain", "utf-8"))
    alt.attach(MIMEText(html, "html", "utf-8"))
    msg.attach(alt)

    attach = MIMEApplication(html.encode("utf-8"), _subtype="html")
    attach.add_header("Content-Disposition", "attachment",
                      filename=f"kong-daily-{date_iso}.html")
    msg.attach(attach)

    host = email_cfg["smtp_host"]
    port = int(email_cfg["smtp_port"])
    user = email_cfg["smtp_user"]
    log.info("SMTP connecting %s:%d as %s", host, port, user)
    ctx = ssl.create_default_context()
    with smtplib.SMTP(host, port, timeout=60) as s:
        s.ehlo()
        if email_cfg.get("smtp_tls", True):
            s.starttls(context=ctx)
            s.ehlo()
        s.login(user, smtp_pass)
        s.send_message(msg)
    log.info("email sent: subject=%r to=%d recipients",
             subject, len(email_cfg["recipients"]))
    return True


def main():
    ap = argparse.ArgumentParser(description="CSOC-SSJ Kong Gateway Daily Report")
    ap.add_argument("--config",
                    default=str(Path(__file__).parent.parent / "config.yaml"))
    ap.add_argument("--date", help="YYYY-MM-DD (default: yesterday)")
    ap.add_argument("--no-email", action="store_true")
    ap.add_argument("--no-save", action="store_true")
    ap.add_argument("--preview-only", action="store_true",
                    help="skip save + email — just render to stdout meta")
    args = ap.parse_args()

    with open(args.config) as f:
        cfg = yaml.safe_load(f)

    log = setup_logging(cfg)
    date_iso = resolve_date(args)
    log.info("===== Kong Daily Report — window: %s =====", date_iso)

    t0 = time.time()
    inbox_root = cfg.get("inbox", {}).get("path", "/opt/csoc-kong-report/inbox")
    access, errors = load_inbox(inbox_root, date_iso, log)

    templates_dir = cfg.get("report", {}).get(
        "templates_dir", str(Path(__file__).parent.parent / "templates")
    )
    r = render(date_iso, access, errors, cfg, templates_dir)
    log.info("render done — subject=%r html=%d text=%d B",
             r["subject"], len(r["html"]), len(r["text"]))

    if args.preview_only:
        log.info("--preview-only: skip save + email")
        return

    if not args.no_save:
        rep_cfg = cfg.get("report", {})
        save_snapshot(
            date_iso, r["html"], r["text"], r["subject"],
            snap_dir=rep_cfg.get("snapshot_dir",
                                 "/opt/csoc-kong-report/reports/archive"),
            retention_days=int(rep_cfg.get("retention_days", 365)),
            log=log,
        )
        prune_inbox(
            inbox_root,
            retention_days=int(cfg.get("inbox", {}).get("retention_days", 365)),
            log=log,
        )
    else:
        log.info("--no-save: skip snapshot")

    if args.no_email:
        log.info("--no-email: skip SMTP")
        log.info("===== done in %.1fs =====", time.time() - t0)
        return

    email_cfg = cfg.get("email", {})
    if not email_cfg.get("enabled", True):
        log.info("email.enabled=false in config — skip SMTP")
        return
    try:
        send_email(r["html"], r["text"], r["subject"], email_cfg,
                   date_iso, log)
    except Exception as e:
        log.exception("SMTP send failed: %s", e)
        sys.exit(2)

    log.info("===== done in %.1fs =====", time.time() - t0)


if __name__ == "__main__":
    main()
