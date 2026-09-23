"""Background Logstash health-check + email alerting engine.

Runs in its own daemon thread (started from app.py), independent of any user
session -- unlike every other SSH connection in this app, which only exists
because a user is actively logged in and typed a password. This is the one
deliberate exception to that model (see the per-server monitor_username /
monitor_password_enc columns in db.py): a background poller needs a standing,
encrypted credential precisely because nobody may be watching when Logstash
goes down at 3am.

Everything else (SMTP settings, recipients, thresholds) is read fresh from
db.get_alert_config() / the servers table on every cycle, so changes made on
the Alerts settings page take effect on the next cycle with no restart.
"""

import html as html_lib
import logging
import re
import smtplib
import threading
import time
from datetime import datetime
from email.message import EmailMessage

import crypto_utils
import db
from ssh_manager import (
    DEFAULT_LOGSTASH_LOG_PATH,
    ES_BULK_ERROR_GREP,
    SSHManager,
    aggregate_es_bulk_errors,
    parse_es_bulk_errors,
)

logger = logging.getLogger("alerting")
logger.setLevel(logging.INFO)
if not logger.handlers:
    # gunicorn's own error-log config (see Dockerfile's --error-logfile -)
    # only captures its own logger tree, not this standalone module logger,
    # and Python's unconfigured "lastResort" handler only surfaces WARNING+.
    # Attach a plain stdout handler so INFO-level cycle activity ("checking
    # server X", "sent alert email") is actually visible in `docker logs`,
    # not just failures -- otherwise a silently-not-running checker and a
    # correctly-idle-because-healthy one look identical from the outside.
    _handler = logging.StreamHandler()
    _handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s alerting: %(message)s"))
    logger.addHandler(_handler)

LOGSTASH_API_PORT = 9600

# How many of the most recent matching log lines to grep for per cycle (see
# _check_server's Elasticsearch-bulk-rejection check below) -- bounded so a
# noisy pipeline can't make every check cycle slower, same spirit as the
# Elasticsearch Errors page's own default. Not user-configurable (unlike the
# thresholds on the Alerts page) to keep this first cut simple; revisit if a
# real deployment needs a different tail size or log path per server.
ES_ERROR_LOG_TAIL_LINES = 500

# `systemctl is-active` prints exactly one of these words (the unit's
# ActiveState). Anything other than "active" is treated as a problem and
# alerts immediately (see _check_server below) -- this dict only controls
# how that state reads in the alert email/Active Alerts panel, so
# "deactivating" shows up as a recognizable phrase ("shutting down") instead
# of a bare systemd term nobody but an admin would parse at a glance.
#
# Note on "activating"/"deactivating" specifically: these are normally
# transient, lasting seconds during a start/stop -- catching one requires a
# check to land in that exact window, so with a 5-minute check interval it's
# unlikely to ever be *observed* mid-transition. If it IS caught, that's
# already worth flagging (a stop/start taking long enough to still be
# mid-transition several minutes later is itself unusual) -- lower "Check
# interval" on the Alerts page if you need tighter odds of catching it.
SERVICE_STATE_PHRASES = {
    "inactive": "stopped",
    "failed": "crashed / failed",
    "activating": "currently starting up",
    "deactivating": "currently shutting down",
    "reloading": "reloading its config",
}


def describe_service_state(state):
    phrase = SERVICE_STATE_PHRASES.get(state)
    return f"{state} ({phrase})" if phrase else state


def _parse_recipients(value):
    if not value:
        return []
    return [p for p in re.split(r"[,;\s]+", value.strip()) if p]


def _effective_recipients(server, config, scope):
    """Per-server override always wins (applies to every scope alike, same as
    before). Otherwise 'service' scope (Logstash systemd down/recovered) uses
    its own recipient list if one's configured, so service outages can be
    routed to a different group than everything else; any other scope, or a
    blank service list, falls back to the shared default list."""
    override = _parse_recipients(server["alert_recipients_override"])
    if override:
        return override
    if scope == "service":
        service_list = _parse_recipients(config["service_recipients"])
        if service_list:
            return service_list
    return _parse_recipients(config["default_recipients"])


# Same red/green/teal already used across the dashboard's own UI (see
# style.css's --color-danger / --color-success / --color-primary) -- an
# alert email should look like it came from the same product, not a bare
# text dump.
_ALERT_KINDS = {
    "service_down":       {"badge": "Service Down",      "headline": "Logstash service is down",          "accent": "#dc2626"},
    "service_recovered":  {"badge": "Resolved",           "headline": "Logstash service is back up",        "accent": "#059669"},
    "api_down":           {"badge": "API Unresponsive",   "headline": "Monitoring API stopped responding",  "accent": "#dc2626"},
    "api_recovered":      {"badge": "Resolved",           "headline": "Monitoring API is responding again", "accent": "#059669"},
    "pipeline_issue":     {"badge": "Pipeline Issue",     "headline": "A pipeline needs attention",         "accent": "#dc2626"},
    "pipeline_recovered": {"badge": "Resolved",           "headline": "Pipeline is healthy again",          "accent": "#059669"},
    "pipeline_schedule_missed":    {"badge": "Schedule Missed", "headline": "A pipeline missed its expected run", "accent": "#dc2626"},
    "pipeline_schedule_recovered": {"badge": "Resolved",       "headline": "Pipeline is back on schedule",        "accent": "#059669"},
    "es_bulk_reject":     {"badge": "ES Rejecting Data", "headline": "Elasticsearch is rejecting pipeline data",   "accent": "#dc2626"},
    "es_bulk_reject_recovered": {"badge": "Resolved",    "headline": "Elasticsearch is accepting data again",     "accent": "#059669"},
    "manually_resolved":  {"badge": "Resolved",           "headline": "Manually marked resolved",           "accent": "#059669"},
    "reminder":           {"badge": "Still Open",         "headline": "This issue hasn't been resolved yet", "accent": "#d97706"},
    "test":               {"badge": "Test Email",         "headline": "Your SMTP settings are working",     "accent": "#0694a2"},
}

_EMAIL_FONT = "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"


def build_alert_email(kind, server_label, server_host=None, now_ts=None, detail=None, pipeline_id=None):
    """Builds (subject, text_body, html_body) for one of _ALERT_KINDS. Kept
    separate from the actual SMTP call so app.py's "Send test email" button
    can reuse the exact same look via kind="test"."""
    meta = _ALERT_KINDS[kind]
    when = datetime.fromtimestamp(now_ts).strftime("%Y-%m-%d %H:%M:%S") if now_ts else None

    rows = []
    if server_host:
        rows.append(("Server", f"{server_label} ({server_host})"))
    elif server_label:
        rows.append(("Server", server_label))
    if pipeline_id:
        rows.append(("Pipeline", pipeline_id))
    if detail:
        rows.append(("Detail", detail))
    if when:
        rows.append(("Time", when))

    subject = f"[Logstash Monitoring] {meta['badge']} — {server_label}" if server_label else f"[Logstash Monitoring] {meta['badge']}"

    text_body = meta["headline"] + "\n\n" + "\n".join(f"{label}: {value}" for label, value in rows) + "\n"

    rows_html = "".join(
        f'<tr>'
        f'<td style="padding:9px 14px 9px 0;color:#666b7a;width:92px;white-space:nowrap;vertical-align:top;'
        f'font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:0.03em;font-family:{_EMAIL_FONT};">'
        f'{html_lib.escape(label)}</td>'
        f'<td style="padding:9px 0;font-size:14px;line-height:1.5;color:#14161f;font-family:{_EMAIL_FONT};">'
        f'{html_lib.escape(str(value))}</td>'
        f'</tr>'
        for label, value in rows
    )

    html_body = f"""<!doctype html>
<html>
<body style="margin:0;padding:0;background-color:#f4f5f9;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background-color:#f4f5f9;padding:32px 12px;">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0"
             style="max-width:560px;width:100%;background-color:#ffffff;border-radius:12px;overflow:hidden;
                    box-shadow:0 2px 10px rgba(20,22,35,0.08);border-collapse:separate;">
        <tr>
          <td style="background-color:{meta['accent']};padding:22px 28px;">
            <div style="color:rgba(255,255,255,0.85);font-size:12px;font-weight:700;letter-spacing:0.08em;
                        text-transform:uppercase;font-family:{_EMAIL_FONT};">{html_lib.escape(meta['badge'])}</div>
            <div style="color:#ffffff;font-size:19px;font-weight:700;padding-top:6px;line-height:1.35;
                        font-family:{_EMAIL_FONT};">{html_lib.escape(meta['headline'])}</div>
          </td>
        </tr>
        <tr>
          <td style="padding:22px 28px 6px;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse;">
              {rows_html}
            </table>
          </td>
        </tr>
        <tr>
          <td style="padding:16px 28px;background-color:#f7f8fc;border-top:1px solid #e3e5ee;">
            <span style="font-size:12px;font-weight:700;color:#0694a2;font-family:{_EMAIL_FONT};">Logstash Monitoring</span>
            <span style="font-size:12px;color:#9498a5;font-family:{_EMAIL_FONT};"> &middot; automated alert, no reply needed</span>
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""

    return subject, text_body, html_body


def send_email(config, recipients, subject, body, html_body=None):
    """Does the actual SMTP send, raising on any failure (bad host, auth
    rejected, decrypt failure, etc.) instead of swallowing it -- so the
    Alerts page's "Send test email" button can show the *real* error instead
    of a generic "didn't arrive". _send() below is the background checker's
    wrapper that logs-and-swallows instead, since a background cycle can't
    show anything to anyone."""
    if not recipients:
        raise RuntimeError("No recipients given.")
    if not config["smtp_host"]:
        raise RuntimeError("SMTP host is not configured on the Alerts page yet.")

    password = crypto_utils.decrypt(config["smtp_password_enc"]) if config["smtp_password_enc"] else None

    from_name = config["from_name"] or "Logstash Monitoring"
    from_addr = config["from_address"] or config["smtp_username"] or ""

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = f"{from_name} <{from_addr}>" if from_addr else from_name
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    if html_body:
        msg.add_alternative(html_body, subtype="html")

    with smtplib.SMTP(config["smtp_host"], config["smtp_port"] or 587, timeout=15) as smtp:
        if config["smtp_use_tls"]:
            smtp.starttls()
        if config["smtp_username"] and password:
            smtp.login(config["smtp_username"], password)
        smtp.send_message(msg)


def _send(config, recipients, subject, body, html_body=None):
    """Returns (ok, error) -- callers use this to record whether the
    notification actually went out (see db.record_alert_email_result), so
    the Active Alerts panel can show "email failed" instead of a plain
    "OPEN" that looks identical whether or not anyone was actually told."""
    if not recipients:
        logger.warning("No alert recipients configured -- dropping email: %s", subject)
        return False, "No recipients configured"
    try:
        send_email(config, recipients, subject, body, html_body)
        logger.info("Sent alert email %r to %s", subject, recipients)
        return True, None
    except Exception as exc:
        logger.exception("Failed to send alert email: %s", subject)
        return False, str(exc)


def _notify_opened(server_id, scope, pipeline_id, config, recipients, subject, body, html_body=None):
    """Sends the "problem just opened" email and records whether it actually
    went out on that same alert_state row -- this is what lets the Active
    Alerts panel distinguish "OPEN, someone was emailed" from "OPEN, but the
    email itself failed" instead of showing an identical badge either way."""
    ok, err = _send(config, recipients, subject, body, html_body)
    db.record_alert_email_result(server_id, scope, pipeline_id, ok, err)


def _evaluate(server_id, scope, pipeline_id, is_problem, detail, required, now_ts):
    """Shared state-machine step for all three alert scopes (service/api/pipeline).
    Returns ("opened", detail), ("resolved", detail), or (None, None)."""
    existing = db.get_alert_state(server_id, scope, pipeline_id)
    if is_problem:
        count = db.touch_alert_candidate(server_id, scope, pipeline_id, detail, now_ts)
        already_open = existing is not None and existing["status"] == "open"
        if not already_open and count >= required:
            db.mark_alert_open(server_id, scope, pipeline_id, now_ts)
            return "opened", detail
        return None, None

    if existing is not None:
        resolved = db.resolve_alert_state(server_id, scope, pipeline_id, now_ts)
        if resolved and resolved["status"] == "open":
            return "resolved", resolved["detail"]
    return None, None


def _check_server(server, config, now_ts):
    label = server["label"] or server["host"]
    service_name = server["service_name_override"] or config["default_service_name"] or "logstash.service"
    # 'service' scope gets its own recipient list (falls back to the shared default
    # if unset); api/pipeline/pipeline_schedule all share the one "everything else"
    # list -- none of them has a dedicated config field, so one lookup covers all
    # three (per-server override, if any, already wins inside _effective_recipients
    # regardless of which of these two variables ends up using it).
    service_recipients = _effective_recipients(server, config, "service")
    other_recipients = _effective_recipients(server, config, "api")

    try:
        password = crypto_utils.decrypt(server["monitor_password_enc"])
    except RuntimeError:
        logger.exception("Cannot decrypt monitoring credential for %s -- skipping this cycle", label)
        return

    manager = SSHManager(server["host"], server["port"], server["monitor_username"], password=password)
    try:
        # ---- 1. Is the Logstash service itself up? ----
        service_problem = None
        try:
            status = manager.service_status(service_name)
            if status != "active":
                service_problem = f"{service_name} is {describe_service_state(status)}"
        except Exception as exc:
            service_problem = f"Could not reach {label} over SSH to check service status: {exc}"

        signal, detail = _evaluate(server["id"], "service", None, service_problem is not None, service_problem, 1, now_ts)
        if signal == "opened":
            subject, text_body, html_body = build_alert_email(
                "service_down", label, server["host"], now_ts, detail=detail
            )
            _notify_opened(server["id"], "service", None, config, service_recipients, subject, text_body, html_body)
        elif signal == "resolved":
            subject, text_body, html_body = build_alert_email(
                "service_recovered", label, server["host"], now_ts, detail=f"{service_name} is active again."
            )
            _send(config, service_recipients, subject, text_body, html_body)

        if service_problem:
            return  # Suppress API + per-pipeline checks -- same root cause.

        # ---- 2. Is the Monitoring API responding? (JVM-hung sentinel) ----
        stats = None
        api_problem = None
        try:
            stats = manager.logstash_stats(LOGSTASH_API_PORT)
        except Exception as exc:
            api_problem = str(exc)

        signal, detail = _evaluate(server["id"], "api", None, api_problem is not None, api_problem, 1, now_ts)
        if signal == "opened":
            subject, text_body, html_body = build_alert_email(
                "api_down", label, server["host"], now_ts,
                detail=f"Logstash's systemd unit is active, but its Monitoring API did not respond "
                       f"(possible hung JVM). {detail}",
            )
            _notify_opened(server["id"], "api", None, config, other_recipients, subject, text_body, html_body)
        elif signal == "resolved":
            subject, text_body, html_body = build_alert_email("api_recovered", label, server["host"], now_ts)
            _send(config, other_recipients, subject, text_body, html_body)

        if api_problem or stats is None:
            return  # Suppress per-pipeline checks -- can't read pipeline data anyway.

        # ---- 3. Per-pipeline: failed to start, reload failures, event backlog ----
        pipelines = stats.get("pipelines") or {}
        threshold = config["event_gap_threshold"] or 100
        required_checks = config["consecutive_checks_required"] or 2

        for pipeline_id, p in pipelines.items():
            workers = p.get("workers") or 0
            reload_failures = p.get("reload_failures") or 0
            events_in = p.get("events_in") or 0
            events_out = p.get("events_out") or 0
            gap = max(0, events_in - events_out)

            reason = None
            required = 1
            detail = None
            if workers <= 0:
                reason, detail = "failed to start/create", f"workers={workers}"
            elif reload_failures > 0:
                reason, detail = "config reload failure", f"reload_failures={reload_failures}"
            elif gap > threshold:
                reason, required = "events backing up", required_checks
                detail = f"in={events_in} out={events_out} gap={gap} (threshold {threshold})"

            signal, sent_detail = _evaluate(
                server["id"], "pipeline", pipeline_id, reason is not None,
                f"{reason}: {detail}" if reason else None, required, now_ts,
            )
            if signal == "opened":
                subject, text_body, html_body = build_alert_email(
                    "pipeline_issue", label, server["host"], now_ts, detail=sent_detail, pipeline_id=pipeline_id
                )
                _notify_opened(server["id"], "pipeline", pipeline_id, config, other_recipients, subject, text_body, html_body)
            elif signal == "resolved":
                subject, text_body, html_body = build_alert_email(
                    "pipeline_recovered", label, server["host"], now_ts, pipeline_id=pipeline_id
                )
                _send(config, other_recipients, subject, text_body, html_body)

        # A pipeline that vanished from this fetch entirely (renamed/removed) --
        # auto-resolve rather than let its alert linger forever.
        for stale_id in db.list_stale_pipeline_alerts(server["id"], set(pipelines.keys())):
            resolved = db.resolve_alert_state(server["id"], "pipeline", stale_id, now_ts)
            if resolved and resolved["status"] == "open":
                subject, text_body, html_body = build_alert_email(
                    "pipeline_recovered", label, server["host"], now_ts,
                    detail="No longer reporting an issue (pipeline may have been renamed/removed).",
                    pipeline_id=stale_id,
                )
                _send(config, other_recipients, subject, text_body, html_body)
            # A schedule alert on a pipeline that's stopped reporting entirely
            # is resolved the same way -- but unlike the alert, the underlying
            # pipeline_schedule *config* row (the admin's expected_value) is
            # deliberately left alone here, in case this is a transient blip in
            # one fetch rather than the pipeline actually being gone for good.
            # (Settings -> Alerts -> Pipeline Schedules has its own "Remove"
            # action for genuinely retiring a pipeline's config.)
            resolved_sched = db.resolve_alert_state(server["id"], "pipeline_schedule", stale_id, now_ts)
            if resolved_sched and resolved_sched["status"] == "open":
                subject, text_body, html_body = build_alert_email(
                    "pipeline_schedule_recovered", label, server["host"], now_ts,
                    detail="No longer reporting an issue (pipeline may have been renamed/removed).",
                    pipeline_id=stale_id,
                )
                _send(config, other_recipients, subject, text_body, html_body)

        # ---- 3b. Per-pipeline: Elasticsearch rejecting bulk requests (e.g. 413) ----
        # Read-only: greps Logstash's own log file (never writes to it) for
        # output-side bulk-request rejections that step 3 above can't see --
        # a rejected bulk request gets retried with exponential backoff, so
        # events_in/out and reload_failures all stay clean while this is
        # actively happening. See ssh_manager.ES_BULK_ERROR_GREP / the
        # dashboard's own Elasticsearch Errors page, which reads the exact
        # same way over the user's live SSH connection instead of this
        # background one.
        #
        # Unlike reload_failures (a cumulative counter that only a Logstash
        # restart resets), this re-evaluates fresh each cycle from only the
        # last ES_ERROR_LOG_TAIL_LINES matching lines -- so once a pipeline
        # stops actually hitting the error, it ages out of that tail on its
        # own within a few cycles instead of needing a manual Resolve. The
        # trade-off: a pipeline that goes fully silent (no new log lines at
        # all) can still show old matches until they scroll out of that tail
        # window, same as a human tailing the file by hand would see.
        try:
            es_error_log = manager.read_log_file(
                DEFAULT_LOGSTASH_LOG_PATH, lines=ES_ERROR_LOG_TAIL_LINES, grep=ES_BULK_ERROR_GREP
            )
            es_error_groups = aggregate_es_bulk_errors(parse_es_bulk_errors(es_error_log))
        except Exception:
            es_error_groups = []  # log missing/unreadable -- skip this optional check, not the whole cycle

        es_errors_by_pipeline = {}
        for g in es_error_groups:
            es_errors_by_pipeline.setdefault(g["pipeline_id"], []).append(g)

        for pipeline_id in set(pipelines.keys()) | set(es_errors_by_pipeline.keys()):
            groups = es_errors_by_pipeline.get(pipeline_id) or []
            detail = None
            if groups:
                total = sum(g["count"] for g in groups)
                codes = ", ".join(str(c) for c in sorted({g["code"] for g in groups}))
                hosts = ", ".join(sorted({g["host"] for g in groups}))
                detail = f"{total} rejected bulk request(s) (code {codes}) against {hosts}"

            signal, sent_detail = _evaluate(server["id"], "es_errors", pipeline_id, bool(groups), detail, 1, now_ts)
            if signal == "opened":
                subject, text_body, html_body = build_alert_email(
                    "es_bulk_reject", label, server["host"], now_ts, detail=sent_detail, pipeline_id=pipeline_id
                )
                _notify_opened(server["id"], "es_errors", pipeline_id, config, other_recipients, subject, text_body, html_body)
            elif signal == "resolved":
                subject, text_body, html_body = build_alert_email(
                    "es_bulk_reject_recovered", label, server["host"], now_ts, pipeline_id=pipeline_id
                )
                _send(config, other_recipients, subject, text_body, html_body)

        # Same vanished-pipeline cleanup as step 3's stale_id loop above, kept
        # separate since an es_errors alert can exist for a pipeline that
        # never had a plain "pipeline" alert (and vice versa).
        for stale_id in db.list_stale_pipeline_alerts(server["id"], set(pipelines.keys()), scope="es_errors"):
            resolved_es = db.resolve_alert_state(server["id"], "es_errors", stale_id, now_ts)
            if resolved_es and resolved_es["status"] == "open":
                subject, text_body, html_body = build_alert_email(
                    "es_bulk_reject_recovered", label, server["host"], now_ts,
                    detail="No longer reporting an issue (pipeline may have been renamed/removed).",
                    pipeline_id=stale_id,
                )
                _send(config, other_recipients, subject, text_body, html_body)

        # ---- 4. Per-pipeline: missed its configured expected run interval ----
        # Read-only: EVERY pipeline is recorded here every cycle regardless of
        # whether anyone has configured an expectation for it -- that's what
        # makes pipelines show up on the Pipeline Schedules admin page on their
        # own, with no manual registration step. Only pipelines with
        # expected_value actually set are evaluated for staleness below.
        for pipeline_id, p in pipelines.items():
            events_out = p.get("events_out") or 0
            sched = db.record_pipeline_activity(server["id"], pipeline_id, events_out, now_ts)
            if sched["expected_value"] is None:
                # Not (or no longer) monitored for staleness -- e.g. the admin
                # just cleared this pipeline's expected interval on the
                # Pipeline Schedules page. If a schedule alert was already
                # open from before that change, nothing else will ever
                # re-evaluate it (this loop is the only place that does), so
                # it would otherwise sit open forever, still firing reminder
                # emails. Auto-resolve it here instead of leaving it orphaned
                # -- an admin shouldn't have to remember to click "Resolve"
                # on the Active Alerts page just because they turned
                # monitoring off for this pipeline.
                signal, _ = _evaluate(server["id"], "pipeline_schedule", pipeline_id, False, None, 1, now_ts)
                if signal == "resolved":
                    subject, text_body, html_body = build_alert_email(
                        "pipeline_schedule_recovered", label, server["host"], now_ts,
                        detail="No longer monitored for schedule (expected interval was cleared).",
                        pipeline_id=pipeline_id,
                    )
                    _send(config, other_recipients, subject, text_body, html_body)
                continue

            expected_seconds = sched["expected_value"] * db.UNIT_SECONDS[sched["expected_unit"]]
            last_activity_at = sched["last_activity_at"] or now_ts
            gap_seconds = now_ts - last_activity_at
            is_stale = gap_seconds > expected_seconds
            expected_label = f"{sched['expected_value']} {sched['expected_unit']}"

            signal, sched_detail = _evaluate(
                server["id"], "pipeline_schedule", pipeline_id, is_stale,
                f"No new output for {format_duration(gap_seconds)} (expected every {expected_label})",
                1, now_ts,
            )
            if signal == "opened":
                subject, text_body, html_body = build_alert_email(
                    "pipeline_schedule_missed", label, server["host"], now_ts,
                    detail=sched_detail, pipeline_id=pipeline_id,
                )
                _notify_opened(
                    server["id"], "pipeline_schedule", pipeline_id, config, other_recipients, subject, text_body, html_body
                )
            elif signal == "resolved":
                subject, text_body, html_body = build_alert_email(
                    "pipeline_schedule_recovered", label, server["host"], now_ts,
                    detail=f"Producing output again (expected every {expected_label}).", pipeline_id=pipeline_id,
                )
                _send(config, other_recipients, subject, text_body, html_body)
    finally:
        manager.close()


def format_duration(seconds):
    seconds = max(0, int(seconds))
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes = rem // 60
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if not days and minutes:
        parts.append(f"{minutes}m")
    return " ".join(parts) or "<1m"


def _reminder_interval_minutes_for_scope(config, scope):
    """Which of the three reminder-interval settings (Settings -> Alerts ->
    Email settings) applies to a given alert scope. 'service'/'api' share one
    (kept under its original column name, reminder_interval_minutes, so
    existing deployments' configured value carries over unchanged);
    'pipeline_schedule' gets its own; everything else (currently just
    'pipeline' -- event-gap / reload-failure / failed-to-start) falls back to
    the gap interval."""
    if scope in ("service", "api"):
        return config["reminder_interval_minutes"]
    if scope == "pipeline_schedule":
        return config["reminder_interval_schedule_minutes"]
    return config["reminder_interval_gap_minutes"]


def _send_reminders(config, now_ts):
    """Re-notifies for alerts that have been OPEN a while without being
    resolved, so a single email sent hours ago doesn't quietly get buried.
    Each alert's own scope decides which of the three reminder-interval
    settings applies (see _reminder_interval_minutes_for_scope) -- 0 disables
    reminders for that category."""
    for alert in db.list_open_alerts_for_reminder_check():
        interval_minutes = _reminder_interval_minutes_for_scope(config, alert["scope"])
        if not interval_minutes or interval_minutes <= 0:
            continue
        cutoff = now_ts - interval_minutes * 60
        if alert["opened_at"] > cutoff:
            continue
        if alert["last_reminder_at"] is not None and alert["last_reminder_at"] > cutoff:
            continue

        label = alert["label"] or alert["host"]
        recipients = _effective_recipients(alert, config, alert["scope"])
        open_for = format_duration(now_ts - alert["opened_at"]) if alert["opened_at"] else "unknown"
        subject, text_body, html_body = build_alert_email(
            "reminder", label, alert["host"], now_ts,
            detail=f"Open for {open_for}. {alert['detail'] or ''}".strip(),
            pipeline_id=alert["pipeline_id"],
        )
        ok, err = _send(config, recipients, subject, text_body, html_body)
        db.mark_reminder_sent(alert["id"], now_ts)
        logger.info("Sent reminder for %s (%s%s): ok=%s", label, alert["scope"],
                    f"/{alert['pipeline_id']}" if alert["pipeline_id"] else "", ok)


def _run_cycle():
    config = db.get_alert_config()
    if not config or not config["enabled"]:
        logger.info("Alerting is disabled (Settings -> Alerts -> Alerting enabled) -- skipping cycle.")
        return
    if not crypto_utils.encryption_available():
        logger.warning("Alerting is enabled but CRED_ENCRYPTION_KEY is not set -- skipping this cycle.")
        return

    servers = db.list_servers_with_monitoring()
    if not servers:
        logger.info("Alerting is enabled but no server has a monitoring credential set -- nothing to check.")
        return

    logger.info("Starting check cycle for %d monitored server(s): %s",
                len(servers), ", ".join(s["label"] or s["host"] for s in servers))
    now_ts = int(time.time())
    for server in servers:
        label = server["label"] or server["host"]
        try:
            _check_server(server, config, now_ts)
            logger.info("Finished checking %s (see above for any opened/resolved alerts).", label)
        except Exception:
            logger.exception("Alert check failed for server %s", label)

    try:
        _send_reminders(config, now_ts)
    except Exception:
        logger.exception("Sending reminder emails failed")


def run_alert_loop():
    """Runs forever in a daemon thread. Re-reads alert_config every cycle, so
    enabling/disabling alerting or changing the interval from the Alerts
    settings page takes effect on the next tick without a restart."""
    logger.info("Background alert checker thread started.")
    while True:
        try:
            _run_cycle()
        except Exception:
            logger.exception("Alert check cycle crashed")

        try:
            config = db.get_alert_config()
            interval_minutes = (config["check_interval_minutes"] if config else None) or 5
        except Exception:
            interval_minutes = 5
        time.sleep(max(60, interval_minutes * 60))


def start_background_thread():
    thread = threading.Thread(target=run_alert_loop, name="logstash-alert-checker", daemon=True)
    thread.start()
    return thread
