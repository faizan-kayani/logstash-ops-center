import json
import os
import re
import secrets
import time
import uuid
from datetime import datetime
from functools import wraps

from flask import Flask, flash, jsonify, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import alerting
import crypto_utils
import db
import excel_utils
from ssh_manager import (
    DEFAULT_LOGSTASH_LOG_PATH,
    ES_BULK_ERROR_GREP,
    SERVICE_NAME_RE,
    SSHManager,
    aggregate_es_bulk_errors,
    load_private_key,
    parse_es_bulk_errors,
)

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

db.init_db()
_seeded_password = db.seed_default_admin()
if _seeded_password:
    app.logger.warning(
        "Created default admin account -- username: admin  password: %s\n"
        "Log in and change this password (or create your own admin and delete this one).",
        _seeded_password,
    )

# Background Logstash health-check + email alerting -- the one deliberate
# exception to "no standing SSH credentials" in this app (see alerting.py's
# module docstring). Guarded against WERKZEUG_RUN_MAIN so Flask's debug
# reloader (python app.py) doesn't start it twice; gunicorn (production, per
# Dockerfile) never sets that var so it always starts there.
if not app.debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    alerting.start_background_thread()

# Live SSH connections, keyed by a random id. Never written to disk -- each browser
# session only holds the ids for the connections *it* opened (session["live"]), so
# this dict is process-wide but not reachable across sessions/users.
LIVE = {}

# Services where an accidental Stop could break the box or lock you out.
# The UI still allows stopping them, but shows a warning and asks for confirmation.
PROTECTED_SERVICES = {
    "ssh.service",
    "sshd.service",
    "systemd-journald.service",
    "systemd-logind.service",
    "dbus.service",
    "networking.service",
    "NetworkManager.service",
}


# ============================================================
# App-level auth (separate from the SSH credentials used to
# actually connect to a target Linux box)
# ============================================================

def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    return db.get_user_by_id(user_id)


@app.context_processor
def inject_nav_user():
    user = current_user()
    # Sidebar "Alerts" badge -- only worth the (cheap, indexed) query for
    # whoever can actually see the Active Alerts page (admins, or a non-admin
    # explicitly granted it -- see users.can_view_active_alerts).
    can_see_alerts = bool(user) and (user["role"] == "admin" or user["can_view_active_alerts"])
    open_alerts = db.count_open_alerts() if can_see_alerts else 0
    return {"nav_user": user, "open_alert_count": open_alerts}


@app.template_filter("format_ts")
def format_ts(value):
    from datetime import datetime
    return datetime.fromtimestamp(value).strftime("%Y-%m-%d %H:%M")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Please log in."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"error": "Admin access required."}), 403
            return redirect(url_for("list_servers"))
        return view(*args, **kwargs)

    return wrapped


def alerts_viewer_required(view):
    """Gates the Active Alerts page + its Resolve button: admins always pass;
    a non-admin passes only with users.can_view_active_alerts set (see Users
    page). Email settings / Per-server monitoring / the config-mutating routes
    stay behind plain @admin_required -- this decorator is never applied to
    those, by design (SMTP + per-server monitoring credentials stay admin-only
    regardless of this flag)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "admin" and not user["can_view_active_alerts"]:
            if request.path.startswith("/api/"):
                return jsonify({"error": "Access denied."}), 403
            return redirect(url_for("list_servers"))
        return view(*args, **kwargs)

    return wrapped


def excel_viewer_required(view):
    """Gates the Excel Sheet workspace: admins always pass; a non-admin
    passes only with users.can_view_excel_sheet set (see Users page). This
    workspace has no relationship to any server/SSH permission -- it's a
    standalone, global feature."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login"))
        if user["role"] != "admin" and not user["can_view_excel_sheet"]:
            return redirect(url_for("list_servers"))
        return view(*args, **kwargs)

    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user() is not None:
        return redirect(url_for("list_servers"))

    if request.method == "GET":
        return render_template("login.html", error=None, form=request.form)

    username = request.form.get("username", "").strip()
    password = request.form.get("password") or ""

    user = db.get_user_by_username(username)
    if user is None or not check_password_hash(user["password_hash"], password):
        return render_template("login.html", error="Invalid username or password.", form=request.form)

    session.clear()
    session["user_id"] = user["id"]
    return redirect(url_for("list_servers"))


@app.route("/logout", methods=["POST"])
def logout():
    for live_id in session.get("live", {}).values():
        entry = LIVE.pop(live_id, None)
        if entry is not None:
            entry["manager"].close()
    session.clear()
    return redirect(url_for("login"))


@app.route("/account", methods=["GET", "POST"])
@admin_required
def account():
    user = current_user()
    if request.method == "GET":
        return render_template("account.html", user=user, error=None, success=None)

    current_password = request.form.get("current_password") or ""
    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if not check_password_hash(user["password_hash"], current_password):
        return render_template("account.html", user=user, error="Current password is incorrect.", success=None)
    if len(new_password) < 8:
        return render_template("account.html", user=user, error="New password must be at least 8 characters.", success=None)
    if new_password != confirm_password:
        return render_template("account.html", user=user, error="New passwords do not match.", success=None)

    db.update_user_password(user["id"], generate_password_hash(new_password))
    return render_template("account.html", user=user, error=None, success="Password updated.")


# ============================================================
# Live SSH connection bookkeeping (per browser session)
# ============================================================

def get_live_manager(server_id):
    live_id = session.get("live", {}).get(server_id)
    if not live_id:
        return None
    entry = LIVE.get(live_id)
    return entry["manager"] if entry else None


def set_live_manager(server_id, manager):
    live_id = str(uuid.uuid4())
    LIVE[live_id] = {"manager": manager, "server_id": server_id}
    live_map = session.get("live", {})
    live_map[server_id] = live_id
    session["live"] = live_map


def clear_live_manager(server_id):
    live_map = session.get("live", {})
    live_id = live_map.pop(server_id, None)
    session["live"] = live_map
    if live_id:
        entry = LIVE.pop(live_id, None)
        if entry is not None:
            entry["manager"].close()


def server_access(server_id, need_control=False):
    """Returns the servers-table row for server_id if the current user may access
    it at the requested level, else None. Admins can access everything."""
    server = db.get_server(server_id)
    if server is None:
        return None
    user = current_user()
    if user["role"] == "admin":
        return server
    perm = db.get_permission(user["id"], server_id)
    if perm is None:
        return None
    allowed = perm["can_control"] if need_control else perm["can_view"]
    return server if allowed else None


def can_control_service(user, server_id, service_name):
    """Whether user may start/stop this specific service on this server: admins
    and full-control grants can control everything; otherwise fall back to any
    per-service grant an admin has handed out individually."""
    if user["role"] == "admin":
        return True
    perm = db.get_permission(user["id"], server_id)
    if perm and perm["can_control"]:
        return True
    return db.has_service_permission(user["id"], server_id, service_name)


# One independent grant per Logstash monitoring page -- previously any of these
# just piggybacked on can_view, so a user with view access saw all three
# automatically with no way to grant e.g. just Start/Stop Services and nothing
# else. Column names follow "can_view_pipeline_<feature>" in the permissions
# table (see init_db). "es_errors" (Elasticsearch Errors page) was added
# after the other three shipped, same independent-grant treatment.
PIPELINE_FEATURES = ("status", "errors", "logs", "es_errors")


def can_view_pipeline_feature(user, server_id, feature):
    """feature is one of PIPELINE_FEATURES. Admins bypass this like everything
    else; a non-admin needs the specific column set on their permissions row
    for this server (server_access's can_view is NOT enough by itself)."""
    if user["role"] == "admin":
        return True
    perm = db.get_permission(user["id"], server_id)
    return bool(perm and perm[f"can_view_pipeline_{feature}"])


# ============================================================
# Servers (user-facing: filtered to what this account can see)
# ============================================================

@app.route("/")
@login_required
def home():
    return redirect(url_for("list_servers"))


@app.route("/servers")
@login_required
def list_servers():
    user = current_user()
    servers = []
    for server in db.list_servers():
        if user["role"] != "admin":
            perm = db.get_permission(user["id"], server["id"])
            if perm is None or not perm["can_view"]:
                continue
            can_control = bool(perm["can_control"])
        else:
            can_control = True
        servers.append({
            "id": server["id"],
            "label": server["label"],
            "host": server["host"],
            "port": server["port"],
            "username": server["username"],
            "connected": get_live_manager(server["id"]) is not None,
            "can_control": can_control,
        })
    return render_template("servers.html", servers=servers, user=user, active="servers")


@app.route("/servers/<server_id>/connect", methods=["GET", "POST"])
@login_required
def connect_server(server_id):
    server = server_access(server_id)
    if server is None:
        return redirect(url_for("list_servers"))

    if get_live_manager(server_id) is not None:
        return redirect(url_for("server_dashboard", server_id=server_id))

    if request.method == "GET":
        return render_template("connect.html", server=server, error=None, form=request.form)

    auth_type = request.form.get("auth_type", "password")
    password = request.form.get("password") or None
    key_text = request.form.get("private_key") or None
    passphrase = request.form.get("passphrase") or None
    sudo_password = request.form.get("sudo_password") or None

    try:
        private_key = None
        if auth_type == "key":
            if not key_text:
                raise ValueError("Paste a private key or switch to password auth.")
            private_key = load_private_key(key_text, passphrase)
            password = None
        elif not password:
            raise ValueError("Password is required for password auth.")

        manager = SSHManager(
            server["host"], server["port"], server["username"],
            password=password, private_key=private_key, sudo_password=sudo_password,
        )
        manager.run_command("echo connected")  # forces the connection attempt now
    except Exception as exc:
        return render_template("connect.html", server=server, error=f"Connection failed: {exc}", form=request.form)

    set_live_manager(server_id, manager)
    return redirect(url_for("server_dashboard", server_id=server_id))


@app.route("/servers/<server_id>/disconnect", methods=["POST"])
@login_required
def disconnect_server(server_id):
    clear_live_manager(server_id)
    return redirect(url_for("list_servers"))


@app.route("/servers/<server_id>")
@login_required
def server_dashboard(server_id):
    server = server_access(server_id)
    if server is None:
        return redirect(url_for("list_servers"))

    if get_live_manager(server_id) is None:
        return redirect(url_for("connect_server", server_id=server_id))

    user = current_user()
    can_control = user["role"] == "admin"
    controllable_services = None
    access_note = None
    if not can_control:
        perm = db.get_permission(user["id"], server_id)
        can_control = bool(perm and perm["can_control"])
        if not can_control:
            controllable_services = db.list_service_permissions(user["id"], server_id)
            access_note = (
                f"Limited control ({len(controllable_services)} service{'s' if len(controllable_services) != 1 else ''})"
                if controllable_services else "View only"
            )

    return render_template(
        "index.html",
        protected=sorted(PROTECTED_SERVICES),
        server_id=server_id,
        label=server["label"],
        host=server["host"],
        username=server["username"],
        can_control=can_control,
        controllable_services=controllable_services,
        access_note=access_note,
        can_view_pipeline_status=can_view_pipeline_feature(user, server_id, "status"),
        can_view_pipeline_errors=can_view_pipeline_feature(user, server_id, "errors"),
        can_view_pipeline_logs=can_view_pipeline_feature(user, server_id, "logs"),
        can_view_pipeline_es_errors=can_view_pipeline_feature(user, server_id, "es_errors"),
    )


# ============================================================
# Services / logs API -- scoped to one catalog server, permission-checked
# ============================================================

def _require_live(server_id):
    """View-level gate shared by every services/logs endpoint. Start/stop additionally
    check can_control_service() themselves, since control can be granted per-service."""
    server = server_access(server_id, need_control=False)
    if server is None:
        return None, (jsonify({"error": "Access denied."}), 403)
    manager = get_live_manager(server_id)
    if manager is None:
        return None, (jsonify({"error": "Not connected. Open this server again to reconnect."}), 409)
    return manager, None


@app.route("/api/servers/<server_id>/services")
@login_required
def api_list_services(server_id):
    manager, err = _require_live(server_id)
    if err:
        return err
    try:
        return jsonify({"services": manager.list_services()})
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/servers/<server_id>/logs")
@login_required
def api_read_log(server_id):
    manager, err = _require_live(server_id)
    if err:
        return err
    if not can_view_pipeline_feature(current_user(), server_id, "logs"):
        return jsonify({"error": "Access denied."}), 403
    path = request.args.get("path", "").strip()
    grep = request.args.get("grep", "").strip() or None
    try:
        lines = int(request.args.get("lines", 200))
    except ValueError:
        lines = 200
    try:
        content = manager.read_log_file(path, lines=lines, grep=grep)
        return jsonify({"path": path, "content": content, "grep": grep})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/servers/<server_id>/logstash/stats")
@login_required
def api_logstash_stats(server_id):
    """Pipeline status, in/out event metrics, and reload/error info, read from
    the Logstash Monitoring API on the target host (see SSHManager.logstash_stats)."""
    manager, err = _require_live(server_id)
    if err:
        return err
    user = current_user()
    # Pipeline Status and Reload/Config Errors both read from this one fetch
    # (see static/app.js) -- either grant is enough to call it.
    if not (can_view_pipeline_feature(user, server_id, "status") or can_view_pipeline_feature(user, server_id, "errors")):
        return jsonify({"error": "Access denied."}), 403
    port = request.args.get("port", "9600").strip() or "9600"
    try:
        result = manager.logstash_stats(port)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    # Per-pipeline 3-state health, plus summary counts -- not an official Logstash
    # concept, just the clearest read of the two signals the Monitoring API gives us:
    #   down   -- workers == 0 (loaded but not actually processing/running)
    #   issues -- running (workers > 0) but has at least one failed reload
    #   up     -- running with no reload failures
    pipelines = result.get("pipelines") or {}
    up = issues = down = 0
    for p in pipelines.values():
        workers = p.get("workers") or 0
        if workers <= 0:
            health = "down"
            down += 1
        elif (p.get("reload_failures") or 0) > 0:
            health = "issues"
            issues += 1
        else:
            health = "up"
            up += 1
        p["health"] = health
    result["pipeline_up_count"] = up
    result["pipeline_issues_count"] = issues
    result["pipeline_down_count"] = down

    # Local-only history snapshot for the time-range filter (see db.record_logstash_snapshot)
    # -- purely appends to the dashboard's own SQLite db; never touches the target server.
    try:
        db.record_logstash_snapshot(server_id, result.get("status"), pipelines)
    except Exception:
        app.logger.exception("Failed to record Logstash history snapshot for server %s", server_id)

    return jsonify(result)


@app.route("/api/servers/<server_id>/logstash/history")
@login_required
def api_logstash_history(server_id):
    """Reads back locally-recorded Logstash snapshots (see db.record_logstash_snapshot)
    for the history/time-range filter -- read-only against the dashboard's own SQLite
    db, no SSH connection involved at all. Coverage only exists for windows when someone
    had this server's Logstash page open (no background poller -- see init_db)."""
    if server_access(server_id, need_control=False) is None:
        return jsonify({"error": "Access denied."}), 403
    if not can_view_pipeline_feature(current_user(), server_id, "status"):
        return jsonify({"error": "Access denied."}), 403

    pipeline_id = request.args.get("pipeline", "").strip() or None
    minutes = request.args.get("minutes", "").strip()
    start_param = request.args.get("start", "").strip()
    end_param = request.args.get("end", "").strip()

    now = int(time.time())
    start_ts = end_ts = None
    if minutes:
        try:
            start_ts = now - int(minutes) * 60
        except ValueError:
            return jsonify({"error": "minutes must be a number."}), 400
    else:
        if start_param:
            try:
                start_ts = int(datetime.fromisoformat(start_param).timestamp())
            except ValueError:
                return jsonify({"error": "Invalid start date/time."}), 400
        if end_param:
            try:
                end_ts = int(datetime.fromisoformat(end_param).timestamp())
            except ValueError:
                return jsonify({"error": "Invalid end date/time."}), 400

    rows = db.query_logstash_history(server_id, pipeline_id, start_ts, end_ts)
    return jsonify({
        "pipeline_ids": db.list_logstash_pipeline_ids(server_id),
        "snapshots": [dict(row) for row in rows],
    })


@app.route("/api/servers/<server_id>/logstash/es-errors")
@login_required
def api_logstash_es_errors(server_id):
    """Read-only: greps the target's own Logstash log file (never modifies it,
    same read_log_file() the Pipeline Logs page uses) for Elasticsearch-output
    bulk-request rejections -- e.g. 413 Payload Too Large, 429 Too Many
    Requests -- and groups them per pipeline/host/code (see
    ssh_manager.parse_es_bulk_errors / aggregate_es_bulk_errors).

    This exists because the Monitoring API (api_logstash_stats above) doesn't
    surface these at all: Logstash retries a rejected bulk request with
    exponential backoff in the background, so events_in/out and
    reload_failures all stay clean while this is actively happening -- the
    only trace is in Logstash's own log."""
    manager, err = _require_live(server_id)
    if err:
        return err
    if not can_view_pipeline_feature(current_user(), server_id, "es_errors"):
        return jsonify({"error": "Access denied."}), 403
    path = request.args.get("path", "").strip() or DEFAULT_LOGSTASH_LOG_PATH
    try:
        lines = int(request.args.get("lines", 2000))
    except ValueError:
        lines = 2000
    try:
        raw = manager.read_log_file(path, lines=lines, grep=ES_BULK_ERROR_GREP)
        groups = aggregate_es_bulk_errors(parse_es_bulk_errors(raw))
        return jsonify({"path": path, "groups": groups})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/servers/<server_id>/services/<name>/details")
@login_required
def api_service_details(server_id, name):
    manager, err = _require_live(server_id)
    if err:
        return err
    try:
        return jsonify(manager.service_details(name))
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


def _log_service_action(server_id, name, action, success, message=None):
    """Best-effort audit-log write for the Start/Stop History panel -- never lets a
    logging failure affect the actual start/stop response the user gets back."""
    try:
        db.record_service_action(server_id, name, action, current_user(), success, message)
    except Exception:
        app.logger.exception("Failed to record %s action for %s/%s", action, server_id, name)


@app.route("/api/servers/<server_id>/services/<name>/start", methods=["POST"])
@login_required
def api_start_service(server_id, name):
    # Permission is checked before connection state, so "you can't control this
    # service" (403) is never masked by an unrelated "not connected yet" (409).
    if server_access(server_id, need_control=False) is None:
        return jsonify({"error": "Access denied."}), 403
    if not can_control_service(current_user(), server_id, name):
        return jsonify({"error": "You don't have permission to control this service."}), 403
    manager = get_live_manager(server_id)
    if manager is None:
        return jsonify({"error": "Not connected. Open this server again to reconnect."}), 409
    try:
        out, err_out, code = manager.start_service(name)
        if code != 0:
            app.logger.warning("start %s failed (exit %s): stdout=%r stderr=%r", name, code, out, err_out)
            message = err_out.strip() or out.strip()
            _log_service_action(server_id, name, "start", False, message)
            return jsonify({"error": message}), 500
        _log_service_action(server_id, name, "start", True)
        return jsonify({"name": name, "active": manager.service_status(name)})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        app.logger.exception("start %s raised an exception", name)
        _log_service_action(server_id, name, "start", False, str(exc))
        return jsonify({"error": str(exc)}), 500


@app.route("/api/servers/<server_id>/services/<name>/stop", methods=["POST"])
@login_required
def api_stop_service(server_id, name):
    if server_access(server_id, need_control=False) is None:
        return jsonify({"error": "Access denied."}), 403
    if not can_control_service(current_user(), server_id, name):
        return jsonify({"error": "You don't have permission to control this service."}), 403
    manager = get_live_manager(server_id)
    if manager is None:
        return jsonify({"error": "Not connected. Open this server again to reconnect."}), 409
    try:
        out, err_out, code = manager.stop_service(name)
        if code != 0:
            app.logger.warning("stop %s failed (exit %s): stdout=%r stderr=%r", name, code, out, err_out)
            message = err_out.strip() or out.strip()
            _log_service_action(server_id, name, "stop", False, message)
            return jsonify({"error": message}), 500
        _log_service_action(server_id, name, "stop", True)
        return jsonify({"name": name, "active": manager.service_status(name)})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        app.logger.exception("stop %s raised an exception", name)
        _log_service_action(server_id, name, "stop", False, str(exc))
        return jsonify({"error": str(exc)}), 500


@app.route("/api/servers/<server_id>/services/<name>/restart", methods=["POST"])
@login_required
def api_restart_service(server_id, name):
    if server_access(server_id, need_control=False) is None:
        return jsonify({"error": "Access denied."}), 403
    if not can_control_service(current_user(), server_id, name):
        return jsonify({"error": "You don't have permission to control this service."}), 403
    manager = get_live_manager(server_id)
    if manager is None:
        return jsonify({"error": "Not connected. Open this server again to reconnect."}), 409
    try:
        out, err_out, code = manager.restart_service(name)
        if code != 0:
            app.logger.warning("restart %s failed (exit %s): stdout=%r stderr=%r", name, code, out, err_out)
            message = err_out.strip() or out.strip()
            _log_service_action(server_id, name, "restart", False, message)
            return jsonify({"error": message}), 500
        _log_service_action(server_id, name, "restart", True)
        return jsonify({"name": name, "active": manager.service_status(name)})
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        app.logger.exception("restart %s raised an exception", name)
        _log_service_action(server_id, name, "restart", False, str(exc))
        return jsonify({"error": str(exc)}), 500


@app.route("/api/servers/<server_id>/services/history")
@login_required
def api_service_action_history(server_id):
    """Reads back the start/stop audit log (see db.record_service_action) -- local
    SQLite read only, no SSH connection needed to view it."""
    if server_access(server_id, need_control=False) is None:
        return jsonify({"error": "Access denied."}), 403

    service_name = request.args.get("service", "").strip() or None
    minutes = request.args.get("minutes", "").strip()
    start_param = request.args.get("start", "").strip()
    end_param = request.args.get("end", "").strip()

    now = int(time.time())
    start_ts = end_ts = None
    if minutes:
        try:
            start_ts = now - int(minutes) * 60
        except ValueError:
            return jsonify({"error": "minutes must be a number."}), 400
    else:
        if start_param:
            try:
                start_ts = int(datetime.fromisoformat(start_param).timestamp())
            except ValueError:
                return jsonify({"error": "Invalid start date/time."}), 400
        if end_param:
            try:
                end_ts = int(datetime.fromisoformat(end_param).timestamp())
            except ValueError:
                return jsonify({"error": "Invalid end date/time."}), 400

    rows = db.query_service_actions(server_id, service_name, start_ts, end_ts)
    return jsonify({
        "service_names": db.list_service_action_names(server_id),
        "entries": [dict(row) for row in rows],
    })


# ============================================================
# Admin: Settings (users + server catalog, tabbed under one area)
# ============================================================

@app.route("/admin/settings")
@admin_required
def admin_settings():
    return redirect(url_for("admin_users"))


@app.route("/admin/settings/servers")
@admin_required
def admin_servers():
    servers = []
    for server in db.list_servers():
        service_grants = {}
        for row in db.list_service_permissions_for_server(server["id"]):
            service_grants.setdefault(row["user_id"], []).append(row["service_name"])
        servers.append({
            "row": server,
            "permissions": db.list_permissions_for_server(server["id"]),
            "service_grants": service_grants,
        })
    non_admins = [u for u in db.list_users() if u["role"] != "admin"]
    return render_template(
        "admin_servers.html", servers=servers, users=non_admins, active="settings", settings_tab="servers"
    )


@app.route("/admin/settings/servers/new", methods=["GET", "POST"])
@admin_required
def admin_new_server():
    if request.method == "GET":
        return render_template("server_new.html", error=None, form=request.form)

    label = request.form.get("label", "").strip() or None
    host = request.form.get("host", "").strip()
    port_raw = request.form.get("port", "").strip() or "22"
    username = request.form.get("username", "").strip()

    try:
        port = int(port_raw)
    except ValueError:
        return render_template("server_new.html", error="Port must be a number.", form=request.form)

    if not host or not username:
        return render_template("server_new.html", error="Host and username are required.", form=request.form)

    db.create_server(label, host, port, username, current_user()["id"])
    return redirect(url_for("admin_servers"))


@app.route("/admin/settings/servers/<server_id>/delete", methods=["POST"])
@admin_required
def admin_delete_server(server_id):
    db.delete_server(server_id)
    return redirect(url_for("admin_servers"))


@app.route("/admin/settings/servers/<server_id>/permissions", methods=["POST"])
@admin_required
def admin_set_permissions(server_id):
    if db.get_server(server_id) is None:
        return redirect(url_for("admin_servers"))

    skipped = []
    for user in db.list_users():
        if user["role"] == "admin":
            continue
        can_view = request.form.get(f"view_{user['id']}") == "on"
        can_control = request.form.get(f"control_{user['id']}") == "on"
        can_view_pipeline_status = request.form.get(f"pipeline_status_{user['id']}") == "on"
        can_view_pipeline_errors = request.form.get(f"pipeline_errors_{user['id']}") == "on"
        can_view_pipeline_logs = request.form.get(f"pipeline_logs_{user['id']}") == "on"
        can_view_pipeline_es_errors = request.form.get(f"pipeline_es_errors_{user['id']}") == "on"
        if any((can_view, can_control, can_view_pipeline_status, can_view_pipeline_errors,
                can_view_pipeline_logs, can_view_pipeline_es_errors)):
            db.set_permission(
                user["id"], server_id, can_view, can_control,
                can_view_pipeline_status, can_view_pipeline_errors, can_view_pipeline_logs,
                can_view_pipeline_es_errors,
            )
        else:
            db.remove_permission(user["id"], server_id)

        raw_services = request.form.get(f"services_{user['id']}", "")
        names = [n.strip() for n in re.split(r"[,\n]+", raw_services) if n.strip()]
        valid_names = [n for n in names if SERVICE_NAME_RE.match(n)]
        db.set_service_permissions(user["id"], server_id, valid_names)
        skipped.extend(n for n in names if n not in valid_names)

    if skipped:
        flash(f"Skipped invalid service name(s): {', '.join(skipped)}", "error")

    return redirect(url_for("admin_servers"))


# ============================================================
# Admin: Alerts -- SMTP settings, thresholds, and per-server monitoring
# credentials/recipients, all editable live from this one page (see
# alerting.py's module docstring for why monitoring credentials are the one
# exception to this app's "no standing SSH credentials" rule).
# ============================================================

def _parse_int_field(form, name, default, error_label, errors):
    raw = form.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        errors.append(f"{error_label} must be a number.")
        return default


def _render_alerts_page(tab, selected_server_id=None):
    """Shared by all four Alerts sub-pages (Active Alerts / Email settings /
    Per-server monitoring / Pipeline Schedules) -- same underlying data,
    template just shows the one section matching `tab`."""
    now_ts = int(time.time())
    active_alerts = []
    for row in db.list_active_alerts():
        alert = dict(row)
        # "Open for" is a presentation concern (depends on "now"), computed
        # here rather than stored, so it's always accurate to the second the
        # page was loaded rather than whenever the row last changed.
        alert["open_duration"] = alerting.format_duration(now_ts - alert["opened_at"]) if alert["opened_at"] else None
        active_alerts.append(alert)

    schedules = []
    if tab == "schedules" and selected_server_id:
        for row in db.list_pipeline_schedules(selected_server_id):
            entry = dict(row)
            entry["last_activity_label"] = (
                f"{alerting.format_duration(now_ts - entry['last_activity_at'])} ago"
                if entry["last_activity_at"] else "never observed"
            )
            schedules.append(entry)

    return render_template(
        "admin_alerts.html",
        tab=tab,
        config=db.get_alert_config(),
        servers=db.list_servers(),
        active_alerts=active_alerts,
        schedules=schedules,
        selected_server_id=selected_server_id,
        schedule_units=list(db.UNIT_SECONDS.keys()),
        encryption_available=crypto_utils.encryption_available(),
        active="settings",
        settings_tab="alerts",
        alerts_tab=tab,
    )


@app.route("/admin/settings/alerts")
@alerts_viewer_required
def admin_alerts():
    return _render_alerts_page("active")


@app.route("/admin/settings/alerts/email")
@admin_required
def admin_alerts_email():
    return _render_alerts_page("email")


@app.route("/admin/settings/alerts/monitoring")
@admin_required
def admin_alerts_monitoring():
    return _render_alerts_page("monitoring")


@app.route("/admin/settings/alerts/schedules")
@admin_required
def admin_alerts_schedules():
    servers = db.list_servers()
    selected_server_id = request.args.get("server") or (servers[0]["id"] if servers else None)
    return _render_alerts_page("schedules", selected_server_id)


@app.route("/admin/settings/alerts/schedules/<server_id>", methods=["POST"])
@admin_required
def admin_update_pipeline_schedules(server_id):
    """Read-only monitoring config, not a remote action: this only ever writes
    to this dashboard's own database (each pipeline's expected run interval).
    Nothing here is sent to Logstash or the target server."""
    if db.get_server(server_id) is None:
        return redirect(url_for("admin_alerts_schedules"))

    errors = []
    for row in db.list_pipeline_schedules(server_id):
        pipeline_id = row["pipeline_id"]
        raw_value = request.form.get(f"value_{pipeline_id}", "").strip()
        unit = request.form.get(f"unit_{pipeline_id}", "").strip()

        if not raw_value:
            db.set_pipeline_schedule_expected(server_id, pipeline_id, None, None)
            continue
        try:
            value = int(raw_value)
            if value <= 0:
                raise ValueError
        except ValueError:
            errors.append(f"Invalid expected interval for '{pipeline_id}' -- must be a positive whole number.")
            continue
        if unit not in db.UNIT_SECONDS:
            errors.append(f"Invalid time unit for '{pipeline_id}'.")
            continue

        db.set_pipeline_schedule_expected(server_id, pipeline_id, value, unit)

    for err in errors:
        flash(err, "error")
    if not errors:
        flash("Pipeline schedules saved.", "success")
    return redirect(url_for("admin_alerts_schedules", server=server_id))


@app.route("/admin/settings/alerts/schedules/<server_id>/<path:pipeline_id>/remove", methods=["POST"])
@admin_required
def admin_remove_pipeline_schedule(server_id, pipeline_id):
    """Drops a pipeline's row from the Pipeline Schedules list entirely (e.g.
    it was renamed/retired) -- only removes this dashboard's own bookkeeping,
    never touches anything on the target server."""
    db.remove_stale_pipeline_schedule(server_id, pipeline_id)
    return redirect(url_for("admin_alerts_schedules", server=server_id))


@app.template_filter("fmt_time")
def fmt_time(ts):
    """Unix timestamp -> human-readable string, for the Active Alerts panel."""
    if not ts:
        return "—"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")


@app.route("/admin/settings/alerts/email", methods=["POST"])
@admin_required
def admin_update_alerts():
    if not crypto_utils.encryption_available():
        flash("CRED_ENCRYPTION_KEY is not set -- alerting can't be enabled until it is. "
              "See the README for how to generate one.", "error")
        return redirect(url_for("admin_alerts_email"))

    errors = []
    fields = {
        "enabled": 1 if request.form.get("enabled") == "on" else 0,
        "smtp_host": request.form.get("smtp_host", "").strip() or None,
        "smtp_username": request.form.get("smtp_username", "").strip() or None,
        "smtp_use_tls": 1 if request.form.get("smtp_use_tls") == "on" else 0,
        "from_name": request.form.get("from_name", "").strip() or None,
        "from_address": request.form.get("from_address", "").strip() or None,
        "default_recipients": request.form.get("default_recipients", "").strip() or None,
        "service_recipients": request.form.get("service_recipients", "").strip() or None,
        "default_service_name": request.form.get("default_service_name", "").strip() or "logstash.service",
    }
    fields["smtp_port"] = _parse_int_field(request.form, "smtp_port", 587, "SMTP port", errors)
    fields["check_interval_minutes"] = _parse_int_field(request.form, "check_interval_minutes", 5, "Check interval", errors)
    fields["event_gap_threshold"] = _parse_int_field(request.form, "event_gap_threshold", 100, "Event gap threshold", errors)
    fields["consecutive_checks_required"] = _parse_int_field(
        request.form, "consecutive_checks_required", 2, "Consecutive checks", errors
    )
    fields["reminder_interval_minutes"] = _parse_int_field(
        request.form, "reminder_interval_minutes", 30, "Reminder interval (Service/API)", errors
    )
    fields["reminder_interval_schedule_minutes"] = _parse_int_field(
        request.form, "reminder_interval_schedule_minutes", 30, "Reminder interval (Pipeline Schedule)", errors
    )
    fields["reminder_interval_gap_minutes"] = _parse_int_field(
        request.form, "reminder_interval_gap_minutes", 30, "Reminder interval (Event-gap)", errors
    )

    # Blank password field means "leave the stored one alone" -- never force a
    # re-type just to change an unrelated field like the interval.
    smtp_password = request.form.get("smtp_password", "")
    if smtp_password:
        fields["smtp_password_enc"] = crypto_utils.encrypt(smtp_password)

    if errors:
        for err in errors:
            flash(err, "error")
        return redirect(url_for("admin_alerts_email"))

    db.update_alert_config(**fields)
    flash("Alert settings saved.", "success")
    return redirect(url_for("admin_alerts_email"))


@app.route("/admin/settings/alerts/servers/<server_id>/monitoring", methods=["POST"])
@admin_required
def admin_update_server_monitoring(server_id):
    server = db.get_server(server_id)
    if server is None:
        return redirect(url_for("admin_alerts_monitoring"))

    if not crypto_utils.encryption_available():
        flash("CRED_ENCRYPTION_KEY is not set -- monitoring credentials can't be stored until it is.", "error")
        return redirect(url_for("admin_alerts_monitoring"))

    monitoring_enabled = request.form.get("monitoring_enabled") == "on"
    monitor_username = request.form.get("monitor_username", "").strip()
    monitor_password = request.form.get("monitor_password", "")
    service_name_override = request.form.get("service_name_override", "").strip() or None
    alert_recipients_override = request.form.get("alert_recipients_override", "").strip() or None

    if monitoring_enabled and not monitor_username:
        flash("Enter a monitoring username to enable monitoring for this server.", "error")
        return redirect(url_for("admin_alerts_monitoring"))

    if not monitoring_enabled or not monitor_username:
        # "Monitoring enabled" toggle off (or a blank username, belt-and-suspenders
        # for any old cached page that predates the toggle) = "stop monitoring this
        # server" -- clears the credential entirely rather than leaving a stale/
        # orphaned password behind.
        db.clear_server_monitoring_credential(server_id)
        db.set_server_monitoring(server_id, None, None, service_name_override, alert_recipients_override)

        # Nobody will ever check this server again once monitoring's off, so any
        # alert still open at this moment would otherwise sit "open" forever --
        # visible on Active Alerts and still firing reminder emails indefinitely,
        # since the reminder loop has no idea monitoring got turned off. Silently
        # resolve them (no "recovered" email -- turning off monitoring doesn't
        # mean the underlying problem is actually fixed, just that we've stopped
        # watching for it).
        now_ts = int(time.time())
        for row in db.list_open_alert_keys(server_id):
            db.resolve_alert_state(server_id, row["scope"], row["pipeline_id"], now_ts,
                                    resolved_by=current_user()["username"])

        flash(f"Monitoring disabled for {server['label'] or server['host']}.", "success")
        return redirect(url_for("admin_alerts_monitoring"))

    # Blank password = keep the previously stored one (don't force a re-type
    # just to change the service-name or recipient override fields).
    password_enc = crypto_utils.encrypt(monitor_password) if monitor_password else server["monitor_password_enc"]
    if monitor_password == "" and not server["monitor_password_enc"]:
        flash("Enter a monitoring password -- none is stored yet for this server.", "error")
        return redirect(url_for("admin_alerts_monitoring"))

    db.set_server_monitoring(server_id, monitor_username, password_enc, service_name_override, alert_recipients_override)
    flash(f"Monitoring settings saved for {server['label'] or server['host']}.", "success")
    return redirect(url_for("admin_alerts_monitoring"))


@app.route("/admin/settings/alerts/test-email", methods=["POST"])
@admin_required
def admin_send_test_email():
    """Sends one real email right now using whatever SMTP settings are
    currently SAVED (not the form's unsaved values -- save first, then test),
    to confirm the SMTP setup actually works without waiting for a real
    Logstash problem to trigger it."""
    config = db.get_alert_config()
    test_recipient = request.form.get("test_recipient", "").strip()
    recipients = alerting._parse_recipients(test_recipient) or alerting._parse_recipients(config["default_recipients"])

    if not recipients:
        flash("Enter a recipient to test, or set Default recipients (or Service alert recipients) first and save.", "error")
        return redirect(url_for("admin_alerts_email"))

    try:
        subject, text_body, html_body = alerting.build_alert_email(
            "test", "Logstash Monitoring", now_ts=int(time.time()),
            detail="This confirms your SMTP settings on the Alerts page are working correctly.",
        )
        alerting.send_email(config, recipients, subject, text_body, html_body)
        flash(f"Test email sent successfully to {', '.join(recipients)}.", "success")
    except Exception as exc:
        flash(f"Test email failed: {exc}", "error")
    return redirect(url_for("admin_alerts_email"))


@app.route("/admin/settings/alerts/<server_id>/resolve", methods=["POST"])
@alerts_viewer_required
def admin_resolve_alert(server_id):
    """Manually clears an open/pending alert from the Active Alerts panel --
    e.g. the admin already fixed it on the server and doesn't want to wait
    for the next check cycle to confirm it. Not destructive: if the underlying
    problem is actually still there, the very next cycle just re-opens it."""
    scope = request.form.get("scope", "").strip()
    pipeline_id = request.form.get("pipeline_id", "").strip() or None
    if scope not in ("service", "api", "pipeline", "pipeline_schedule", "es_errors"):
        flash("Invalid alert reference.", "error")
        return redirect(url_for("admin_alerts"))

    server = db.get_server(server_id)
    if server is None:
        flash("Server not found.", "error")
        return redirect(url_for("admin_alerts"))

    now_ts = int(time.time())
    resolved_by = current_user()["username"]
    resolved = db.resolve_alert_state(server_id, scope, pipeline_id, now_ts, resolved_by=resolved_by)
    if resolved is None:
        flash("That alert is no longer open.", "success")
        return redirect(url_for("admin_alerts"))

    if resolved["status"] == "open":
        try:
            config = db.get_alert_config()
            recipients = alerting._effective_recipients(server, config, scope)
            if recipients:
                label = server["label"] or server["host"]
                subject, text_body, html_body = alerting.build_alert_email(
                    "manually_resolved", label, server["host"], now_ts,
                    detail=f"Manually marked resolved by {resolved_by}.", pipeline_id=pipeline_id,
                )
                alerting.send_email(config, recipients, subject, text_body, html_body)
        except Exception:
            app.logger.exception("Failed to send manual-resolve notification for server %s", server_id)

    flash(f"Alert cleared for {server['label'] or server['host']}.", "success")
    return redirect(url_for("admin_alerts"))


# ============================================================
# Admin: users (role assignment + account management)
# ============================================================

@app.route("/admin/settings/users")
@admin_required
def admin_users():
    return render_template(
        "admin_users.html", users=db.list_users(), current_id=current_user()["id"],
        active="settings", settings_tab="users",
    )


@app.route("/admin/settings/users/new", methods=["POST"])
@admin_required
def admin_new_user():
    username = request.form.get("username", "").strip()
    password = request.form.get("password") or ""
    role = request.form.get("role") if request.form.get("role") in db.ROLES else "user"

    if not username or len(password) < 8:
        flash("Username is required and password must be at least 8 characters.", "error")
        return redirect(url_for("admin_users"))

    if db.get_user_by_username(username) is not None:
        flash(f"A user named '{username}' already exists.", "error")
        return redirect(url_for("admin_users"))

    db.create_user(username, generate_password_hash(password), role)
    flash(f"User '{username}' created.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/settings/users/<int:user_id>/role", methods=["POST"])
@admin_required
def admin_set_role(user_id):
    role = request.form.get("role")
    if role not in db.ROLES:
        return redirect(url_for("admin_users"))

    target = db.get_user_by_id(user_id)
    if target is not None and target["role"] == "admin" and role != "admin" and db.count_admins() <= 1:
        flash("Can't demote the last remaining admin.", "error")
        return redirect(url_for("admin_users"))

    db.update_user_role(user_id, role)
    return redirect(url_for("admin_users"))


@app.route("/admin/settings/users/<int:user_id>/alerts-access", methods=["POST"])
@admin_required
def admin_set_alerts_access(user_id):
    """Grants/revokes a non-admin's view of the Active Alerts page (see
    alerts_viewer_required / users.can_view_active_alerts) -- Email settings and
    Per-server monitoring have no equivalent toggle and stay admin-only."""
    target = db.get_user_by_id(user_id)
    if target is None or target["role"] == "admin":
        return redirect(url_for("admin_users"))
    db.set_user_alert_access(user_id, request.form.get("can_view_active_alerts") == "on")
    return redirect(url_for("admin_users"))


@app.route("/admin/settings/users/<int:user_id>/password", methods=["POST"])
@admin_required
def admin_reset_password(user_id):
    target = db.get_user_by_id(user_id)
    if target is None:
        return redirect(url_for("admin_users"))

    new_password = request.form.get("new_password") or ""
    confirm_password = request.form.get("confirm_password") or ""

    if len(new_password) < 8:
        flash("New password must be at least 8 characters.", "error")
        return redirect(url_for("admin_users"))
    if new_password != confirm_password:
        flash("New password and confirmation do not match.", "error")
        return redirect(url_for("admin_users"))

    db.update_user_password(user_id, generate_password_hash(new_password))
    flash(f"Password updated for '{target['username']}'.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/settings/users/<int:user_id>/delete", methods=["POST"])
@admin_required
def admin_delete_user(user_id):
    target = db.get_user_by_id(user_id)
    if target is None:
        return redirect(url_for("admin_users"))
    if user_id == current_user()["id"]:
        flash("You can't delete your own account.", "error")
        return redirect(url_for("admin_users"))
    if target["role"] == "admin" and db.count_admins() <= 1:
        flash("Can't delete the last remaining admin.", "error")
        return redirect(url_for("admin_users"))

    db.delete_user(user_id)
    flash(f"User '{target['username']}' deleted.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/settings/users/<int:user_id>/excel-access", methods=["POST"])
@admin_required
def admin_set_excel_access(user_id):
    """Grants/revokes a non-admin's access to the Excel Sheet workspace (see
    excel_viewer_required / users.can_view_excel_sheet)."""
    target = db.get_user_by_id(user_id)
    if target is None or target["role"] == "admin":
        return redirect(url_for("admin_users"))
    db.set_user_excel_access(user_id, request.form.get("can_view_excel_sheet") == "on")
    return redirect(url_for("admin_users"))


# ============================================================
# Excel Sheet workspace -- a small self-contained spreadsheet editor stored
# entirely in this dashboard's own database. Unrelated to SSH/Logstash
# monitoring; global, not tied to any server (see excel_sheet table comment
# in db.py and excel_viewer_required above).
# ============================================================

MAX_GRID_ROWS = 500
MAX_GRID_COLS = 100


def _validate_grid(payload):
    """Returns (grid, error_message). error_message is None on success."""
    if not isinstance(payload, dict) or not isinstance(payload.get("rows"), list):
        return None, "Malformed sheet data."
    rows = payload["rows"]
    if len(rows) > MAX_GRID_ROWS:
        return None, f"Too many rows (max {MAX_GRID_ROWS})."
    cleaned_rows = []
    for row in rows:
        if not isinstance(row, list):
            return None, "Malformed sheet data."
        if len(row) > MAX_GRID_COLS:
            return None, f"Too many columns (max {MAX_GRID_COLS})."
        cleaned_row = []
        for cell in row:
            if not isinstance(cell, dict):
                cell = {}
            cleaned_row.append({
                "v": str(cell.get("v", ""))[:10000],
                "bg": cell.get("bg") if isinstance(cell.get("bg"), str) else None,
                "fg": cell.get("fg") if isinstance(cell.get("fg"), str) else None,
            })
        cleaned_rows.append(cleaned_row)
    return {"rows": cleaned_rows}, None


@app.route("/excel")
@excel_viewer_required
def excel_sheets_list():
    return render_template("excel_sheets.html", sheets=db.list_excel_sheets(), active="excel")


@app.route("/excel/new", methods=["POST"])
@excel_viewer_required
def excel_new():
    name = (request.form.get("name") or "").strip() or "Untitled sheet"
    grid = db.excel_default_grid()
    sheet_id = db.create_excel_sheet(name, json.dumps(grid), current_user()["id"])
    return redirect(url_for("excel_editor", sheet_id=sheet_id))


def _parse_uploaded_workbook(uploaded):
    """Shared by excel_upload (new sheet) and excel_import_into (replace an
    existing sheet's content). Returns (grid, error_flash_message) -- exactly
    one of the two is None."""
    if uploaded is None or not uploaded.filename:
        return None, "Choose a .xlsx file to import."
    if not uploaded.filename.lower().endswith((".xlsx", ".xlsm")):
        return None, "Only .xlsx/.xlsm Excel files are supported."

    try:
        grid = excel_utils.workbook_to_grid(uploaded.stream)
    except ValueError as exc:
        return None, str(exc)

    grid, error = _validate_grid(grid)
    if error:
        return None, f"That file is too large to import: {error}"

    return grid, None


@app.route("/excel/upload", methods=["POST"])
@excel_viewer_required
def excel_upload():
    """Imports an uploaded .xlsx as a brand-new sheet (see excel_import_into
    for importing into a sheet that's already open)."""
    uploaded = request.files.get("file")
    grid, error = _parse_uploaded_workbook(uploaded)
    if error:
        flash(error, "error")
        return redirect(url_for("excel_sheets_list"))

    name = uploaded.filename.rsplit(".", 1)[0]
    sheet_id = db.create_excel_sheet(name, json.dumps(grid), current_user()["id"])
    flash(f"Imported '{name}'.", "success")
    return redirect(url_for("excel_editor", sheet_id=sheet_id))


@app.route("/excel/<sheet_id>/import", methods=["POST"])
@excel_viewer_required
def excel_import_into(sheet_id):
    """Imports an uploaded .xlsx directly into the sheet that's currently
    open, replacing its content -- the editor's own "Import" button, distinct
    from excel_upload's "start a new sheet from a file" on the list page."""
    if db.get_excel_sheet(sheet_id) is None:
        flash("That sheet no longer exists.", "error")
        return redirect(url_for("excel_sheets_list"))

    uploaded = request.files.get("file")
    grid, error = _parse_uploaded_workbook(uploaded)
    if error:
        flash(error, "error")
        return redirect(url_for("excel_editor", sheet_id=sheet_id))

    db.update_excel_sheet_data(sheet_id, json.dumps(grid))
    flash(f"Imported '{uploaded.filename}' into this sheet.", "success")
    return redirect(url_for("excel_editor", sheet_id=sheet_id))


@app.route("/excel/<sheet_id>")
@excel_viewer_required
def excel_editor(sheet_id):
    sheet = db.get_excel_sheet(sheet_id)
    if sheet is None:
        flash("That sheet no longer exists.", "error")
        return redirect(url_for("excel_sheets_list"))
    grid = json.loads(sheet["data_json"])
    return render_template("excel_editor.html", sheet=sheet, grid=grid, active="excel")


@app.route("/excel/<sheet_id>/save", methods=["POST"])
@excel_viewer_required
def excel_save(sheet_id):
    if db.get_excel_sheet(sheet_id) is None:
        return jsonify({"error": "Sheet not found."}), 404

    payload = request.get_json(silent=True)
    grid, error = _validate_grid(payload or {})
    if error:
        return jsonify({"error": error}), 400

    db.update_excel_sheet_data(sheet_id, json.dumps(grid))
    return jsonify({"ok": True})


@app.route("/excel/<sheet_id>/rename", methods=["POST"])
@excel_viewer_required
def excel_rename(sheet_id):
    if db.get_excel_sheet(sheet_id) is None:
        return redirect(url_for("excel_sheets_list"))
    name = (request.form.get("name") or "").strip()
    if name:
        db.rename_excel_sheet(sheet_id, name)
    return redirect(url_for("excel_editor", sheet_id=sheet_id))


@app.route("/excel/<sheet_id>/delete", methods=["POST"])
@excel_viewer_required
def excel_delete(sheet_id):
    db.delete_excel_sheet(sheet_id)
    flash("Sheet deleted.", "success")
    return redirect(url_for("excel_sheets_list"))


@app.route("/excel/<sheet_id>/export")
@excel_viewer_required
def excel_export(sheet_id):
    sheet = db.get_excel_sheet(sheet_id)
    if sheet is None:
        flash("That sheet no longer exists.", "error")
        return redirect(url_for("excel_sheets_list"))

    grid = json.loads(sheet["data_json"])
    buf = excel_utils.grid_to_workbook_bytes(grid)
    safe_name = re.sub(r"[^A-Za-z0-9_-]+", "_", sheet["name"]).strip("_") or "sheet"
    return send_file(
        buf,
        as_attachment=True,
        download_name=f"{safe_name}.xlsx",
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
