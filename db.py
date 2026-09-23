import os
import sqlite3
import time
import uuid

DB_PATH = os.environ.get("DB_PATH", "/app/data/dashboard.db")

ROLES = ("admin", "user")


def _escape_like(value):
    """Escapes %, _, and \\ in a string bound into a LIKE pattern, so free-text
    search input can't be mistaken for SQL LIKE wildcards."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _connect():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_column(conn, table, column, definition):
    """Adds `column` to `table` if it's missing -- SQLite has no portable
    'ADD COLUMN IF NOT EXISTS', so check PRAGMA table_info first. Lets old
    deployments upgrade in place on next startup instead of needing a
    migration script."""
    existing = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in existing:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def init_db():
    """Creates tables if they don't exist yet. Safe to call on every startup."""
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL CHECK (role IN ('admin', 'user')),
                created_at    INTEGER NOT NULL
            )
        """)
        # Global (not per-server) grant letting a non-admin user see the Active
        # Alerts panel -- open/pending issues across every monitored server, plus
        # the manual "Resolve" button. Deliberately does NOT cover the Email
        # settings or Per-server monitoring tabs (SMTP credentials and per-server
        # monitoring passwords stay admin-only) -- those remain gated by
        # @admin_required regardless of this flag.
        _ensure_column(conn, "users", "can_view_active_alerts", "INTEGER NOT NULL DEFAULT 0")
        # Global (not per-server) grant letting a non-admin user open the Excel
        # Sheet workspace (see excel_sheet table below) -- same shape as
        # can_view_active_alerts above: off by default, admin opts a user in
        # from the Users page.
        _ensure_column(conn, "users", "can_view_excel_sheet", "INTEGER NOT NULL DEFAULT 0")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS servers (
                id         TEXT PRIMARY KEY,
                label      TEXT,
                host       TEXT NOT NULL,
                port       INTEGER NOT NULL,
                username   TEXT NOT NULL,
                created_by INTEGER,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
            )
        """)
        # Alerting add-ons for an existing server row -- all optional/nullable.
        # monitor_username/monitor_password_enc are a SEPARATE credential from
        # the personal SSH login users type in each session: the background
        # alert checker has no user session to borrow one from, so it needs
        # its own standing (encrypted) credential, used only for read-only
        # health checks -- never for start/stop. Blank overrides fall back to
        # the global defaults in alert_config.
        _ensure_column(conn, "servers", "monitor_username", "TEXT")
        _ensure_column(conn, "servers", "monitor_password_enc", "TEXT")
        _ensure_column(conn, "servers", "service_name_override", "TEXT")
        _ensure_column(conn, "servers", "alert_recipients_override", "TEXT")
        # Per-user, per-server grants for non-admin accounts. Admins bypass this
        # table entirely (they can see/control every server). can_view covers
        # seeing the service list and reading logs; can_control additionally
        # allows starting/stopping services.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS permissions (
                user_id    INTEGER NOT NULL,
                server_id  TEXT NOT NULL,
                can_view   INTEGER NOT NULL DEFAULT 0,
                can_control INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (user_id, server_id),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            )
        """)
        # Independent per-server grants for the three Logstash monitoring pages --
        # previously any user with can_view above saw all of Pipeline Status /
        # Reload-Config-Errors / Pipeline Logs automatically, with no way to grant
        # just "Start / Stop Services" and nothing else. All default OFF, so
        # existing grants don't silently widen: a user who could already see
        # everything before this column existed sees only Start/Stop Services
        # until an admin explicitly ticks these too.
        _ensure_column(conn, "permissions", "can_view_pipeline_status", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "permissions", "can_view_pipeline_errors", "INTEGER NOT NULL DEFAULT 0")
        _ensure_column(conn, "permissions", "can_view_pipeline_logs", "INTEGER NOT NULL DEFAULT 0")
        # Elasticsearch Errors page (added after the other three) -- same
        # independent, default-OFF grant treatment as above.
        _ensure_column(conn, "permissions", "can_view_pipeline_es_errors", "INTEGER NOT NULL DEFAULT 0")
        # Fine-grained escape hatch: a user with can_view but not can_control on a
        # server can still be handed start/stop rights on individual services here,
        # instead of all-or-nothing control over the whole server.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS service_permissions (
                user_id      INTEGER NOT NULL,
                server_id    TEXT NOT NULL,
                service_name TEXT NOT NULL,
                PRIMARY KEY (user_id, server_id, service_name),
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            )
        """)
        # Local history of Logstash pipeline stats -- one row per pipeline per read.
        # Populated only as a side effect of the dashboard actually fetching live
        # stats over an existing SSH connection (see db.record_logstash_snapshot /
        # app.api_logstash_stats); there is no standing connection or background
        # poller, so coverage only exists for windows when someone had a given
        # server's Logstash page open. This is local-only bookkeeping for the
        # dashboard's own history/time-range filter -- it is never written back to
        # the target server.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logstash_snapshots (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id         TEXT NOT NULL,
                pipeline_id       TEXT NOT NULL,
                captured_at       INTEGER NOT NULL,
                node_status       TEXT,
                workers           INTEGER,
                events_in         INTEGER,
                events_filtered   INTEGER,
                events_out        INTEGER,
                queue_type        TEXT,
                queue_events      INTEGER,
                reload_failures   INTEGER,
                reload_last_error TEXT,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_logstash_snapshots_lookup
            ON logstash_snapshots (server_id, pipeline_id, captured_at)
        """)

        # Audit log of every start/stop/restart the dashboard has actually performed
        # (via api_start_service / api_stop_service / api_restart_service) -- who,
        # what, when, and whether it succeeded. Local-only bookkeeping, same as
        # logstash_snapshots above; this never reaches back out to the target
        # server, it just records what the dashboard itself did over the SSH
        # connection it already had open.
        #
        # 'restart' was added to the allowed actions after this table already
        # shipped with a CHECK restricted to ('start', 'stop') -- SQLite can't
        # ALTER a CHECK constraint in place, so an existing table with the old
        # constraint needs a rebuild (rename -> recreate -> copy -> drop) rather
        # than a plain CREATE TABLE IF NOT EXISTS, which would silently no-op and
        # leave 'restart' inserts failing on old deployments.
        existing = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'service_action_log'"
        ).fetchone()
        needs_restart_migration = existing is not None and "'restart'" not in existing["sql"]
        if needs_restart_migration:
            # If a previous run of this migration got interrupted partway (e.g. the
            # process was killed between the rename and the final DROP below), a
            # stale "_old" table can be left behind -- clear it first so a retry on
            # next startup doesn't fail with "already another table with this name"
            # and permanently wedge the migration.
            conn.execute("DROP TABLE IF EXISTS service_action_log_old")
            conn.execute("DROP INDEX IF EXISTS idx_service_action_log_lookup")
            conn.execute("ALTER TABLE service_action_log RENAME TO service_action_log_old")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS service_action_log (
                id             INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id      TEXT NOT NULL,
                service_name   TEXT NOT NULL,
                action         TEXT NOT NULL CHECK (action IN ('start', 'stop', 'restart')),
                performed_at   INTEGER NOT NULL,
                performed_by   INTEGER,
                performed_by_username TEXT,
                success        INTEGER NOT NULL,
                message        TEXT,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE,
                FOREIGN KEY (performed_by) REFERENCES users (id) ON DELETE SET NULL
            )
        """)

        if needs_restart_migration:
            conn.execute("""
                INSERT INTO service_action_log
                    (id, server_id, service_name, action, performed_at, performed_by, performed_by_username, success, message)
                SELECT id, server_id, service_name, action, performed_at, performed_by, performed_by_username, success, message
                FROM service_action_log_old
            """)
            conn.execute("DROP TABLE service_action_log_old")

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_service_action_log_lookup
            ON service_action_log (server_id, service_name, performed_at)
        """)

        # Single-row (id=1) global alerting config -- SMTP settings, default
        # recipients, and check thresholds. Deliberately a DB table (not env
        # vars) so an admin can change any of it live from the Alerts settings
        # page without touching the deployment. The one thing that CAN'T live
        # here is the encryption key protecting smtp_password_enc -- that has
        # to be a bootstrap env var (CRED_ENCRYPTION_KEY), same as SECRET_KEY.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_config (
                id                          INTEGER PRIMARY KEY CHECK (id = 1),
                enabled                     INTEGER NOT NULL DEFAULT 0,
                smtp_host                   TEXT,
                smtp_port                   INTEGER DEFAULT 587,
                smtp_username               TEXT,
                smtp_password_enc           TEXT,
                smtp_use_tls                INTEGER NOT NULL DEFAULT 1,
                from_name                   TEXT,
                from_address                TEXT,
                default_recipients          TEXT,
                check_interval_minutes      INTEGER NOT NULL DEFAULT 5,
                event_gap_threshold         INTEGER NOT NULL DEFAULT 100,
                consecutive_checks_required INTEGER NOT NULL DEFAULT 2,
                default_service_name        TEXT NOT NULL DEFAULT 'logstash.service',
                updated_at                  INTEGER
            )
        """)
        conn.execute("INSERT OR IGNORE INTO alert_config (id, enabled) VALUES (1, 0)")
        # How often (minutes) to re-send a "still open" reminder for an alert
        # that's been open a while -- 0/NULL disables reminders entirely. Added
        # after alert_config already shipped, so it's a migration not a fresh
        # column default like the others above.
        #
        # reminder_interval_minutes covers 'service'/'api' scope alerts (kept
        # under its original name so existing deployments' configured value
        # carries over unchanged); reminder_interval_schedule_minutes covers
        # 'pipeline_schedule'; reminder_interval_gap_minutes covers 'pipeline'
        # (event-gap / reload-failure / failed-to-start). Split into three so
        # e.g. a fast 1-minute reminder on service-down doesn't also mean
        # getting spammed every minute for a slow-moving pipeline backlog.
        _ensure_column(conn, "alert_config", "reminder_interval_minutes", "INTEGER NOT NULL DEFAULT 30")
        _ensure_column(conn, "alert_config", "reminder_interval_schedule_minutes", "INTEGER NOT NULL DEFAULT 30")
        _ensure_column(conn, "alert_config", "reminder_interval_gap_minutes", "INTEGER NOT NULL DEFAULT 30")
        # Optional separate recipient list for 'service' scope alerts only (Logstash
        # systemd down/recovered) -- lets service outages route to a different group
        # than API/pipeline/schedule alerts. NULL/blank means "use default_recipients",
        # so existing deployments keep today's single-list behavior untouched.
        _ensure_column(conn, "alert_config", "service_recipients", "TEXT")

        # Tracks currently-open alerts so the checker only emails on a state
        # TRANSITION (healthy->unhealthy, then unhealthy->healthy for
        # recovery) instead of every single check, and so it knows how many
        # consecutive checks an event-gap has persisted before it crosses
        # consecutive_checks_required. scope is 'service' (systemd down),
        # 'api' (monitoring API unresponsive -- JVM hung sentinel), 'pipeline'
        # (pipeline_id set -- failed to start / reload failure / event backlog),
        # or 'pipeline_schedule' (pipeline_id set -- missed its configured
        # expected run interval, see pipeline_schedule table below); one open
        # row per (server, scope, pipeline_id).
        #
        # 'pipeline_schedule' was added after this table already shipped with a
        # CHECK missing that value -- same rebuild-in-place migration as
        # service_action_log's 'restart' addition above, for the same reason
        # (SQLite can't ALTER a CHECK constraint).
        existing_alert_state = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'alert_state'"
        ).fetchone()
        needs_schedule_scope_migration = existing_alert_state is not None and "'pipeline_schedule'" not in existing_alert_state["sql"]
        if needs_schedule_scope_migration:
            conn.execute("DROP INDEX IF EXISTS idx_alert_state_active")
            conn.execute("ALTER TABLE alert_state RENAME TO alert_state_old")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_state (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id         TEXT NOT NULL,
                scope             TEXT NOT NULL CHECK (scope IN ('service', 'api', 'pipeline', 'pipeline_schedule')),
                pipeline_id       TEXT,
                status            TEXT NOT NULL DEFAULT 'candidate' CHECK (status IN ('candidate', 'open', 'resolved')),
                consecutive_count INTEGER NOT NULL DEFAULT 1,
                detail            TEXT,
                opened_at         INTEGER,
                last_seen_at      INTEGER NOT NULL,
                resolved_at       INTEGER,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            )
        """)

        if needs_schedule_scope_migration:
            conn.execute("""
                INSERT INTO alert_state
                    (id, server_id, scope, pipeline_id, status, consecutive_count, detail, opened_at, last_seen_at, resolved_at)
                SELECT id, server_id, scope, pipeline_id, status, consecutive_count, detail, opened_at, last_seen_at, resolved_at
                FROM alert_state_old
            """)
            conn.execute("DROP TABLE alert_state_old")

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_state_active
            ON alert_state (server_id, scope, pipeline_id)
            WHERE status IN ('candidate', 'open')
        """)
        # Whether the notification email for the current open/resolved state
        # actually sent -- "OPEN" on its own only means "the problem was
        # detected", not "someone was told about it". Without this, a broken
        # SMTP config looks identical to a working one in the Active Alerts
        # panel (both just say "OPEN"), which is confusing until you go dig
        # through container logs.
        _ensure_column(conn, "alert_state", "email_ok", "INTEGER")
        _ensure_column(conn, "alert_state", "email_error", "TEXT")
        # When the last "still open" reminder went out, so the reminder loop
        # knows whether it's due for another one yet (see alert_config's
        # reminder_interval_minutes).
        _ensure_column(conn, "alert_state", "last_reminder_at", "INTEGER")
        # Who manually cleared this via the Active Alerts "Resolve" button, if
        # anyone -- distinguishes an admin override from the checker actually
        # confirming recovery on its own.
        _ensure_column(conn, "alert_state", "resolved_by", "TEXT")

        # 'es_errors' (Elasticsearch-output bulk-request rejections, e.g. 413
        # Payload Too Large -- see alerting.py's _check_server) was added
        # after this table already shipped with a CHECK missing that value --
        # same rebuild-in-place migration as 'pipeline_schedule' above, run
        # here (rather than folded into that one) so it's independent of
        # whether this deployment already had 'pipeline_schedule' or not.
        existing_alert_state_2 = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'alert_state'"
        ).fetchone()
        needs_es_errors_scope_migration = existing_alert_state_2 is not None and "'es_errors'" not in existing_alert_state_2["sql"]
        if needs_es_errors_scope_migration:
            conn.execute("DROP INDEX IF EXISTS idx_alert_state_active")
            conn.execute("ALTER TABLE alert_state RENAME TO alert_state_old2")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS alert_state (
                id                INTEGER PRIMARY KEY AUTOINCREMENT,
                server_id         TEXT NOT NULL,
                scope             TEXT NOT NULL CHECK (scope IN ('service', 'api', 'pipeline', 'pipeline_schedule', 'es_errors')),
                pipeline_id       TEXT,
                status            TEXT NOT NULL DEFAULT 'candidate' CHECK (status IN ('candidate', 'open', 'resolved')),
                consecutive_count INTEGER NOT NULL DEFAULT 1,
                detail            TEXT,
                opened_at         INTEGER,
                last_seen_at      INTEGER NOT NULL,
                resolved_at       INTEGER,
                email_ok          INTEGER,
                email_error       TEXT,
                last_reminder_at  INTEGER,
                resolved_by       TEXT,
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            )
        """)

        if needs_es_errors_scope_migration:
            conn.execute("""
                INSERT INTO alert_state
                    (id, server_id, scope, pipeline_id, status, consecutive_count, detail, opened_at,
                     last_seen_at, resolved_at, email_ok, email_error, last_reminder_at, resolved_by)
                SELECT id, server_id, scope, pipeline_id, status, consecutive_count, detail, opened_at,
                       last_seen_at, resolved_at, email_ok, email_error, last_reminder_at, resolved_by
                FROM alert_state_old2
            """)
            conn.execute("DROP TABLE alert_state_old2")

        conn.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_alert_state_active
            ON alert_state (server_id, scope, pipeline_id)
            WHERE status IN ('candidate', 'open')
        """)

        # Per-pipeline expected-run-interval config + the background checker's
        # own bookkeeping of when each pipeline last actually did something.
        # Rows are created/kept up to date automatically by the alert checker
        # for every pipeline it observes on every monitored server (see
        # alerting.py's record_pipeline_activity) -- an admin never has to
        # register a pipeline by hand, just fill in expected_value/expected_unit
        # for the ones they want watched, via Alerts -> Pipeline Schedules.
        # NULL expected_value = "not monitored for staleness" (the default for
        # every pipeline until an admin opts it in).
        #
        # This is local-only bookkeeping read from the target server's
        # Monitoring API (same as logstash_snapshots/alert_state) -- it is
        # never written back to Logstash or the target server in any way.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pipeline_schedule (
                server_id        TEXT NOT NULL,
                pipeline_id      TEXT NOT NULL,
                expected_value   INTEGER,
                expected_unit    TEXT CHECK (expected_unit IN ('seconds', 'minutes', 'hours', 'days', 'weeks')),
                last_events_out  INTEGER,
                last_activity_at INTEGER,
                last_seen_at     INTEGER NOT NULL,
                PRIMARY KEY (server_id, pipeline_id),
                FOREIGN KEY (server_id) REFERENCES servers (id) ON DELETE CASCADE
            )
        """)

        # Excel Sheet workspace -- a small self-contained spreadsheet editor
        # that lives entirely inside this dashboard's own database. Global
        # (not tied to any server, see users.can_view_excel_sheet above): it
        # has nothing to do with SSH/Logstash monitoring, it's just a shared
        # place for the team to keep and edit a grid of data (e.g. a pipeline
        # run-schedule reference sheet) without leaving the dashboard.
        # data_json holds the whole grid (cell values + per-cell colors) as
        # one JSON blob -- see excel_sheet_default_grid()/the row/cell shape
        # documented next to it -- simpler than a per-cell table for a feature
        # with no need for cross-sheet querying.
        conn.execute("""
            CREATE TABLE IF NOT EXISTS excel_sheet (
                id         TEXT PRIMARY KEY,
                name       TEXT NOT NULL,
                data_json  TEXT NOT NULL,
                created_by INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY (created_by) REFERENCES users (id) ON DELETE SET NULL
            )
        """)
        conn.commit()


def seed_default_admin():
    """Creates a random-password admin account on first run, so there's a way in.
    Returns the plaintext password if one was created, else None."""
    from werkzeug.security import generate_password_hash

    with _connect() as conn:
        existing = conn.execute("SELECT id FROM users LIMIT 1").fetchone()
        if existing is not None:
            return None

        password = uuid.uuid4().hex[:12]
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
            ("admin", generate_password_hash(password), int(time.time())),
        )
        conn.commit()
        return password


# ---------- users ----------

def get_user_by_username(username):
    with _connect() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(user_id):
    with _connect() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def list_users():
    with _connect() as conn:
        return conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()


def create_user(username, password_hash, role):
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, int(time.time())),
        )
        conn.commit()
        return cur.lastrowid


def delete_user(user_id):
    with _connect() as conn:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()


def update_user_password(user_id, password_hash):
    with _connect() as conn:
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (password_hash, user_id))
        conn.commit()


def update_user_role(user_id, role):
    with _connect() as conn:
        conn.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        conn.commit()


def set_user_alert_access(user_id, can_view_active_alerts):
    """Grants/revokes a non-admin user's view of the Active Alerts panel --
    Email settings and Per-server monitoring stay admin-only regardless (see
    the can_view_active_alerts column comment in init_db)."""
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET can_view_active_alerts = ? WHERE id = ?",
            (int(can_view_active_alerts), user_id),
        )
        conn.commit()


def set_user_excel_access(user_id, can_view_excel_sheet):
    """Grants/revokes a non-admin user's access to the Excel Sheet workspace
    (see the can_view_excel_sheet column comment in init_db)."""
    with _connect() as conn:
        conn.execute(
            "UPDATE users SET can_view_excel_sheet = ? WHERE id = ?",
            (int(can_view_excel_sheet), user_id),
        )
        conn.commit()


def count_admins():
    with _connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").fetchone()
        return row["n"]


# ---------- servers (catalog) ----------

def create_server(label, host, port, username, created_by):
    server_id = str(uuid.uuid4())
    with _connect() as conn:
        conn.execute(
            "INSERT INTO servers (id, label, host, port, username, created_by, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (server_id, label, host, port, username, created_by, int(time.time())),
        )
        conn.commit()
    return server_id


def list_servers():
    with _connect() as conn:
        return conn.execute("SELECT * FROM servers ORDER BY created_at").fetchall()


def get_server(server_id):
    with _connect() as conn:
        return conn.execute("SELECT * FROM servers WHERE id = ?", (server_id,)).fetchone()


def delete_server(server_id):
    with _connect() as conn:
        conn.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        conn.commit()


# ---------- permissions ----------

def get_permission(user_id, server_id):
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM permissions WHERE user_id = ? AND server_id = ?",
            (user_id, server_id),
        ).fetchone()


def list_permissions_for_user(user_id):
    with _connect() as conn:
        return conn.execute("SELECT * FROM permissions WHERE user_id = ?", (user_id,)).fetchall()


def list_permissions_for_server(server_id):
    with _connect() as conn:
        return conn.execute(
            "SELECT permissions.*, users.username FROM permissions "
            "JOIN users ON users.id = permissions.user_id "
            "WHERE server_id = ? ORDER BY users.username",
            (server_id,),
        ).fetchall()


def set_permission(user_id, server_id, can_view, can_control,
                    can_view_pipeline_status=False, can_view_pipeline_errors=False, can_view_pipeline_logs=False,
                    can_view_pipeline_es_errors=False):
    with _connect() as conn:
        values = (
            int(can_view), int(can_control),
            int(can_view_pipeline_status), int(can_view_pipeline_errors), int(can_view_pipeline_logs),
            int(can_view_pipeline_es_errors),
        )
        conn.execute(
            "INSERT INTO permissions "
            "(user_id, server_id, can_view, can_control, can_view_pipeline_status, can_view_pipeline_errors, can_view_pipeline_logs, can_view_pipeline_es_errors) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (user_id, server_id) DO UPDATE SET "
            "can_view = ?, can_control = ?, can_view_pipeline_status = ?, can_view_pipeline_errors = ?, can_view_pipeline_logs = ?, can_view_pipeline_es_errors = ?",
            (user_id, server_id) + values + values,
        )
        conn.commit()


def remove_permission(user_id, server_id):
    with _connect() as conn:
        conn.execute("DELETE FROM permissions WHERE user_id = ? AND server_id = ?", (user_id, server_id))
        conn.commit()


# ---------- per-service permissions (fine-grained start/stop grants) ----------

def list_service_permissions(user_id, server_id):
    """Service names this user may start/stop on this server, independent of
    (and in addition to) their server-wide can_control flag."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT service_name FROM service_permissions WHERE user_id = ? AND server_id = ? "
            "ORDER BY service_name",
            (user_id, server_id),
        ).fetchall()
        return [row["service_name"] for row in rows]


def set_service_permissions(user_id, server_id, service_names):
    """Replaces the full set of per-service control grants for this user/server."""
    with _connect() as conn:
        conn.execute(
            "DELETE FROM service_permissions WHERE user_id = ? AND server_id = ?", (user_id, server_id)
        )
        conn.executemany(
            "INSERT INTO service_permissions (user_id, server_id, service_name) VALUES (?, ?, ?)",
            [(user_id, server_id, name) for name in service_names],
        )
        conn.commit()


def has_service_permission(user_id, server_id, service_name):
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM service_permissions WHERE user_id = ? AND server_id = ? AND service_name = ?",
            (user_id, server_id, service_name),
        ).fetchone()
        return row is not None


def list_service_permissions_for_server(server_id):
    """All per-service grants on a server, across users -- for rendering the admin panel."""
    with _connect() as conn:
        return conn.execute(
            "SELECT user_id, service_name FROM service_permissions WHERE server_id = ?",
            (server_id,),
        ).fetchall()


# ---------- Logstash history (local-only; read-side of the target server, never written to it) ----------

SNAPSHOT_RETENTION_SECONDS = 30 * 86400  # 30 days


def record_logstash_snapshot(server_id, node_status, pipelines):
    """Appends one row per pipeline for this read, plus opportunistic pruning of
    anything older than SNAPSHOT_RETENTION_SECONDS so this table doesn't grow
    unbounded. Called after every successful live stats fetch (manual Refresh or
    Auto-refresh) -- this is the only way history accumulates, since there's no
    background poller (see the table comment in init_db)."""
    captured_at = int(time.time())
    rows = []
    for pipeline_id, p in (pipelines or {}).items():
        reload_last_error = p.get("reload_last_error")
        if isinstance(reload_last_error, dict):
            reload_last_error = reload_last_error.get("message")
        rows.append((
            server_id, pipeline_id, captured_at, node_status,
            p.get("workers"), p.get("events_in"), p.get("events_filtered"), p.get("events_out"),
            p.get("queue_type"), p.get("queue_events"), p.get("reload_failures"),
            reload_last_error,
        ))
    if not rows:
        return

    with _connect() as conn:
        conn.executemany(
            "INSERT INTO logstash_snapshots "
            "(server_id, pipeline_id, captured_at, node_status, workers, events_in, events_filtered, "
            "events_out, queue_type, queue_events, reload_failures, reload_last_error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
        conn.execute(
            "DELETE FROM logstash_snapshots WHERE captured_at < ?",
            (captured_at - SNAPSHOT_RETENTION_SECONDS,),
        )
        conn.commit()


def query_logstash_history(server_id, pipeline_id=None, start_ts=None, end_ts=None, limit=2000):
    query = "SELECT * FROM logstash_snapshots WHERE server_id = ?"
    params = [server_id]
    if pipeline_id:
        # Substring match (not exact) -- the UI field is a free-text search box,
        # not a constrained dropdown, so partial pipeline names should work.
        query += " AND pipeline_id LIKE ? ESCAPE '\\'"
        params.append(f"%{_escape_like(pipeline_id)}%")
    if start_ts is not None:
        query += " AND captured_at >= ?"
        params.append(start_ts)
    if end_ts is not None:
        query += " AND captured_at <= ?"
        params.append(end_ts)
    query += " ORDER BY captured_at DESC LIMIT ?"
    params.append(limit)

    with _connect() as conn:
        return conn.execute(query, params).fetchall()


def list_logstash_pipeline_ids(server_id):
    """Distinct pipeline ids this dashboard has ever recorded a snapshot for, on this
    server -- used to populate the history filter's pipeline dropdown."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT DISTINCT pipeline_id FROM logstash_snapshots WHERE server_id = ? ORDER BY pipeline_id",
            (server_id,),
        ).fetchall()
        return [row["pipeline_id"] for row in rows]


# ---------- Service start/stop audit log (local-only; see service_action_log comment in init_db) ----------

SERVICE_ACTION_LOG_RETENTION_SECONDS = 90 * 86400  # 90 days


def record_service_action(server_id, service_name, action, user, success, message=None):
    """Appends one row every time api_start_service/api_stop_service actually runs,
    plus opportunistic pruning of anything older than the retention window. `user`
    is the acting user's db row (or None if somehow unavailable)."""
    performed_at = int(time.time())
    with _connect() as conn:
        conn.execute(
            "INSERT INTO service_action_log "
            "(server_id, service_name, action, performed_at, performed_by, performed_by_username, success, message) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                server_id, service_name, action, performed_at,
                user["id"] if user else None,
                user["username"] if user else "unknown",
                int(bool(success)), message,
            ),
        )
        conn.execute(
            "DELETE FROM service_action_log WHERE performed_at < ?",
            (performed_at - SERVICE_ACTION_LOG_RETENTION_SECONDS,),
        )
        conn.commit()


def query_service_actions(server_id, service_name=None, start_ts=None, end_ts=None, limit=2000):
    query = "SELECT * FROM service_action_log WHERE server_id = ?"
    params = [server_id]
    if service_name:
        # Substring match -- same free-text search box as the Logstash filter.
        query += " AND service_name LIKE ? ESCAPE '\\'"
        params.append(f"%{_escape_like(service_name)}%")
    if start_ts is not None:
        query += " AND performed_at >= ?"
        params.append(start_ts)
    if end_ts is not None:
        query += " AND performed_at <= ?"
        params.append(end_ts)
    query += " ORDER BY performed_at DESC LIMIT ?"
    params.append(limit)

    with _connect() as conn:
        return conn.execute(query, params).fetchall()


def list_service_action_names(server_id):
    """Distinct service names this dashboard has ever logged a start/stop for, on
    this server -- used to populate the history filter's search suggestions."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT DISTINCT service_name FROM service_action_log WHERE server_id = ? ORDER BY service_name",
            (server_id,),
        ).fetchall()
        return [row["service_name"] for row in rows]


# ---------- Alerting: global config (single row, id=1) ----------

def get_alert_config():
    with _connect() as conn:
        return conn.execute("SELECT * FROM alert_config WHERE id = 1").fetchone()


def update_alert_config(**fields):
    """Partial update -- pass only the columns being changed, e.g.
    update_alert_config(enabled=True, smtp_host="..."). Used by the Alerts
    settings page so every field is editable live, no redeploy needed."""
    if not fields:
        return
    columns = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values())
    with _connect() as conn:
        conn.execute(
            f"UPDATE alert_config SET {columns}, updated_at = ? WHERE id = 1",
            values + [int(time.time())],
        )
        conn.commit()


# ---------- Alerting: per-server monitoring credential + overrides ----------

def set_server_monitoring(server_id, monitor_username, monitor_password_enc,
                           service_name_override, alert_recipients_override):
    with _connect() as conn:
        conn.execute(
            "UPDATE servers SET monitor_username = ?, monitor_password_enc = ?, "
            "service_name_override = ?, alert_recipients_override = ? WHERE id = ?",
            (monitor_username, monitor_password_enc, service_name_override,
             alert_recipients_override, server_id),
        )
        conn.commit()


def clear_server_monitoring_credential(server_id):
    """Removes just the stored monitoring credential (e.g. it stopped working),
    leaving the service-name/recipient overrides and the server itself intact."""
    with _connect() as conn:
        conn.execute(
            "UPDATE servers SET monitor_username = NULL, monitor_password_enc = NULL WHERE id = ?",
            (server_id,),
        )
        conn.commit()


def list_open_alert_keys(server_id):
    """(scope, pipeline_id) for every candidate/open alert on this server --
    used when monitoring is turned off for a server, so its stale alerts can be
    resolved instead of sitting open forever (nobody's checking it anymore, so
    nothing will ever naturally clear them) and still firing reminder emails."""
    with _connect() as conn:
        return conn.execute(
            "SELECT scope, pipeline_id FROM alert_state WHERE server_id = ? AND status IN ('candidate', 'open')",
            (server_id,),
        ).fetchall()


def list_servers_with_monitoring():
    """Catalog servers with a monitoring credential configured -- these are the
    ones the background alert checker actually polls each cycle."""
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM servers WHERE monitor_username IS NOT NULL AND monitor_password_enc IS NOT NULL"
        ).fetchall()


# ---------- Alerting: candidate/open alert state (suppression + recovery tracking) ----------

def get_alert_state(server_id, scope, pipeline_id=None):
    with _connect() as conn:
        if pipeline_id is None:
            return conn.execute(
                "SELECT * FROM alert_state WHERE server_id = ? AND scope = ? AND pipeline_id IS NULL "
                "AND status IN ('candidate', 'open')",
                (server_id, scope),
            ).fetchone()
        return conn.execute(
            "SELECT * FROM alert_state WHERE server_id = ? AND scope = ? AND pipeline_id = ? "
            "AND status IN ('candidate', 'open')",
            (server_id, scope, pipeline_id),
        ).fetchone()


def touch_alert_candidate(server_id, scope, pipeline_id, detail, now_ts):
    """Bumps consecutive_count on the existing candidate/open row (or creates a
    new candidate at count=1) every check the problem condition still holds.
    Returns the count *after* this bump, so the caller can compare against
    consecutive_checks_required to decide whether to actually alert yet."""
    with _connect() as conn:
        existing = get_alert_state(server_id, scope, pipeline_id)
        if existing:
            new_count = existing["consecutive_count"] + 1
            conn.execute(
                "UPDATE alert_state SET consecutive_count = ?, detail = ?, last_seen_at = ? WHERE id = ?",
                (new_count, detail, now_ts, existing["id"]),
            )
            conn.commit()
            return new_count
        conn.execute(
            "INSERT INTO alert_state (server_id, scope, pipeline_id, status, consecutive_count, detail, last_seen_at) "
            "VALUES (?, ?, ?, 'candidate', 1, ?, ?)",
            (server_id, scope, pipeline_id, detail, now_ts),
        )
        conn.commit()
        return 1


def mark_alert_open(server_id, scope, pipeline_id, now_ts):
    """Promotes a candidate row to 'open' once it crosses the threshold and the
    alert email has actually been sent."""
    with _connect() as conn:
        if pipeline_id is None:
            conn.execute(
                "UPDATE alert_state SET status = 'open', opened_at = ? "
                "WHERE server_id = ? AND scope = ? AND pipeline_id IS NULL AND status = 'candidate'",
                (now_ts, server_id, scope),
            )
        else:
            conn.execute(
                "UPDATE alert_state SET status = 'open', opened_at = ? "
                "WHERE server_id = ? AND scope = ? AND pipeline_id = ? AND status = 'candidate'",
                (now_ts, server_id, scope, pipeline_id),
            )
        conn.commit()


def resolve_alert_state(server_id, scope, pipeline_id, now_ts, resolved_by=None):
    """Closes an open/candidate alert -- either the checker confirming the
    problem cleared on its own (resolved_by=None), or an admin manually
    clearing it from the Active Alerts "Resolve" button (resolved_by=username).
    Returns the row as it was before resolving (None if there was nothing
    open) so the caller can tell whether a recovery email is actually owed --
    only if the alert had reached 'open' (i.e. was actually sent)."""
    with _connect() as conn:
        row = get_alert_state(server_id, scope, pipeline_id)
        if row is None:
            return None
        conn.execute(
            "UPDATE alert_state SET status = 'resolved', resolved_at = ?, resolved_by = ? WHERE id = ?",
            (now_ts, resolved_by, row["id"]),
        )
        conn.commit()
        return row


def list_open_alert_scopes(server_id):
    """Which of 'service'/'api' currently have an OPEN alert for this server --
    used to suppress pipeline-level checks while that root cause is active."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT DISTINCT scope FROM alert_state "
            "WHERE server_id = ? AND scope IN ('service', 'api') AND status = 'open'",
            (server_id,),
        ).fetchall()
        return {row["scope"] for row in rows}


def list_stale_pipeline_alerts(server_id, current_pipeline_ids, scope="pipeline"):
    """Pipeline-scoped candidate/open alerts (default scope='pipeline'; also
    used with scope='es_errors' -- see alerting.py's _check_server) whose
    pipeline no longer appears in the latest fetch -- e.g. it recovered
    between one check and the next, or was renamed/removed. Returns the
    pipeline ids so the caller can resolve each one."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT pipeline_id FROM alert_state "
            "WHERE server_id = ? AND scope = ? AND status IN ('candidate', 'open')",
            (server_id, scope),
        ).fetchall()
        return [row["pipeline_id"] for row in rows if row["pipeline_id"] not in current_pipeline_ids]


def list_active_alerts():
    """All candidate/open alerts across every server, open-first then most
    recently seen -- for the Alerts page's 'Active Alerts' panel."""
    with _connect() as conn:
        return conn.execute("""
            SELECT alert_state.*, servers.label, servers.host
            FROM alert_state
            JOIN servers ON servers.id = alert_state.server_id
            WHERE alert_state.status IN ('candidate', 'open')
            ORDER BY CASE alert_state.status WHEN 'open' THEN 0 ELSE 1 END, alert_state.last_seen_at DESC
        """).fetchall()


def record_alert_email_result(server_id, scope, pipeline_id, ok, error=None):
    """Records whether the notification email for the CURRENT candidate/open
    row actually sent -- shown in the Active Alerts panel so a broken SMTP
    config doesn't silently look identical to a working one."""
    with _connect() as conn:
        if pipeline_id is None:
            conn.execute(
                "UPDATE alert_state SET email_ok = ?, email_error = ? "
                "WHERE server_id = ? AND scope = ? AND pipeline_id IS NULL AND status IN ('candidate', 'open')",
                (int(bool(ok)), error, server_id, scope),
            )
        else:
            conn.execute(
                "UPDATE alert_state SET email_ok = ?, email_error = ? "
                "WHERE server_id = ? AND scope = ? AND pipeline_id = ? AND status IN ('candidate', 'open')",
                (int(bool(ok)), error, server_id, scope, pipeline_id),
            )
        conn.commit()


def count_open_alerts():
    """Lightweight count for the sidebar badge -- checked on every page load,
    so this stays a single indexed COUNT rather than list_active_alerts()'s
    full join+select."""
    with _connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS n FROM alert_state WHERE status = 'open'").fetchone()
        return row["n"]


def list_open_alerts_for_reminder_check():
    """Every currently-open alert, regardless of type -- the reminder loop
    (alerting.py's _send_reminders) decides per-row whether it's actually due,
    since which reminder-interval config value applies depends on the alert's
    `scope`, which this deliberately dumb query has no opinion on."""
    with _connect() as conn:
        return conn.execute("""
            SELECT alert_state.*, servers.label, servers.host, servers.alert_recipients_override
            FROM alert_state
            JOIN servers ON servers.id = alert_state.server_id
            WHERE alert_state.status = 'open'
              AND alert_state.opened_at IS NOT NULL
        """).fetchall()


def mark_reminder_sent(alert_id, now_ts):
    with _connect() as conn:
        conn.execute("UPDATE alert_state SET last_reminder_at = ? WHERE id = ?", (now_ts, alert_id))
        conn.commit()


# ---------- Pipeline schedule monitoring (read-only; see pipeline_schedule table comment in init_db) ----------

UNIT_SECONDS = {
    "seconds": 1,
    "minutes": 60,
    "hours": 3600,
    "days": 86400,
    "weeks": 604800,
}


def record_pipeline_activity(server_id, pipeline_id, events_out, now_ts):
    """Called by the alert checker every cycle for every pipeline it observes
    (whether or not anyone has configured an expected interval for it yet) --
    this is what makes every pipeline show up on the Pipeline Schedules page
    automatically, and is how "did it just do something" gets tracked.
    Returns the row *after* the update, so the caller has expected_value/unit
    and the (possibly just-refreshed) last_activity_at to evaluate against.
    "Activity" = the out-count changed at all since the last check (covers a
    counter reset from a Logstash restart too, not just increases)."""
    with _connect() as conn:
        existing = conn.execute(
            "SELECT * FROM pipeline_schedule WHERE server_id = ? AND pipeline_id = ?",
            (server_id, pipeline_id),
        ).fetchone()
        if existing is None:
            # First time seeing this pipeline -- seed last_activity_at to now
            # rather than leaving it null, so a newly-discovered pipeline isn't
            # immediately treated as "overdue" the moment someone configures an
            # expected interval for it.
            conn.execute(
                "INSERT INTO pipeline_schedule (server_id, pipeline_id, last_events_out, last_activity_at, last_seen_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (server_id, pipeline_id, events_out, now_ts, now_ts),
            )
        else:
            changed = existing["last_events_out"] is None or events_out != existing["last_events_out"]
            new_activity_at = now_ts if changed else existing["last_activity_at"]
            conn.execute(
                "UPDATE pipeline_schedule SET last_events_out = ?, last_activity_at = ?, last_seen_at = ? "
                "WHERE server_id = ? AND pipeline_id = ?",
                (events_out, new_activity_at, now_ts, server_id, pipeline_id),
            )
        conn.commit()
        return conn.execute(
            "SELECT * FROM pipeline_schedule WHERE server_id = ? AND pipeline_id = ?",
            (server_id, pipeline_id),
        ).fetchone()


def list_pipeline_schedules(server_id):
    """Every pipeline the checker has ever observed for this server, for the
    Pipeline Schedules admin page -- includes ones with no expected interval
    configured yet (expected_value IS NULL), which is most of them until an
    admin opts specific ones in."""
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM pipeline_schedule WHERE server_id = ? ORDER BY pipeline_id",
            (server_id,),
        ).fetchall()


def list_monitored_pipeline_schedules(server_id):
    """Only the pipelines with an expected interval actually configured --
    what the alert checker loops over to decide what to evaluate."""
    with _connect() as conn:
        return conn.execute(
            "SELECT * FROM pipeline_schedule WHERE server_id = ? AND expected_value IS NOT NULL",
            (server_id,),
        ).fetchall()


def set_pipeline_schedule_expected(server_id, pipeline_id, expected_value, expected_unit):
    """expected_value=None clears it (pipeline goes back to "not monitored").
    Upserts in case this is somehow called before the checker has ever
    recorded activity for this pipeline (shouldn't normally happen since the
    UI only lists pipelines the checker already knows about, but a defensive
    upsert costs nothing)."""
    now_ts = int(time.time())
    with _connect() as conn:
        conn.execute(
            "INSERT INTO pipeline_schedule (server_id, pipeline_id, expected_value, expected_unit, last_seen_at) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (server_id, pipeline_id) DO UPDATE SET expected_value = ?, expected_unit = ?",
            (server_id, pipeline_id, expected_value, expected_unit, now_ts, expected_value, expected_unit),
        )
        conn.commit()


def remove_stale_pipeline_schedule(server_id, pipeline_id):
    """Drops bookkeeping for a pipeline that's vanished from the live fetch
    entirely (renamed/removed) -- any open pipeline_schedule alert for it
    should already have been resolved by the caller before this runs."""
    with _connect() as conn:
        conn.execute(
            "DELETE FROM pipeline_schedule WHERE server_id = ? AND pipeline_id = ?",
            (server_id, pipeline_id),
        )
        conn.commit()


# ---------- Excel Sheet workspace (local-only; see excel_sheet table comment in init_db) ----------

def excel_default_grid(rows=10, cols=6):
    """A blank starting grid for a brand-new sheet. Each cell is
    {"v": <text>, "bg": <hex color or None>, "fg": <hex color or None>} --
    see excel.py in app.py for the same shape used by import/export."""
    return {"rows": [[{"v": "", "bg": None, "fg": None} for _ in range(cols)] for _ in range(rows)]}


def list_excel_sheets():
    with _connect() as conn:
        return conn.execute(
            "SELECT s.id, s.name, s.created_at, s.updated_at, s.created_by, u.username AS created_by_username "
            "FROM excel_sheet s LEFT JOIN users u ON u.id = s.created_by "
            "ORDER BY s.updated_at DESC"
        ).fetchall()


def get_excel_sheet(sheet_id):
    with _connect() as conn:
        return conn.execute("SELECT * FROM excel_sheet WHERE id = ?", (sheet_id,)).fetchone()


def create_excel_sheet(name, data_json, created_by):
    sheet_id = str(uuid.uuid4())
    now_ts = int(time.time())
    with _connect() as conn:
        conn.execute(
            "INSERT INTO excel_sheet (id, name, data_json, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (sheet_id, name, data_json, created_by, now_ts, now_ts),
        )
        conn.commit()
    return sheet_id


def update_excel_sheet_data(sheet_id, data_json):
    with _connect() as conn:
        conn.execute(
            "UPDATE excel_sheet SET data_json = ?, updated_at = ? WHERE id = ?",
            (data_json, int(time.time()), sheet_id),
        )
        conn.commit()


def rename_excel_sheet(sheet_id, name):
    with _connect() as conn:
        conn.execute(
            "UPDATE excel_sheet SET name = ?, updated_at = ? WHERE id = ?",
            (name, int(time.time()), sheet_id),
        )
        conn.commit()


def delete_excel_sheet(sheet_id):
    with _connect() as conn:
        conn.execute("DELETE FROM excel_sheet WHERE id = ?", (sheet_id,))
        conn.commit()
