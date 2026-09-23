import io
import json
import re
import shlex

import paramiko

SERVICE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.@:\\-]+\.service$")

# Default location of Logstash's own log file -- same default already shown
# in the Pipeline Logs page's path field (see index.html). Used as the
# fallback for the Elasticsearch Errors view and the background alert
# checker alike, so both stay in sync if this ever needs to change.
DEFAULT_LOGSTASH_LOG_PATH = "/var/log/logstash/logstash-plain.log"

# Matches the Elasticsearch *output* plugin's own log line for a rejected
# bulk request -- e.g. "413 Payload Too Large" when a batch is bigger than
# the target cluster (or a proxy in front of it) will accept, or "429 Too
# Many Requests". This is deliberately narrow (logger name + ":code=>") so it
# doesn't also match unrelated grok/dateparse failures elsewhere in the log.
# Run server-side via `grep -inE` (see SSHManager.read_log_file), so this must
# stay valid POSIX extended-regex, not just Python re syntax.
ES_BULK_ERROR_GREP = r"logstash\.outputs\.elasticsearch.*:code=>[0-9]+"

# Python-side parsing against one already-grepped line, to pull out the
# fields the Elasticsearch Errors view/alert actually display. Split into
# independent pieces (head/code/host/content_length) rather than one long
# sequential regex, because the :url=>"..." value in this message isn't
# reliably quote-delimited -- some Elasticsearch clients embed a literal
# "%22" (a URL-encoded quote) inside the query string instead of escaping
# it, which would otherwise swallow everything up to the *next* real quote
# (typically the empty :body=>"" further along the line) into the url
# capture, and silently drop content_length along with it. Searching for
# each field independently sidesteps that instead of trying to out-clever a
# message format this dashboard doesn't control.
# read_log_file() runs `grep -n`, which prepends "<linenum>:" to every
# returned line -- the leading (?:\d+:)? here absorbs that so this still
# anchors correctly on the log's own leading "[" instead of never matching.
_ES_ERROR_HEAD_RE = re.compile(
    r"^(?:\d+:)?\[(?P<ts>[^\]]+)\]\[(?P<level>[^\]]+)\]\[[^\]]*elasticsearch[^\]]*\]\[(?P<pipeline>[^\]]+)\]"
)
_ES_ERROR_CODE_RE = re.compile(r":code=>(\d+)")
_ES_ERROR_HOST_RE = re.compile(r':url=>"https?://([^/:"]+)')
_ES_ERROR_CONTENT_LENGTH_RE = re.compile(r":content_length=>(\d+)")


def parse_es_bulk_errors(raw_text):
    """Pulls structured fields (pipeline id, target ES host, HTTP code,
    content length) out of Logstash's own log lines for Elasticsearch-output
    bulk-request rejections (the lines ES_BULK_ERROR_GREP matches). Pure text
    parsing -- no SSH, no network, just regex over whatever read_log_file()
    already fetched read-only from the target host.

    A line missing the bracketed head or a :code=> is skipped rather than
    raising -- a slightly different Logstash log format on some version
    should mean fewer/no rows here, not a broken page. :url=>/:content_length=>
    are best-effort (None if absent or unparseable) for the same reason."""
    records = []
    for line in raw_text.splitlines():
        line = line.strip()
        head = _ES_ERROR_HEAD_RE.match(line)
        code_match = _ES_ERROR_CODE_RE.search(line)
        if not head or not code_match:
            continue
        host_match = _ES_ERROR_HOST_RE.search(line)
        length_match = _ES_ERROR_CONTENT_LENGTH_RE.search(line)
        records.append({
            "timestamp": head.group("ts"),
            "pipeline_id": head.group("pipeline"),
            "code": int(code_match.group(1)),
            "host": host_match.group(1) if host_match else "unknown",
            "content_length": int(length_match.group(1)) if length_match else None,
            # Strip grep -n's "<linenum>:" prefix for display -- it's already
            # served its purpose (letting the head regex anchor past it above).
            "raw": re.sub(r"^\d+:", "", line),
        })
    return records


def aggregate_es_bulk_errors(records):
    """Groups parsed error records (see parse_es_bulk_errors) by
    (pipeline, host, code) -- one row per distinct failure pattern instead of
    one per log line, with a count plus first/last-seen and a sample line.
    Assumes records are already in chronological (oldest-first) order, which
    is how `grep pattern file | tail -n N` returns them -- so the first
    record seen for a key is its first_seen and every later one updates
    last_seen, with no extra sorting needed."""
    groups = {}
    for r in records:
        key = (r["pipeline_id"], r["host"], r["code"])
        g = groups.get(key)
        if g is None:
            groups[key] = g = {
                "pipeline_id": r["pipeline_id"],
                "host": r["host"],
                "code": r["code"],
                "count": 0,
                "first_seen": r["timestamp"],
                "last_seen": r["timestamp"],
                "sample": r["raw"],
                "sample_content_length": r["content_length"],
            }
        g["count"] += 1
        g["last_seen"] = r["timestamp"]
    return sorted(groups.values(), key=lambda g: -g["count"])

KEY_CLASSES = (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey)


def load_private_key(key_text, passphrase=None):
    """Parses a pasted private key (any common format) into a paramiko key object."""
    last_exc = None
    for key_cls in KEY_CLASSES:
        try:
            return key_cls.from_private_key(io.StringIO(key_text), password=passphrase or None)
        except paramiko.SSHException as exc:
            last_exc = exc
    raise ValueError(f"Could not parse private key ({last_exc})")


class SSHManager:
    """One live SSH connection to a target Linux server, scoped to systemctl read/start/stop only.

    Credentials are kept in memory only (never written to disk) for the lifetime of the
    connection, so a dropped transport can be transparently reconnected.
    """

    def __init__(self, host, port, username, password=None, private_key=None, sudo_password=None):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.private_key = private_key
        # Falls back to the login password so password-auth users don't have to enter it twice.
        self.sudo_password = sudo_password or password
        self._client = None

    def _connect(self):
        if self._client is not None:
            transport = self._client.get_transport()
            if transport is not None and transport.is_active():
                return self._client
            self._client.close()

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self.host,
            port=self.port,
            username=self.username,
            password=self.password,
            pkey=self.private_key,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        self._client = client
        return client

    def close(self):
        if self._client is not None:
            self._client.close()
            self._client = None

    def run_command(self, command):
        client = self._connect()
        stdin, stdout, stderr = client.exec_command(command, timeout=15)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return out, err, exit_code

    def run_privileged_command(self, command):
        """Runs `command` via sudo, feeding the sudo password over stdin instead of
        requiring passwordless sudo to be pre-configured on the target server."""
        if not self.sudo_password:
            raise RuntimeError(
                "No sudo password available. Enter one on the login page, or set up "
                "passwordless sudo for systemctl on the target server."
            )

        client = self._connect()
        stdin, stdout, stderr = client.exec_command(f"sudo -S -p '' {command}", timeout=15)
        stdin.write(self.sudo_password + "\n")
        stdin.flush()
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return out, err, exit_code

    def list_services(self):
        out, err, code = self.run_command(
            "systemctl list-units --type=service --all --no-pager --plain"
        )
        if code != 0:
            raise RuntimeError(f"Failed to list services: {err.strip() or out.strip()}")

        services = {}
        for line in out.splitlines():
            line = line.strip()
            if not line or line.startswith("UNIT"):
                continue
            if line[0].isdigit():
                # Reached the "N loaded units listed." footer line.
                break

            parts = line.split(None, 4)
            if len(parts) < 4:
                continue

            name, load, active, sub = parts[0], parts[1], parts[2], parts[3]
            if not name.endswith(".service"):
                continue

            services[name] = {
                "name": name,
                "load": load,
                "active": active,
                "sub": sub,
                "description": parts[4] if len(parts) > 4 else "",
            }

        # systemd unloads (garbage-collects) units that aren't enabled/referenced shortly
        # after they stop, so a manually created test service can vanish from
        # `list-units` entirely once stopped. list-unit-files enumerates every service
        # unit file on disk regardless of runtime load state, so merge it in to keep
        # such services visible (shown as inactive until started again).
        out2, err2, code2 = self.run_command(
            "systemctl list-unit-files --type=service --no-legend --no-pager"
        )
        if code2 == 0:
            for line in out2.splitlines():
                line = line.strip()
                if not line:
                    continue
                name = line.split(None, 1)[0]
                if name.endswith(".service") and name not in services:
                    services[name] = {
                        "name": name,
                        "load": "not-loaded",
                        "active": "inactive",
                        "sub": "dead",
                        "description": "",
                    }

        return sorted(services.values(), key=lambda s: s["name"])

    def service_details(self, name):
        """Returns properties that explain whether something besides this dashboard
        could restart the service: its Restart= policy and any socket/path/timer
        units set to trigger it (socket activation is the classic reason a service
        comes back seconds after a clean `systemctl stop`)."""
        self._validate_service_name(name)
        props = "Id,LoadState,ActiveState,SubState,UnitFileState,Restart,TriggeredBy,PartOf,RequiredBy,WantedBy,FragmentPath"
        out, err, code = self.run_command(
            f"systemctl show {shlex.quote(name)} -p {props} --no-pager"
        )
        if code != 0:
            raise RuntimeError(f"Failed to get details: {err.strip() or out.strip()}")

        details = {}
        for line in out.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                details[key] = value
        return details

    def read_log_file(self, path, lines=200, grep=None):
        """Reads the last N lines of a log file. If `grep` is given, it's run as a
        real (case-insensitive, extended-regex) grep on the remote host BEFORE the
        tail -- i.e. "last N matching lines", not "last N lines then filtered" --
        so an ERROR that scrolled off screen minutes ago still surfaces. The pattern
        is shell-quoted as a single argument, so arbitrary regex content is safe
        from shell injection (it's just passed to grep -E, never interpreted by
        the shell)."""
        if not path or not path.startswith("/"):
            raise ValueError("Path must be an absolute path (e.g. /var/log/app.log).")

        lines = max(10, min(int(lines), 2000))
        quoted = shlex.quote(path)

        if grep:
            command = f"grep -inE -- {shlex.quote(grep)} {quoted} | tail -n {lines}"
        else:
            command = f"tail -n {lines} -- {quoted}"

        out, err, code = self.run_command(command)
        # A piped command's exit code reflects `tail`, not `grep`, so "no lines
        # matched" (grep exit 1) never looks like a failure here -- only a real
        # error (bad path, permission denied) does, surfaced via stderr text.
        if code != 0 or "Permission denied" in err:
            out, err, code = self.run_privileged_command(command)
            if code != 0:
                raise RuntimeError(f"Failed to read log: {err.strip() or out.strip()}")

        if grep and not out.strip() and err.strip():
            raise RuntimeError(f"grep failed: {err.strip()}")

        return out

    def logstash_stats(self, api_port=9600):
        """Pulls pipeline health + in/out metrics from the Logstash Monitoring API
        via curl run *on the target host* -- this deliberately never opens an HTTP
        connection from the dashboard server itself, keeping the SSH-only trust
        boundary this app is built around.

        Tries http://localhost:<port>/ first (the common case -- api.http.host is
        127.0.0.1 or 0.0.0.0). Some hosts instead pin api.http.host to their own
        external IP, which makes "localhost" unreachable even from the same box;
        rather than requiring a logstash.yml edit + restart on a production node,
        we fall back to curling this connection's own host/IP (self.host) before
        giving up -- that's the same address api.http.host would be pinned to."""
        try:
            port = int(api_port)
        except (TypeError, ValueError):
            raise ValueError("API port must be a number.")

        candidates = ["localhost"] if self.host == "localhost" else ["localhost", self.host]
        root_out = root_err = ""
        root_code = 1
        base_host = None
        for candidate in candidates:
            root_out, root_err, root_code = self.run_command(f"curl -s -m 5 http://{candidate}:{port}/")
            if root_code == 0 and root_out.strip():
                base_host = candidate
                break

        if base_host is None:
            tried = " or ".join(f"{c}:{port}" for c in candidates)
            raise RuntimeError(
                f"Could not reach the Logstash monitoring API on {tried} "
                f"({root_err.strip() or 'no response'}). Confirm api.enabled / api.http.host / "
                f"api.http.port in logstash.yml and that curl is installed on the target host."
            )

        stats_out, stats_err, stats_code = self.run_command(f"curl -s -m 5 http://{base_host}:{port}/_node/stats")
        if stats_code != 0 or not stats_out.strip():
            raise RuntimeError(f"Failed to fetch /_node/stats: {stats_err.strip() or 'no response'}")

        # workers/batch_size are pipeline *config*, not runtime stats. On some Logstash
        # versions/builds they show up nested under a "pipeline" sub-object inside each
        # /_node/stats pipeline entry (confirmed on a live 8.19.5 node) -- but on others
        # (confirmed on a live k8-es-ls01 node) that sub-object is simply absent from
        # /_node/stats entirely, on any pipeline. Relying on /_node/stats alone silently
        # produced "workers": None for every pipeline there -> everything reported as
        # DOWN even though Logstash was actively processing (JDBC input logs showed
        # queries running fine). /_node/pipelines is the dedicated config endpoint that
        # has always carried these fields, keyed the same way as /_node/stats.pipelines,
        # so we fetch it too and prefer it -- falling back to the nested stats field
        # (or nothing) if this second call fails, rather than hard-erroring the whole
        # status page over a config-only endpoint.
        pipelines_cfg_out, pipelines_cfg_err, pipelines_cfg_code = self.run_command(
            f"curl -s -m 5 http://{base_host}:{port}/_node/pipelines"
        )
        pipeline_cfgs = {}
        if pipelines_cfg_code == 0 and pipelines_cfg_out.strip():
            try:
                pipeline_cfgs = json.loads(pipelines_cfg_out).get("pipelines") or {}
            except ValueError:
                pass  # fall through to the per-pipeline nested-stats fallback below

        try:
            node = json.loads(root_out)
            stats = json.loads(stats_out)
        except ValueError as exc:
            raise RuntimeError(f"Unexpected (non-JSON) response from monitoring API: {exc}")

        pipelines = {}
        for pipeline_id, p in (stats.get("pipelines") or {}).items():
            events = p.get("events") or {}
            reloads = p.get("reloads") or {}
            queue = p.get("queue") or {}
            pipeline_cfg = pipeline_cfgs.get(pipeline_id) or p.get("pipeline") or {}
            pipelines[pipeline_id] = {
                "workers": pipeline_cfg.get("workers"),
                "batch_size": pipeline_cfg.get("batch_size"),
                "events_in": events.get("in", 0),
                "events_filtered": events.get("filtered", 0),
                "events_out": events.get("out", 0),
                "duration_in_millis": events.get("duration_in_millis", 0),
                "queue_push_duration_in_millis": events.get("queue_push_duration_in_millis", 0),
                "queue_type": queue.get("type", "memory"),
                # the field is "events_count", not "events" -- same silent-None/0 trap as workers above.
                "queue_events": queue.get("events_count", 0),
                "reload_successes": reloads.get("successes", 0),
                "reload_failures": reloads.get("failures", 0),
                "reload_last_error": reloads.get("last_error"),
            }

        return {
            "status": node.get("status", "unknown"),
            "name": node.get("name"),
            "version": node.get("version"),
            "http_address": node.get("http_address"),
            "uptime_seconds": (stats.get("jvm") or {}).get("uptime_in_millis", 0) // 1000,
            "pipelines": pipelines,
        }

    def _validate_service_name(self, name):
        if not SERVICE_NAME_RE.match(name):
            raise ValueError(f"Invalid service name: {name!r}")

    def start_service(self, name):
        self._validate_service_name(name)
        return self.run_privileged_command(f"systemctl start {shlex.quote(name)}")

    def stop_service(self, name):
        self._validate_service_name(name)
        return self.run_privileged_command(f"systemctl stop {shlex.quote(name)}")

    def restart_service(self, name):
        self._validate_service_name(name)
        return self.run_privileged_command(f"systemctl restart {shlex.quote(name)}")

    def service_status(self, name):
        self._validate_service_name(name)
        out, err, code = self.run_command(f"systemctl is-active {shlex.quote(name)}")
        return out.strip()
