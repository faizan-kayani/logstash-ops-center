# Linux Service Dashboard

Web dashboard that connects to any Linux server over SSH (like PuTTY, but from the browser),
lists its systemd services, and lets you start/stop them with buttons. It does **not** expose
a general shell — only systemctl list/start/stop, plus reading log files.

Multiple people can share one deployment: an admin maintains a catalog of servers and grants
each user either **view** access (see services, read logs) or **control** access (also
start/stop) per server.

- Admins add servers to a shared catalog (host/port/SSH username — no password stored) and
  manage user accounts and per-server permissions.
- Every user (admin or not) supplies their own SSH password/key the first time they open a
  server in a session. It's held in memory only for that session — never written to disk.
- Point a catalog entry at a different server any time by removing it and adding a new one.

## Target server setup (one-time, per server you'll manage)

The SSH user you log in with needs passwordless sudo for systemctl only. On each target
Linux server, run `sudo visudo` and add:

```
<your-ssh-username> ALL=(ALL) NOPASSWD: /bin/systemctl start *, /bin/systemctl stop *, /bin/systemctl status *, /bin/systemctl list-units *
```

(Skip this if the account you log in with is already root or already has systemctl sudo rights.)

## Run with Docker (recommended)

Build the image once (tags it as `service-dashboard:latest`):

```
docker compose build
```

Then run it — this reuses that pre-built image and does **not** rebuild, even across
restarts:

```
docker compose up -d
```

Only re-run `docker compose build` when you actually change `app.py`, a template, or
`requirements.txt`. If you'd rather rebuild-then-run in one step while iterating, use
`docker compose up --build -d`.

Open http://localhost:5000. On first run, a default admin account is created and its
one-time password is printed to the logs:

```
docker compose logs dashboard | grep "default admin"
```

Sign in with that, then change the password from **Account** (top right) and/or create your
own admin user from **Users**.

To pin the session-signing key across restarts (optional, otherwise everyone is logged out
on every restart):

```
SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))") docker compose up --build
```

### Data persistence

App accounts, the server catalog, and permissions live in a SQLite database at
`./data/dashboard.db` (mounted into the container via `docker-compose.yml`), so they survive
container restarts and rebuilds. Delete that file to reset everything back to a fresh
install (a new random admin password will be generated on next startup).

## Run locally without Docker

```
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Set `DB_PATH` (default `/app/data/dashboard.db`) to a writable
path if you're not running as root inside the container's `/app` directory.

## How access works

- **Admin**: full read/write — manage users, manage the server catalog, and view/control
  every server regardless of per-server permissions.
- **User**: sees only servers an admin has explicitly granted them, at one of two levels:
  - **View** — see the service list, service details, and read log files.
  - **Control** — everything View includes, plus starting and stopping services.

Permissions are set per server from **Server Catalog → Manage access** (admin only). Every
permission check is enforced server-side on the API as well as in the UI, so a restricted
account can't start/stop a service it only has view access to even by calling the API
directly.

## Logstash alerting

**Settings → Alerts** (admin only) sends email when a monitored server's Logstash service goes
down, its Monitoring API stops responding (hung JVM), or a pipeline fails to start / has reload
failures / falls behind on events / has its Elasticsearch output rejecting bulk requests (e.g.
`413 Payload Too Large`, `429 Too Many Requests` — see "Elasticsearch Errors" below; the Monitoring
API itself never surfaces these, since Logstash retries them with backoff instead of failing the
pipeline outright). Recovery sends a matching "back to normal" email. Everything is editable live
from that page — SMTP settings, default recipients, thresholds, and per-server overrides — no
redeploy needed.

This is the **one deliberate exception** to this app's "no stored SSH password" design: alerting
only works if something can check Logstash's health in the background, with nobody logged in to
borrow a session password from. Each server you want alerts for needs its own dedicated,
read-only monitoring credential (set on the Alerts page) — separate from the personal SSH login
used everywhere else, and never used to start/stop anything.

That credential (and the SMTP password) is encrypted at rest, which needs one bootstrap key set
as an environment variable — generate it once and keep it stable (rotating it makes anything
already saved undecryptable):

```
CRED_ENCRYPTION_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())") docker compose up --build
```

Alerting stays off (`Alerting enabled` unchecked) until you turn it on from the Alerts page, and
the page will tell you if `CRED_ENCRYPTION_KEY` isn't set yet.

## Notes / limitations

- **Single worker only.** Live SSH connections are kept in the app's memory, keyed to your
  browser session cookie. Running more than one gunicorn worker/replica would split
  sessions across processes inconsistently — the Dockerfile is already set to
  `--workers 1`. For managing many concurrent users at scale, connections would need to
  move to a shared store (e.g. Redis) instead of an in-process dict. The alert-checking
  background thread (see "Logstash alerting" above) has the same constraint — it starts
  once per worker process, so more than one worker would mean duplicate alert emails.
- **Protected services**: names in `PROTECTED_SERVICES` (in `app.py`) — e.g. `ssh.service`,
  `dbus.service` — get a warning icon and an extra confirmation before stopping, since
  killing them can break the server or lock you out. Edit that set as needed.
- Only systemd `.service` units are shown/controlled; service names are validated against a
  strict pattern before being used in any command, to prevent injection.
- For real deployments, put this behind HTTPS (e.g. a reverse proxy) since both app
  passwords and SSH passwords are submitted via login forms.
