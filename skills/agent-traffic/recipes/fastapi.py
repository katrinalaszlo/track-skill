"""Track on FastAPI or Starlette. Copy this file into your app as track.py. Standard library only.

    from track import TrackMiddleware
    app.add_middleware(TrackMiddleware, account_id_of=lambda scope: scope.get("state", {}).get("account_id"))

account_id_of(scope) returns the customer id your auth resolved, or None. In FastAPI the usual way is one line in the
auth dependency: request.state.account_id = user.id (request.state is scope["state"]).

It sends one event per request to Track after the response, built the way the @katrinalaszlo/track Express
middleware builds it, so names, redacted paths and hashes match across stacks:
  name        the route pattern: GET /v1/notes/{note_id} -> notes_note_id, POST /notes -> notes_post, no route -> unmatched
  path        the request path without the query string, secret-looking segments replaced by :token
  account_id  HMAC-SHA256 of the customer id under AGENT_TRAFFIC_ACCOUNT_SALT
  ip_hash     HMAC-SHA256 of the client address under a key that changes every UTC day (an IPv6 address as its /64)
Reads AGENT_TRAFFIC_KEY, AGENT_TRAFFIC_ACCOUNT_SALT and, optionally, AGENT_TRAFFIC_PROJECT_ID and
AGENT_TRAFFIC_ENDPOINT from the environment, else from .env in the working directory. The key and salt are never
logged. Behind a proxy, scope["client"] is the proxy's address unless your server is started to trust forwarded
headers (uvicorn --proxy-headers).
"""
import atexit
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import queue
import re
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

ENDPOINT = "https://alg.katrinalaszlo.com"
BATCH_MAX = 25
FLUSH_SECONDS = 1.0
SEND_TIMEOUT_SECONDS = 5
RETRIES_MAX = 3
QUEUE_MAX = 5000
PATH_MAX = 2048
IP_HASH_CONTEXT = "agent-traffic ip_hash v1"

log = logging.getLogger("track")

TOKEN_ROUTE = re.compile(
    r"^(auth|invite|invites|invitation|invitations|magic|magic-link|reset|reset-password|password-reset|token|tokens"
    r"|verify|verify-email|verification|confirm|activate)$",
    re.IGNORECASE,
)
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)


def read_setting(name):
    if os.environ.get(name):
        return os.environ[name]
    if not os.path.exists(".env"):
        return None
    with open(".env") as env_file:
        for line in env_file:
            if line.startswith(name + "="):
                return line.split("=", 1)[1].strip().strip("\"'")
    return None


def event_name(route_path, method):
    """The route pattern as a name, by the middleware's rule: "api" and version segments (v1) are dropped, every
    other segment is split into words, the method is added unless it is GET or HEAD."""
    if route_path is None:
        return "unmatched"
    segments = [s for s in route_path.lower().split("/") if s != "api" and not re.fullmatch(r"v\d+", s)]
    words = [w for s in segments for w in re.split(r"[^a-z0-9]+", s) if w]
    if method not in ("GET", "HEAD"):
        words.append(method.lower())
    name = re.sub(r"^[^a-z]+", "", "_".join(words))
    return re.sub(r"_+$", "", (name or "root")[:64])


def looks_like_secret(segment, after_token_route):
    """A JWT, 32 or more hex characters, or 20 or more base64url characters with a letter and a digit that are mixed
    case or have no - or _. Right after a word like /invite/ or /reset/ the bar is lower: a uuid, or 16 characters."""
    if after_token_route and UUID.match(segment):
        return True
    s = re.sub(r"(=|%3D)+$", "", segment, flags=re.IGNORECASE)
    if re.fullmatch(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", s):
        return True
    if re.fullmatch(r"[0-9a-fA-F]+", s):
        return len(s) >= (16 if after_token_route else 32)
    if len(s) < (16 if after_token_route else 20) or not re.fullmatch(r"[A-Za-z0-9_-]+", s):
        return False
    if not re.search(r"[0-9]", s) or not re.search(r"[A-Za-z]", s):
        return False
    return bool((re.search(r"[A-Z]", s) and re.search(r"[a-z]", s)) or not re.search(r"[-_]", s))


def redact_path(path):
    segments = path.split("/")
    return "/".join(
        ":token" if looks_like_secret(segment, i > 0 and bool(TOKEN_ROUTE.match(segments[i - 1]))) else segment
        for i, segment in enumerate(segments)
    )


def hash_account_id(account_id, salt):
    return hmac.new(salt.encode(), str(account_id).encode(), hashlib.sha256).hexdigest()


def ip_for_hash(ip):
    """The text that is hashed: an IPv4 address as is (also written as ::ffff:a.b.c.d), an IPv6 address as its first
    four groups and ::/64. None when it is not an IP address."""
    if not isinstance(ip, str):
        return None
    text = ip.strip().split("%")[0]
    if text.lower().startswith("::ffff:") and "." in text:
        text = text[7:]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.version == 4:
        return str(address)
    return ":".join(format(int(group, 16), "x") for group in address.exploded.split(":")[:4]) + "::/64"


def hash_ip(ip, salt, occurred_at):
    """occurred_at is the event's ISO time; its UTC date picks the day key."""
    address = ip_for_hash(ip)
    if address is None:
        return None
    day_key = hmac.new(salt.encode(), (IP_HASH_CONTEXT + " " + occurred_at[:10]).encode(), hashlib.sha256).digest()
    return hmac.new(day_key, address.encode(), hashlib.sha256).hexdigest()


class TrackMiddleware:
    """ASGI middleware. account_id_of(scope) returns the customer id auth resolved, or None."""

    def __init__(self, app, account_id_of=None):
        self.app = app
        self.account_id_of = account_id_of
        self.key = read_setting("AGENT_TRAFFIC_KEY")
        self.salt = read_setting("AGENT_TRAFFIC_ACCOUNT_SALT")
        project_id = read_setting("AGENT_TRAFFIC_PROJECT_ID")
        endpoint = (read_setting("AGENT_TRAFFIC_ENDPOINT") or ENDPOINT).rstrip("/")
        self.url = endpoint + "/v1/events" + ("?project_id=" + project_id if project_id else "")
        self.pending = queue.Queue(maxsize=QUEUE_MAX)
        if not self.key:
            log.warning("track: AGENT_TRAFFIC_KEY is not set, so no events are sent")
            return
        if not self.salt:
            log.warning("track: AGENT_TRAFFIC_ACCOUNT_SALT is not set, so no account ids and no ip_hash are sent")
        threading.Thread(target=self._send_loop, daemon=True).start()
        atexit.register(self.flush)

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or not self.key:
            await self.app(scope, receive, send)
            return
        occurred_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        # 500 unless the app answers: an exception that escapes it is a server error.
        status = {"code": 500}

        async def send_and_keep_status(message):
            if message["type"] == "http.response.start":
                status["code"] = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_and_keep_status)
        finally:
            try:
                self.pending.put_nowait(self.build_event(scope, status["code"], occurred_at))
            except queue.Full:
                log.warning("track: %d events are waiting to be sent, so this one is dropped", QUEUE_MAX)
            except Exception:
                # The request is already answered: the event is lost, the response is not. Path only, never the query.
                log.exception("track: event not recorded for %s %s", scope.get("method"), redact_path(scope.get("path", "")))

    def build_event(self, scope, status_code, occurred_at):
        headers = {name.decode("latin-1").lower(): value.decode("latin-1") for name, value in scope["headers"]}
        route = scope.get("route")
        path = scope.get("path")
        event = {
            "idempotency_key": str(uuid.uuid4()),
            "name": event_name(getattr(route, "path", None), scope["method"]),
            "occurred_at": occurred_at,
            "source": "sdk",
            "properties": {"status_code": status_code, "method": scope["method"]},
        }
        if isinstance(path, str) and path.startswith("/") and len(path) <= PATH_MAX:
            event["path"] = redact_path(path)
        for field, header in (("user_agent", "user-agent"), ("accept_language", "accept-language"), ("signature_agent", "signature-agent")):
            if header in headers:
                event[field] = headers[header]
        account_id = self.account_id_of(scope) if self.account_id_of else None
        if account_id and self.salt:
            event["account_id"] = hash_account_id(account_id, self.salt)
        client = scope.get("client")
        if client and self.salt:
            ip_hash = hash_ip(client[0], self.salt, occurred_at)
            if ip_hash:
                event["ip_hash"] = ip_hash
        return event

    def _send_loop(self):
        while True:
            time.sleep(FLUSH_SECONDS)
            self.flush()

    def flush(self):
        while not self.pending.empty():
            batch = []
            while len(batch) < BATCH_MAX and not self.pending.empty():
                batch.append(self.pending.get())
            self.post(batch)

    def post(self, batch):
        request = urllib.request.Request(
            self.url,
            data=json.dumps(batch).encode(),
            headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json"},
            method="POST",
        )
        failure = None
        for attempt in range(1, RETRIES_MAX + 1):
            try:
                with urllib.request.urlopen(request, timeout=SEND_TIMEOUT_SECONDS) as response:
                    answer = json.loads(response.read())
                rejected = [entry.get("reason") for entry in answer.get("rejected", []) if entry.get("reason") != "duplicate"]
                if rejected:
                    log.warning("track: %d of %d events rejected: %s", len(rejected), len(batch), ", ".join(sorted(set(map(str, rejected)))))
                return
            except urllib.error.HTTPError as error:
                failure = "%s %s" % (error.code, error.read().decode(errors="replace")[:300])
                # A 4xx other than 429 will fail the same way again, so it is not retried.
                if error.code < 500 and error.code != 429:
                    log.warning("track: batch of %d dropped: %s", len(batch), failure)
                    return
            except OSError as error:
                failure = str(error)
            if attempt < RETRIES_MAX:
                log.warning("track: batch of %d failed (%s), retrying", len(batch), failure)
                time.sleep(FLUSH_SECONDS * 2 ** attempt)
        log.warning("track: batch of %d dropped after %d attempts: %s", len(batch), RETRIES_MAX, failure)
