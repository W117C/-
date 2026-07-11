"""OOB (Out-of-Band) callback infrastructure for vulnerability confirmation.

Provides a minimal HTTP callback server for confirming SSRF, Blind-XSS, and
other out-of-band vulnerabilities. The server can run in two modes:

  1. Embedded mode — started during scan, shut down after verification window
  2. Standalone mode — long-running on a public IP, polled by SecAgent

Design constraints:
  - Uses only Python stdlib (no Flask/FastAPI dependency)
  - Single-file server (~100 lines) for easy deployment
  - Callback records persist to a JSONL file for crash recovery
  - Thread-safe: HTTP handler runs in a background thread

Client-side flow:
  1. Scan dispatches payload with unique callback ID: http://callback-host/{id}
  2. Finding recorded with status="pending_verification"
  3. User polls GET /poll/{id} after a delay
  4. If callback arrived, finding is promoted to confirmed
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class CallbackRecord:
    """Represents a single OOB callback event."""

    def __init__(
        self,
        callback_id: str,
        source_ip: str,
        method: str,
        path: str,
        headers: dict[str, str],
        body: str = "",
        timestamp: dt.datetime | None = None,
    ):
        self.callback_id = callback_id
        self.source_ip = source_ip
        self.method = method
        self.path = path
        self.headers = headers
        self.body = body[:1000]  # Cap body size
        self.timestamp = timestamp or dt.datetime.now(dt.timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        return {
            "callback_id": self.callback_id,
            "source_ip": self.source_ip,
            "method": self.method,
            "path": self.path,
            "headers": self.headers,
            "body": self.body,
            "timestamp": self.timestamp.isoformat(),
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CallbackRecord:
        return CallbackRecord(
            callback_id=d["callback_id"],
            source_ip=d["source_ip"],
            method=d["method"],
            path=d["path"],
            headers=d.get("headers", {}),
            body=d.get("body", ""),
            timestamp=dt.datetime.fromisoformat(d["timestamp"]),
        )


class CallbackStore:
    """Thread-safe persistent store for OOB callbacks.

    Backed by a JSONL file so records survive process restarts and
    can be tailed for analysis.
    """

    def __init__(self, storage_path: str | Path):
        self.storage_path = Path(storage_path)
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._index: dict[str, list[CallbackRecord]] = {}
        self._load()

    def _load(self) -> None:
        """Load existing records from disk."""
        if not self.storage_path.exists():
            return
        with open(self.storage_path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    rec = CallbackRecord.from_dict(obj)
                    self._index.setdefault(rec.callback_id, []).append(rec)
                except (json.JSONDecodeError, KeyError):
                    continue

    def add(self, record: CallbackRecord) -> None:
        """Add a callback record (in-memory + append to disk)."""
        with self._lock:
            self._index.setdefault(record.callback_id, []).append(record)
            with open(self.storage_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(record.to_dict()) + "\n")

    def get(self, callback_id: str) -> list[CallbackRecord]:
        """Get all callback records for a given ID."""
        with self._lock:
            return list(self._index.get(callback_id, []))

    def has_callback(self, callback_id: str) -> bool:
        """Return True if any callback was received for this ID."""
        with self._lock:
            return callback_id in self._index and len(self._index[callback_id]) > 0

    def cleanup(self, max_age_seconds: int = 3600) -> int:
        """Remove records older than max_age_seconds. Returns count removed."""
        cutoff = dt.datetime.now(dt.timezone.utc).timestamp() - max_age_seconds
        removed = 0
        with self._lock:
            new_index: dict[str, list[CallbackRecord]] = {}
            for cid, records in self._index.items():
                kept = [r for r in records if r.timestamp.timestamp() > cutoff]
                removed += len(records) - len(kept)
                if kept:
                    new_index[cid] = kept
            self._index = new_index
            # Rewrite disk file
            with open(self.storage_path, "w", encoding="utf-8") as f:
                for records in new_index.values():
                    for r in records:
                        f.write(json.dumps(r.to_dict()) + "\n")
        return removed


# Global in-memory fallback for tests (when no file path given)
_global_store: dict[str, list[CallbackRecord]] = {}


def _handler_factory(store: CallbackStore):
    """Create a request handler class bound to a specific store."""
    class OOBHandler(BaseHTTPRequestHandler):
        """Handle incoming OOB callbacks (HTTP GET/POST/HEAD/etc)."""

        def log_message(self, format, *args):
            """Silence default stderr logging."""
            pass

        def _handle(self):
            """Common handler for all HTTP methods."""
            path = self.path
            # Extract callback_id from path: /{callback_id}/...
            parts = path.strip("/").split("/")
            callback_id = parts[0] if parts and parts[0] else "unknown"

            # Read body for POST requests
            content_length = int(self.headers.get("Content-Length", 0))
            body = ""
            if content_length > 0:
                body = self.rfile.read(content_length).decode("utf-8", "replace")

            record = CallbackRecord(
                callback_id=callback_id,
                source_ip=self.client_address[0],
                method=self.command,
                path=path,
                headers=dict(self.headers),
                body=body,
            )
            store.add(record)
            log.info("OOB callback received: id=%s from %s %s", callback_id, self.client_address[0], self.command)

            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")

        def do_GET(self):
            self._handle()

        def do_POST(self):
            self._handle()

        def do_HEAD(self):
            self._handle()

        def do_PUT(self):
            self._handle()

    return OOBHandler


class CallbackServer:
    """Minimal HTTP server for receiving OOB callbacks.

    Usage:
        server = CallbackServer(port=8080)  # store_path defaults to tempdir
        server.start()  # Non-blocking
        # ... run scan ...
        records = server.poll("abc123")
        server.stop()
    """

    def __init__(
        self,
        port: int = 8080,
        host: str = "0.0.0.0",
        store_path: str | Path | None = None,
    ):
        self.port = port
        self.host = host
        if store_path is None:
            import tempfile
            store_path = tempfile.mktemp(prefix="secagent_oob_", suffix=".jsonl")
        self.store = CallbackStore(store_path)
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        """Start the server in a background thread.

        Passing ``port=0`` lets the OS assign a free port; the resolved port
        is written back to ``self.port`` so callers can build callback URLs.
        """
        handler = _handler_factory(self.store)
        self._server = HTTPServer((self.host, self.port), handler)
        # If port was 0, the OS picked one — capture it for URL generation.
        if self.port == 0:
            self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        log.info("OOB CallbackServer listening on %s:%d", self.host, self.port)

    def stop(self) -> None:
        """Stop the server."""
        if self._server:
            self._server.shutdown()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None

    def poll(self, callback_id: str, timeout: float = 0) -> list[CallbackRecord]:
        """Check if callback arrived for a given ID.

        If timeout > 0, block until callback arrives or timeout expires.
        """
        deadline = time.monotonic() + timeout
        while True:
            records = self.store.get(callback_id)
            if records:
                return records
            if time.monotonic() >= deadline:
                return []
            time.sleep(0.5)

    def has_callback(self, callback_id: str) -> bool:
        return self.store.has_callback(callback_id)

    def get(self, callback_id: str) -> list[CallbackRecord]:
        """Get all callback records for a given ID (delegates to store)."""
        return self.store.get(callback_id)

    def get_url(self, callback_id: str, public_host: str | None = None) -> str:
        """Generate a callback URL for injection.

        Args:
            callback_id: Unique ID for this callback
            public_host: Public hostname (if None, uses local IP)
        """
        host = public_host or self._get_local_ip()
        return f"http://{host}:{self.port}/{callback_id}"

    @staticmethod
    def _get_local_ip() -> str:
        """Determine local IP for URL generation."""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except OSError:
            return "127.0.0.1"


def generate_callback_id() -> str:
    """Generate a unique callback ID (URL-safe)."""
    return uuid.uuid4().hex[:12]


def create_callback_url(public_url: str, callback_id: str) -> str:
    """Create a full callback URL from a public base URL.

    Args:
        public_url: e.g. "https://callbacks.example.com"
        callback_id: unique ID for this scan

    Returns:
        Full URL: "https://callbacks.example.com/{callback_id}"
    """
    base = public_url.rstrip("/")
    return f"{base}/{callback_id}"
