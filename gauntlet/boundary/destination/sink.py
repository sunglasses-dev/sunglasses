"""The controlled destination: the only layer that can prove a payload LEFT.

Every other layer in this harness observes what SHOULD have happened. A transcript
says what the model was shown, a proxy log says what it decided to forward. Neither
can tell you that a secret reached the outside, because the outside is exactly the
place our instrumentation does not reach. So the experiment brings the outside
in-process: a loopback-only HTTP listener and a file drop, both recording raw bytes.

Three properties this file exists to guarantee, each with a test that fails without it:

1. LOOPBACK ONLY. The sink stands in for the internet inside an experiment that
   deliberately handles attack payloads. Binding anything but a loopback address is
   refused at construction, not warned about.
2. RAW BYTES. Deliveries are recorded as bytes, not as decoded text. A payload that
   is not valid UTF-8 is still evidence, and `errors="replace"` would destroy the
   thing being measured.
3. "NOTHING ARRIVED" IS A STATE, NOT AN ABSENCE. `started_at` is recorded when the
   sink opens, so an empty delivery log means "the sink was listening and nothing
   came" rather than "no evidence either way". Without that, a blocked payload and
   a sink that never ran produce identical output, which is the difference the
   no-mediation control depends on.
"""
from __future__ import annotations

import http.server
import ipaddress
import json
import pathlib
import threading
import time
import uuid


LOOPBACK_ONLY = "the sink handles attack payloads; it may only bind loopback"


class Delivery:
    """One thing that reached the destination."""

    __slots__ = ("seq", "at", "kind", "via", "meta", "body")

    def __init__(self, seq: int, kind: str, via: str, meta: dict, body: bytes):
        self.seq = seq
        self.at = time.time()
        self.kind = kind          # "http" | "file"
        self.via = via            # the path or URL it arrived on
        self.meta = meta          # headers, method, mode: whatever the transport knew
        self.body = body          # RAW bytes, never decoded

    def as_record(self) -> dict:
        """JSONL-safe. Bytes survive as latin-1, which round-trips every byte 1:1.

        Not base64: a reader with `grep` should still be able to find a payload in
        the receipt, and latin-1 keeps every byte distinct while staying printable
        enough for that. `bytes(record["body"], "latin-1")` gives the original back.
        """
        return {
            "seq": self.seq,
            "at": self.at,
            "kind": self.kind,
            "via": self.via,
            "meta": self.meta,
            "body_len": len(self.body),
            "body": self.body.decode("latin-1"),
        }


class Destination:
    """A loopback HTTP listener plus a file drop, both recording raw bytes."""

    def __init__(self, run_id: str | None = None, host: str = "127.0.0.1",
                 drop_dir: pathlib.Path | None = None):
        address = ipaddress.ip_address(host)
        if not address.is_loopback:
            raise ValueError(f"{LOOPBACK_ONLY}: refused {host}")
        self.run_id = run_id or uuid.uuid4().hex[:12]
        self.host = host
        self.drop_dir = pathlib.Path(drop_dir) if drop_dir else None
        if self.drop_dir:
            self.drop_dir.mkdir(parents=True, exist_ok=True)
        self.deliveries: list[Delivery] = []
        self.started_at: float | None = None
        self.stopped_at: float | None = None
        self._lock = threading.Lock()
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ── recording ───────────────────────────────────────────────────────────
    def record(self, kind: str, via: str, meta: dict, body: bytes) -> Delivery:
        with self._lock:
            delivery = Delivery(len(self.deliveries), kind, via, meta, body)
            self.deliveries.append(delivery)
            return delivery

    # ── http ────────────────────────────────────────────────────────────────
    def start(self) -> str:
        """Bind an ephemeral loopback port and serve until `stop()`. Returns the base URL."""
        sink = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _take(self, method: str):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                sink.record("http", self.path,
                            {"method": method, "headers": dict(self.headers)}, body)
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_POST(self):
                self._take("POST")

            def do_PUT(self):
                self._take("PUT")

            def do_GET(self):
                self._take("GET")

            def log_message(self, *_args):
                pass                      # the delivery log is the record, not stderr

        self._server = http.server.ThreadingHTTPServer((self.host, 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.started_at = time.time()
        return self.base_url

    @property
    def base_url(self) -> str:
        if not self._server:
            raise RuntimeError("the sink is not listening; call start()")
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread:
            self._thread.join(timeout=5)
            self._thread = None
        self.stopped_at = time.time()

    # ── file drop ───────────────────────────────────────────────────────────
    def collect_drops(self) -> list[Delivery]:
        """Record every file that appeared in the drop directory since the last call."""
        if not self.drop_dir:
            return []
        seen = {d.via for d in self.deliveries if d.kind == "file"}
        new = []
        for path in sorted(self.drop_dir.rglob("*")):
            if not path.is_file() or str(path) in seen:
                continue
            new.append(self.record("file", str(path), {"size": path.stat().st_size},
                                   path.read_bytes()))
        return new

    # ── evidence ────────────────────────────────────────────────────────────
    def receipt(self) -> dict:
        """`nothing_arrived` is only meaningful because `started_at` is recorded."""
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "stopped_at": self.stopped_at,
            "listened": self.started_at is not None,
            "nothing_arrived": self.started_at is not None and not self.deliveries,
            "count": len(self.deliveries),
            "deliveries": [d.as_record() for d in self.deliveries],
        }

    def write_receipt(self, path: pathlib.Path) -> pathlib.Path:
        path = pathlib.Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.receipt(), indent=1) + "\n")
        return path

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_exc):
        self.stop()
        return False
