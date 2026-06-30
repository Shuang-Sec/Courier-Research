#!/usr/bin/env python3
"""Tiny HTTP request capture server for local AV/request-shape experiments.

It records every request into a separate directory:
  request-line.txt, headers.json, body.bin, body.sha256, body.entropy.txt, summary.json
"""
from __future__ import annotations

import argparse
import hashlib
import http.server
import json
import math
import os
import pathlib
import socketserver
import sys
import threading
from datetime import datetime, timezone

_COUNTER_LOCK = threading.Lock()
_COUNTER = 0


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class CaptureHandler(http.server.BaseHTTPRequestHandler):
    server_version = "CTFRequestCapture/1.0"

    def _capture(self) -> None:
        global _COUNTER
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length) if length > 0 else b""
        now = utc_now()
        with _COUNTER_LOCK:
            _COUNTER += 1
            idx = _COUNTER
        safe_ts = now.replace(":", "").replace(".", "_")
        req_dir = pathlib.Path(self.server.out_dir) / f"{idx:04d}-{safe_ts}-{self.client_address[0].replace('.', '_')}"
        req_dir.mkdir(parents=True, exist_ok=True)

        headers = {k: v for k, v in self.headers.items()}
        body_sha256 = hashlib.sha256(body).hexdigest()
        summary = {
            "index": idx,
            "timestamp_utc": now,
            "client_ip": self.client_address[0],
            "client_port": self.client_address[1],
            "method": self.command,
            "path": self.path,
            "request_version": self.request_version,
            "headers": headers,
            "body_len": len(body),
            "body_sha256": body_sha256,
            "body_entropy": shannon_entropy(body),
        }

        (req_dir / "request-line.txt").write_text(f"{self.command} {self.path} {self.request_version}\n", encoding="utf-8")
        (req_dir / "headers.json").write_text(json.dumps(headers, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
        (req_dir / "body.bin").write_bytes(body)
        (req_dir / "body.sha256").write_text(body_sha256 + "\n", encoding="ascii")
        (req_dir / "body.entropy.txt").write_text(f"{summary['body_entropy']:.6f}\n", encoding="ascii")
        (req_dir / "summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")

        # Append a JSONL index for quick matrix parsing.
        with _COUNTER_LOCK:
            with open(pathlib.Path(self.server.out_dir) / "requests.jsonl", "a", encoding="utf-8") as f:
                f.write(json.dumps(summary, ensure_ascii=False, sort_keys=True) + "\n")

        response = b"OK\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self) -> None:  # noqa: N802
        self._capture()

    def do_POST(self) -> None:  # noqa: N802
        self._capture()

    def do_HEAD(self) -> None:  # noqa: N802
        self._capture()

    def do_PUT(self) -> None:  # noqa: N802
        self._capture()

    def log_message(self, fmt: str, *args: object) -> None:
        msg = "%s - - [%s] %s\n" % (self.client_address[0], self.log_date_time_string(), fmt % args)
        sys.stderr.write(msg)


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture raw HTTP requests into per-request evidence files.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8001)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args()

    out_dir = pathlib.Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "server-start.json").write_text(
        json.dumps({"timestamp_utc": utc_now(), "host": args.host, "port": args.port, "pid": os.getpid()}, indent=2),
        encoding="utf-8",
    )

    server = ThreadingHTTPServer((args.host, args.port), CaptureHandler)
    server.out_dir = str(out_dir)  # type: ignore[attr-defined]
    print(f"[+] request capture listening on {args.host}:{args.port}, out={out_dir}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
