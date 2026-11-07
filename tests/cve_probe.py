#!/usr/bin/env python3
"""Replay public PHP CVE request shapes against a local proxy and inert upstream.

This tests proxy decisions, not exploitation of a vulnerable application.
All requests are restricted to a loopback listener created by this script.
"""

import hashlib
import http.client
import http.server
import json
import os
import queue
import re
import socket
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar
from urllib.parse import urlencode

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / "target" / "release" / "threat-classifier-proxy"
ANSI = re.compile(r"\x1b\[[0-9;]*m")
DECISION = re.compile(
    r'decision="?(allow|block)"?\s+label=(.*?)\s+score=([0-9.eE+-]+)\s+elapsed_ms=(\d+)'
)
AGENT = "Mozilla/5.0 (X11; Linux x86_64; rv:70.0) Gecko/20100101 Firefox/70.0"


@dataclass(frozen=True)
class Probe:
    name: str
    cve: str
    kind: str
    method: str
    path: str
    body: bytes = b""
    headers: dict[str, str] = field(default_factory=dict)
    chunked: bool = False


def multipart_part(boundary: str, headers: list[str], payload: bytes) -> bytes:
    head = "\r\n".join(headers)
    return f"--{boundary}\r\n{head}\r\n\r\n".encode() + payload + b"\r\n"


def multipart_close(boundary: str) -> bytes:
    return f"--{boundary}--\r\n".encode()


def oom_multipart() -> tuple[bytes, str]:
    """CVE-2026-109618 shape: many part headers, empty files, nested names."""
    boundary = "----incibe-109618"
    headers = [
        'Content-Disposition: form-data; name="a[b][c][d]"',
        *[f"X-Probe-{index}: {'A' * 32}" for index in range(400)],
    ]
    parts = [multipart_part(boundary, headers, b"x")]
    for index in range(40):
        parts.append(
            multipart_part(
                boundary,
                [
                    f'Content-Disposition: form-data; name="f{index}"; filename=""',
                    "Content-Type: application/octet-stream",
                ],
                b"",
            )
        )
    parts.append(multipart_close(boundary))
    return b"".join(parts), boundary


def upload_progress_multipart() -> tuple[bytes, str]:
    """CVE-2026-109619/115560 shape: upload progress plus a file part."""
    boundary = "----incibe-upload-progress"
    body = b"".join(
        [
            multipart_part(
                boundary,
                ['Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"'],
                b"probe",
            ),
            multipart_part(
                boundary,
                [
                    'Content-Disposition: form-data; name="file"; filename="probe.txt"',
                    "Content-Type: text/plain",
                ],
                b"probe",
            ),
            multipart_close(boundary),
        ]
    )
    return body, boundary


def benign_multipart() -> tuple[bytes, str]:
    boundary = "----incibe-benign"
    body = b"".join(
        [
            multipart_part(
                boundary,
                [
                    'Content-Disposition: form-data; name="file"; filename="hello.txt"',
                    "Content-Type: text/plain",
                ],
                b"hello",
            ),
            multipart_close(boundary),
        ]
    )
    return body, boundary


def probes() -> list[Probe]:
    # https://www.incibe.es/incibe-cert/alerta-temprana/avisos/multiples-vulnerabilidades-en-php
    # https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
    # https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
    # https://github.com/php/php-src/security/advisories/GHSA-7qg2-v9fj-4mwv
    # https://github.com/YOURLS/YOURLS/security/advisories/GHSA-f8ff-652m-j5rx
    # https://github.com/Dolibarr/dolibarr/security/advisories/GHSA-v5fq-cf5m-vwv7
    # https://github.com/php/php-src/security/advisories/GHSA-rgrp-mwpx-f6rm
    # https://github.com/symfony/symfony/security/advisories/GHSA-r925-mgvr-h9cc
    # Symfony's fix includes the same 25-space pattern in HeaderUtilsTest.php.
    oom_body, oom_boundary = oom_multipart()
    upload_body, upload_boundary = upload_progress_multipart()
    benign_body, benign_boundary = benign_multipart()
    form = [
        ("action", "update"),
        ("token", "CSRF_TOKEN"),
        ("socid", "1"),
        ("name", "TestCompany"),
        ("status", "1"),
        ("localtax1assuj_value", "1"),
        ("lt1", "1"),
        ("client", "1"),
        ("typent_id", "0"),
    ]
    injection = list(form)
    injection[6] = (
        "lt1",
        "1,note_private=(SELECT pass_crypted FROM llx_user WHERE rowid=1)",
    )
    form_headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Cookie": "PHPSESSID=local-test-session",
    }
    soap_start = (
        '<?xml version="1.0"?><SOAP-ENV:Envelope '
        'xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/">'
        "<SOAP-ENV:Body>"
    )
    soap_end = "</SOAP-ENV:Body></SOAP-ENV:Envelope>"
    soap_small = (soap_start + "<a>ok</a>" + soap_end).encode()
    soap_deep = (soap_start + "<a>" * 50_000 + "</a>" * 50_000 + soap_end).encode()
    return [
        Probe("fpm-control", "CVE-2026-6735", "control", "GET", "/hello"),
        Probe("fpm-xss", "CVE-2026-6735", "attack", "GET", "/<script>alert()</script>"),
        Probe(
            "fpm-xss-encoded",
            "CVE-2026-6735",
            "variant",
            "GET",
            "/%3Cscript%3Ealert()%3C/script%3E",
        ),
        Probe("fpm-status", "CVE-2026-6735", "control", "GET", "/status?full&html"),
        Probe("yourls-control", "CVE-2026-62858", "control", "GET", "/test"),
        Probe("yourls-traversal", "CVE-2026-62858", "attack", "GET", "/../../test"),
        Probe(
            "dolibarr-control",
            "CVE-2026-33944",
            "control",
            "POST",
            "/societe/card.php?socid=1",
            urlencode(form).encode(),
            form_headers,
        ),
        Probe(
            "dolibarr-sqli",
            "CVE-2026-33944",
            "attack",
            "POST",
            "/societe/card.php?socid=1",
            urlencode(injection).encode(),
            form_headers,
        ),
        Probe(
            "soap-control",
            "CVE-2026-91765",
            "control",
            "POST",
            "/soap-endpoint.php",
            soap_small,
            {"Content-Type": "text/xml"},
        ),
        Probe(
            "soap-50000-levels",
            "CVE-2026-91765",
            "attack",
            "POST",
            "/soap-endpoint.php",
            soap_deep,
            {"Content-Type": "text/xml"},
        ),
        Probe(
            "symfony-control",
            "CVE-2026-108082",
            "control",
            "GET",
            "/",
            headers={"Cache-Control": "a,b"},
        ),
        Probe(
            "symfony-redos",
            "CVE-2026-108082",
            "attack",
            "GET",
            "/",
            headers={"Cache-Control": "a" + " " * 25 + ",b"},
        ),
        Probe(
            "php-multipart-benign",
            "CVE-2026-109618",
            "control",
            "POST",
            "/upload.php",
            benign_body,
            {"Content-Type": f"multipart/form-data; boundary={benign_boundary}"},
        ),
        Probe(
            "php109618-oom-multipart",
            "CVE-2026-109618",
            "attack",
            "POST",
            "/index.php",
            oom_body,
            {"Content-Type": f"multipart/form-data; boundary={oom_boundary}"},
        ),
        Probe(
            "php109618-chunked",
            "CVE-2026-109618",
            "attack",
            "POST",
            "/index.php",
            oom_body,
            {"Content-Type": f"multipart/form-data; boundary={oom_boundary}"},
            chunked=True,
        ),
        Probe(
            "php109619-upload-progress",
            "CVE-2026-109619/CVE-2026-115560",
            "attack",
            "POST",
            "/upload.php",
            upload_body,
            {
                "Content-Type": f"multipart/form-data; boundary={upload_boundary}",
                "Cookie": "PHPSESSID=local-test-session",
            },
            chunked=True,
        ),
    ]


class InertUpstream(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    received: ClassVar[dict[str, dict]] = {}

    def do_GET(self) -> None:
        self.record()

    def do_POST(self) -> None:
        self.record()

    def record(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        InertUpstream.received[self.headers["X-Lab-Case"]] = {
            "method": self.command,
            "path": self.path,
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "cache_control": self.headers.get("Cache-Control"),
        }
        response = b"INERT_UPSTREAM_OK"
        self.send_response(200)
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, *args: object) -> None:
        pass


def wait_for_proxy(process: subprocess.Popen, address: tuple[str, int]) -> None:
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError(f"proxy exited at startup: {process.returncode}")
        try:
            with socket.create_connection(address, timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("proxy did not start")


def main() -> None:
    if not BINARY.is_file():
        raise SystemExit("Run 'cargo build --release' before this probe.")
    upstream = http.server.ThreadingHTTPServer(("127.0.0.1", 0), InertUpstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    address = ("127.0.0.1", port)
    environment = os.environ.copy()
    environment.update(
        UPSTREAM_URL=f"http://127.0.0.1:{upstream.server_port}",
        LISTEN_ADDR=f"127.0.0.1:{port}",
        RUST_LOG="warn,threat_classifier_proxy=info",
        NO_COLOR="1",
    )
    process = subprocess.Popen(
        [str(BINARY)],
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    decisions: queue.Queue[str] = queue.Queue()

    def collect_logs() -> None:
        assert process.stdout is not None
        for line in process.stdout:
            clean = ANSI.sub("", line)
            if "request classified" in clean:
                decisions.put(clean)

    log_thread = threading.Thread(target=collect_logs, daemon=True)
    log_thread.start()
    try:
        wait_for_proxy(process, address)
        print(
            json.dumps(
                {
                    "note": "Only local inert upstream; HTTP status is the proxy decision, not verified exploitation."
                }
            )
        )
        for probe in probes():
            headers = {
                "Host": "test-site.com",
                "User-Agent": AGENT,
                "Accept": "*/*",
                "X-Lab-Case": probe.name,
                **probe.headers,
            }
            if probe.method == "POST" and not probe.chunked:
                headers["Content-Length"] = str(len(probe.body))
            if probe.chunked:
                headers["Transfer-Encoding"] = "chunked"
            connection = http.client.HTTPConnection(*address, timeout=90)
            try:
                start = time.monotonic()
                connection.putrequest(
                    probe.method, probe.path, skip_host=True, skip_accept_encoding=True
                )
                for name, value in headers.items():
                    connection.putheader(name, value)
                if probe.chunked:
                    connection.endheaders()
                    for offset in range(0, len(probe.body), 8192):
                        chunk = probe.body[offset : offset + 8192]
                        connection.send(
                            f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n"
                        )
                    connection.send(b"0\r\n\r\n")
                else:
                    connection.endheaders(probe.body if probe.body else None)
                response = connection.getresponse()
                response_body = response.read()
                result = {
                    "case": probe.name,
                    "cve": probe.cve,
                    "kind": probe.kind,
                    "status": response.status,
                    "elapsed_ms": round((time.monotonic() - start) * 1000, 1),
                    "body_bytes": len(probe.body),
                    "chunked": probe.chunked,
                    "client_port": connection.sock.getsockname()[1]
                    if connection.sock
                    else None,
                    "upstream_received": probe.name in InertUpstream.received,
                }
                if response.status in (200, 401):
                    match = DECISION.search(decisions.get(timeout=5))
                    if not match:
                        raise RuntimeError(
                            f"could not parse classification for {probe.name}"
                        )
                    result.update(
                        decision=match.group(1),
                        label=match.group(2),
                        score=float(match.group(3)),
                    )
                if result["upstream_received"]:
                    received = InertUpstream.received[probe.name]
                    assert (
                        response.status == 200 and response_body == b"INERT_UPSTREAM_OK"
                    )
                    assert received["method"] == probe.method
                    assert received["path"] == probe.path
                    assert (
                        received["body_sha256"]
                        == hashlib.sha256(probe.body).hexdigest()
                    )
                    if "Cache-Control" in probe.headers:
                        assert (
                            received["cache_control"] == probe.headers["Cache-Control"]
                        )
                elif response.status == 200:
                    raise RuntimeError(f"unexpected non-upstream 200 for {probe.name}")
                print(json.dumps(result), flush=True)
            finally:
                connection.close()
    finally:
        process.terminate()
        try:
            process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        upstream.shutdown()
        upstream.server_close()
        log_thread.join(timeout=2)


if __name__ == "__main__":
    main()
