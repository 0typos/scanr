#!/usr/bin/env python3
"""The lab for docs/tutorial.md: three loopback services with known behaviour.

    python3 docs/tutorial/lab.py                     # run until Ctrl-C
    python3 docs/tutorial/lab.py --check             # connect to each service once and exit
    python3 docs/tutorial/lab.py --exit-with-parent  # for tests: leave when the parent does

  25025  greets on connect, like SMTP    -> a banner, never probed for TLS
  28080  accepts and says nothing        -> a silent open port
  28443  TLS 1.2 with ALPN h2, http/1.1  -> what `--tls` learns from
  28444  TLS 1.0/1.1 only, the old box    -> what `--tls-versions` finds
  29000  nothing listening               -> closed
  29001  nothing listening               -> closed

Everything binds 127.0.0.1. The TLS certificate is generated on first run into
`lab-cert.pem` / `lab-key.pem` next to this script (needs `openssl`
on PATH); delete them to get a new one. No dependencies beyond the standard library.
"""

import argparse
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time

HOST = "127.0.0.1"
GREET_PORT = 25025
SILENT_PORT = 28080
TLS_PORT = 28443
LEGACY_PORT = 28444
CLOSED_PORTS = (29000, 29001)
GREETING = b"220 mail.lab.internal ESMTP ready\r\n"

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "lab-cert.pem")
KEY = os.path.join(HERE, "lab-key.pem")


def listener(port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, port))
    s.listen(64)
    return s


def serve_plain(port: int, greeting: bytes) -> None:
    """Accept, optionally greet, close. A greeting is what a banner read records."""
    s = listener(port)
    while True:
        conn, _ = s.accept()
        try:
            if greeting:
                conn.sendall(greeting)
        except OSError:
            pass
        finally:
            conn.close()


def ensure_certificate() -> None:
    """A self-signed P-256 certificate. Two commands rather than `req -newkey ec -pkeyopt`,
    which LibreSSL (macOS) does not accept; both of these it does."""
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    subprocess.run(
        ["openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", KEY],
        check=True,
    )
    subprocess.run(
        ["openssl", "req", "-x509", "-key", KEY, "-out", CERT, "-days", "30", "-subj", "/CN=lab.internal"],
        check=True,
    )


def serve_tls(port: int) -> None:
    """A TLS 1.2-only server that says nothing before the handshake, as TLS servers do.

    scanr's probe reads only the server's first flight, so the handshake never completes
    from the server's point of view; the errors that raises here are expected.
    """
    ensure_certificate()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ctx.load_cert_chain(CERT, KEY)
    s = listener(port)
    while True:
        conn, _ = s.accept()
        try:
            with ctx.wrap_socket(conn, server_side=True) as tls:
                tls.recv(1)
        except (ssl.SSLError, OSError, ValueError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def cert_der() -> bytes:
    """The lab certificate as DER, for a canned TLS flight."""
    ensure_certificate()
    out = subprocess.run(
        ["openssl", "x509", "-in", CERT, "-outform", "DER"],
        check=True,
        capture_output=True,
    )
    return out.stdout


def serve_legacy_tls(port: int) -> None:
    """The old appliance `--tls-versions` exists to find: it speaks only TLS 1.0 and 1.1.

    A real 1.0/1.1 server cannot be stood up with the `ssl` module on a current host —
    the system crypto policy disables those versions outright — so this answers the TLS
    wire directly instead. scanr's probe reads only the server's first flight, so a
    canned ServerHello, Certificate and ServerHelloDone at the client's version is
    exactly what it sees; the handshake is never completed, as with the 28443 server.
    Portable and deterministic: no `ssl`, no crypto, one thread per connection.

    A ClientHello that names TLS 1.0 or 1.1 (and does not offer anything newer through
    `supported_versions`) gets that version's flight; SSLv3 gets `handshake_failure`,
    anything newer `protocol_version`, and an SSLv2 CLIENT-HELLO nothing at all.
    """
    der = cert_der()
    s = listener(port)

    def flight(version: int) -> bytes:
        hello = version.to_bytes(2, "big") + b"\x42" * 32 + b"\x00" + b"\x00\x2f" + b"\x00"
        cert_entry = len(der).to_bytes(3, "big") + der
        cert_body = len(cert_entry).to_bytes(3, "big") + cert_entry
        msgs = b""
        for kind, body in ((2, hello), (11, cert_body), (14, b"")):
            msgs += bytes([kind]) + len(body).to_bytes(3, "big") + body
        return b"\x16" + version.to_bytes(2, "big") + len(msgs).to_bytes(2, "big") + msgs

    def alert(desc: int) -> bytes:
        return b"\x15\x03\x01" + b"\x00\x02" + bytes([2, desc])  # alert record, fatal

    def handle(conn: socket.socket) -> None:
        try:
            conn.settimeout(2)
            head = conn.recv(5)
            if not head or head[0] & 0x80:  # SSLv2 CLIENT-HELLO: not spoken
                return
            body = b""
            need = int.from_bytes(head[3:5], "big")
            while len(body) < need:
                chunk = conn.recv(need - len(body))
                if not chunk:
                    break
                body += chunk
            client_version = int.from_bytes(body[4:6], "big")
            offers_newer = b"\x00\x2b" in body  # supported_versions extension
            if not offers_newer and client_version in (0x0301, 0x0302):
                conn.sendall(flight(client_version))
            elif client_version == 0x0300:
                conn.sendall(alert(40))  # handshake_failure
            else:
                conn.sendall(alert(70))  # protocol_version
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    while True:
        conn, _ = s.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


def check() -> int:
    """Touch each service the way the tutorial's first scan does."""
    ok = True
    for port, expect in (
        (GREET_PORT, "greets"),
        (SILENT_PORT, "silent"),
        (TLS_PORT, "tls"),
        (LEGACY_PORT, "legacy"),
    ):
        try:
            with socket.create_connection((HOST, port), timeout=2) as c:
                c.settimeout(0.5)
                try:
                    first = c.recv(64)
                except (socket.timeout, OSError):
                    first = b""
            got = "greets" if first else "silent"
            if expect == "tls":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                ctx.set_alpn_protocols(["h2"])
                with socket.create_connection((HOST, port), timeout=2) as raw:
                    with ctx.wrap_socket(raw, server_hostname="lab.internal") as t:
                        got = f"tls {t.version()} alpn={t.selected_alpn_protocol()}"
            if expect == "legacy":
                got = "legacy tls1.0-1.1"
            print(f"{HOST}:{port}  {got}")
        except OSError as e:
            print(f"{HOST}:{port}  DOWN ({e})")
            ok = False
    for port in CLOSED_PORTS:
        try:
            socket.create_connection((HOST, port), timeout=1).close()
            print(f"{HOST}:{port}  UNEXPECTEDLY OPEN")
            ok = False
        except OSError:
            print(f"{HOST}:{port}  closed")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="probe a running lab and exit")
    ap.add_argument(
        "--exit-with-parent",
        action="store_true",
        help="exit when the parent process does (a test spawned us and will not clean up)",
    )
    args = ap.parse_args()
    if args.check:
        return check()
    if args.exit_with_parent:
        parent = os.getppid()

        def watch() -> None:
            while os.getppid() == parent:
                time.sleep(0.5)
            os._exit(0)

        threading.Thread(target=watch, daemon=True).start()

    for port in CLOSED_PORTS:
        try:
            listener(port).close()
        except OSError:
            print(f"warning: something is listening on {HOST}:{port}; it should be closed", file=sys.stderr)

    threads = [
        threading.Thread(target=serve_plain, args=(GREET_PORT, GREETING), daemon=True),
        threading.Thread(target=serve_plain, args=(SILENT_PORT, b""), daemon=True),
        threading.Thread(target=serve_tls, args=(TLS_PORT,), daemon=True),
        threading.Thread(target=serve_legacy_tls, args=(LEGACY_PORT,), daemon=True),
    ]
    for t in threads:
        t.start()
    print(
        f"lab up on {HOST}: {GREET_PORT} greets, {SILENT_PORT} silent, {TLS_PORT} tls1.2 "
        f"(h2, http/1.1), {LEGACY_PORT} tls1.0-1.1 only; "
        f"{', '.join(map(str, CLOSED_PORTS))} closed. Ctrl-C to stop.",
        flush=True,
    )
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    try:
        signal.pause()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
