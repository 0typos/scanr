#!/usr/bin/env python3
"""The lab for docs/tutorial.md: three loopback services with known behaviour.

    python3 docs/tutorial-lab.py            # run until Ctrl-C
    python3 docs/tutorial-lab.py --check    # connect to each service once and exit

  25025  greets on connect, like SMTP    -> a banner, never probed for TLS
  28080  accepts and says nothing        -> a silent open port
  28443  TLS 1.2 with ALPN h2, http/1.1  -> what `--tls` learns from
  29000  nothing listening               -> closed
  29001  nothing listening               -> closed

Everything binds 127.0.0.1. The TLS certificate is generated on first run into
`tutorial-lab-cert.pem` / `tutorial-lab-key.pem` next to this script (needs `openssl`
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

HOST = "127.0.0.1"
GREET_PORT = 25025
SILENT_PORT = 28080
TLS_PORT = 28443
CLOSED_PORTS = (29000, 29001)
GREETING = b"220 mail.lab.internal ESMTP ready\r\n"

HERE = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(HERE, "tutorial-lab-cert.pem")
KEY = os.path.join(HERE, "tutorial-lab-key.pem")


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
    if os.path.exists(CERT) and os.path.exists(KEY):
        return
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
            "ec_paramgen_curve:prime256v1", "-nodes", "-keyout", KEY, "-out", CERT,
            "-days", "30", "-subj", "/CN=lab.internal",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
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


def check() -> int:
    """Touch each service the way the tutorial's first scan does."""
    ok = True
    for port, expect in ((GREET_PORT, "greets"), (SILENT_PORT, "silent"), (TLS_PORT, "tls")):
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
    args = ap.parse_args()
    if args.check:
        return check()

    for port in CLOSED_PORTS:
        try:
            listener(port).close()
        except OSError:
            print(f"warning: something is listening on {HOST}:{port}; it should be closed", file=sys.stderr)

    threads = [
        threading.Thread(target=serve_plain, args=(GREET_PORT, GREETING), daemon=True),
        threading.Thread(target=serve_plain, args=(SILENT_PORT, b""), daemon=True),
        threading.Thread(target=serve_tls, args=(TLS_PORT,), daemon=True),
    ]
    for t in threads:
        t.start()
    print(
        f"lab up on {HOST}: {GREET_PORT} greets, {SILENT_PORT} silent, {TLS_PORT} tls1.2 "
        f"(h2, http/1.1); {', '.join(map(str, CLOSED_PORTS))} closed. Ctrl-C to stop.",
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
