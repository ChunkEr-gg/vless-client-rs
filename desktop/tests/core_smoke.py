"""Exercise the packaged desktop core's listener events and SOCKS forwarding."""

import hashlib
import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAYLOAD = b"desktop profiles core round trip"


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)


def transfer(core, port):
    for line in core.stdout:
        if line.startswith(b"READY "):
            address = line.split()[1].decode()
            break
    else:
        raise RuntimeError("Core exited before reporting its SOCKS listener")
    host, listener = address.rsplit(":", 1)
    assert host == "127.0.0.1"
    with socket.create_connection((host, int(listener)), timeout=5) as client:
        with client.makefile("rb") as reader:
            client.sendall(b"\x05\x01\x00")
            assert reader.read(2) == b"\x05\x00"
            client.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port))
            reply = reader.read(4)
            assert reply[:3] == b"\x05\x00\x00"
            reader.read({1: 4, 4: 16}[reply[3]] + 2)
            client.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
            headers, body = reader.read().split(b"\r\n\r\n", 1)
            assert b"200 OK" in headers and body == PAYLOAD


def exercise(outbound):
    config = {"inbounds": [{"type": "socks", "tag": "local", "listen": "127.0.0.1", "listen_port": 0}],
              "outbounds": [outbound]}
    with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        with subprocess.Popen([sys.argv[1], "run", "--disable-color", "-c", "stdin"],
                              env={**os.environ, "RK_DESKTOP_EVENTS": "1"},
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE) as core:
            with ThreadPoolExecutor(max_workers=1) as pool:
                try:
                    core.stdin.write(json.dumps(config).encode())
                    core.stdin.close()
                    pool.submit(transfer, core, origin.server_port).result(timeout=20)
                finally:
                    core.kill()
                    core.wait()
                    origin.shutdown()


def main():
    host = "127.0.0.1"
    with tempfile.TemporaryDirectory() as directory:
        cert = Path(directory) / "cert.pem"
        key = Path(directory) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-days", "1", "-subj", "/CN=localhost", "-keyout", str(key),
                        "-out", str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
        user = str(uuid.uuid4())
        with socket.socket() as reservation:
            reservation.bind((host, 0))
            port = reservation.getsockname()[1]
        inbound = {"type": "vless", "listen": host, "listen_port": port, "users": [{"uuid": user}],
                   "tls": {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}}
        with subprocess.Popen([sys.argv[1], "run", "--disable-color", "-c", "stdin"],
                              stdin=subprocess.PIPE) as server:
            try:
                server.stdin.write(json.dumps({"inbounds": [inbound], "outbounds": [{"type": "direct"}]}).encode())
                server.stdin.close()
                deadline = time.monotonic() + 10
                while True:
                    try:
                        with socket.create_connection((host, port), timeout=1):
                            break
                    except OSError:
                        if server.poll() is not None or time.monotonic() >= deadline:
                            raise
                        time.sleep(0.05)
                exercise({"type": "vless", "server": host, "server_port": port, "uuid": user,
                          "tls": {"enabled": True, "server_name": "localhost", "min_version": "1.3",
                                  "certificate_leaf_sha256": pin}})
            finally:
                server.kill()
                server.wait()


if __name__ == "__main__":
    main()
