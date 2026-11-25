"""Exercise the packaged launcher, Xray client and independent VLESS/TLS server on loopback."""
import argparse
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import uuid


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextlib.contextmanager
def child(command):
    # The launcher owns a separate Xray process. Tear down its entire test group.
    proc = subprocess.Popen(command, stdin=subprocess.PIPE, start_new_session=os.name != "nt")
    try:
        yield proc
    finally:
        if proc.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], check=True)
            else:
                os.killpg(proc.pid, signal.SIGTERM)
        proc.wait(timeout=10)


def send_config(process, data):
    process.stdin.write(data)
    process.stdin.close()


def wait_for_listener(process, port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"listener on port {port} did not start (process status {process.poll()})")


def exercise(directory, launcher, core):
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                    "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=fixture.test",
                    "-addext", "subjectAltName=DNS:fixture.test"], check=True, capture_output=True)
    pin = hashlib.sha256(ssl.PEM_cert_to_DER_cert(cert.read_text())).hexdigest()
    user = str(uuid.uuid4())
    fixture = os.urandom(128 * 1024)

    class Origin(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", str(len(fixture)))
            self.end_headers()
            self.wfile.write(fixture)

    with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        port = unused_port()
        server_config = {
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless",
                          "settings": {"clients": [{"id": user}], "decryption": "none"},
                          "streamSettings": {"network": "tcp", "security": "tls", "tlsSettings": {
                              "alpn": ["http/1.1"], "certificates": [
                                  {"certificateFile": str(cert), "keyFile": str(key)}]}}}],
            "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"], "port": str(origin.server_port)}]}}],
        }
        with child([core, "run", "-config", "stdin:"]) as server:
            send_config(server, json.dumps(server_config).encode())
            wait_for_listener(server, port)
            proxy_port = unused_port()
            with child([launcher, core, str(proxy_port)]) as client:
                link = f"vless://{user}@127.0.0.1:{port}?security=tls&sni=fixture.test&pcs={pin}"
                send_config(client, link.encode())
                wait_for_listener(client, proxy_port)
                result = subprocess.run(["curl", "--silent", "--show-error", "--fail",
                    "--max-time", "10", "--noproxy", "", "--proxy", f"socks5h://127.0.0.1:{proxy_port}",
                    f"http://127.0.0.1:{origin.server_port}/payload"], capture_output=True, check=True)
                if result.stdout != fixture:
                    raise ValueError("proxied payload differs from origin")
                print(f"Verified {len(fixture)} bytes through the packaged client", flush=True)
        origin.shutdown()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("launcher", type=Path)
    parser.add_argument("core", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory() as temp:
        exercise(Path(temp), args.launcher.resolve(), args.core.resolve())
