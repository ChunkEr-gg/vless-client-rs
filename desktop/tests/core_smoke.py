"""Exercise the packaged desktop core's SOCKS or system TUN forwarding."""

import argparse
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
TUN_DESTINATION = "198.51.100.211"
TUN_PREFIX = TUN_DESTINATION + "/32"
TUN_NAME = "vless-ci"


class Origin(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)


def ready(core):
    for line in core.stdout:
        if line.startswith(b"READY "):
            address = line.split()[1].decode()
            break
    else:
        raise RuntimeError("Core exited before reporting its SOCKS listener")
    host, listener = address.rsplit(":", 1)
    assert host == "127.0.0.1"
    return host, int(listener)


def transfer_http(client, reader):
    client.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
    headers, body = reader.read().split(b"\r\n\r\n", 1)
    assert b"200 OK" in headers and body == PAYLOAD


def transfer(core, port):
    host, listener = ready(core)
    with socket.create_connection((host, listener), timeout=5) as client:
        with client.makefile("rb") as reader:
            client.sendall(b"\x05\x01\x00")
            assert reader.read(2) == b"\x05\x00"
            client.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port))
            reply = reader.read(4)
            assert reply[:3] == b"\x05\x00\x00"
            reader.read({1: 4, 4: 16}[reply[3]] + 2)
            transfer_http(client, reader)


def route_interface():
    if sys.platform == "win32":
        result = subprocess.check_output([
            "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
            "Get-NetRoute -PolicyStore ActiveStore -AddressFamily IPv4 | "
            f"Where-Object DestinationPrefix -eq '{TUN_PREFIX}' | "
            "Select-Object -ExpandProperty InterfaceAlias",
        ], text=True, timeout=8)
        return result.strip()
    if sys.platform == "darwin":
        result = subprocess.check_output(
            ["/sbin/route", "-n", "get", TUN_DESTINATION], text=True, timeout=5)
        return next(line.split(":", 1)[1].strip() for line in result.splitlines()
                    if line.strip().startswith("interface:"))
    result = subprocess.check_output(["ip", "-j", "route", "get", TUN_DESTINATION],
                                     text=True, timeout=5)
    return json.loads(result)[0]["dev"]


def transfer_tun(core, port, original_interface):
    ready(core)
    interface = route_interface()
    assert interface != original_interface, (interface, original_interface)
    if sys.platform == "darwin":
        assert interface.startswith("utun"), interface
    else:
        assert interface == TUN_NAME, interface
    with socket.create_connection((TUN_DESTINATION, port), timeout=5) as client:
        with client.makefile("rb") as reader:
            transfer_http(client, reader)


def exercise(binary, outbound, tun):
    config = {"inbounds": [{"type": "socks", "tag": "local", "listen": "127.0.0.1", "listen_port": 0}],
              "outbounds": [outbound]}
    original_interface = None
    if tun:
        original_interface = route_interface()
        # Limit the fixture to a single documentation address.
        tun_inbound = {
            "type": "tun", "tag": "system", "address": ["172.29.255.1/30"],
            "auto_route": True, "route_address": [TUN_PREFIX], "stack": "system",
        }
        if sys.platform != "darwin":
            tun_inbound["interface_name"] = TUN_NAME
        config["inbounds"].append(tun_inbound)
        config["route"] = {"auto_detect_interface": True}
    with ThreadingHTTPServer(("127.0.0.1", 0), Origin) as origin:
        threading.Thread(target=origin.serve_forever, daemon=True).start()
        with subprocess.Popen([binary, "run", "--disable-color", "-c", "stdin"],
                              env={**os.environ, "RK_DESKTOP_EVENTS": "1", "RK_DESKTOP_PIPE": "1"},
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE) as core:
            with ThreadPoolExecutor(max_workers=1) as pool:
                try:
                    core.stdin.write(json.dumps(config).encode() + b"\n")
                    core.stdin.flush()
                    if tun:
                        pool.submit(transfer_tun, core, origin.server_port, original_interface).result(timeout=20)
                    else:
                        pool.submit(transfer, core, origin.server_port).result(timeout=20)
                    core.stdin.close()
                    assert core.wait(timeout=11) == 0, "graceful core shutdown failed"
                    if tun:
                        assert route_interface() == original_interface, "TUN route survived shutdown"
                        print("TUN payload matched and the original route was restored.", flush=True)
                finally:
                    if core.poll() is None:
                        core.kill()
                        core.wait()
                    origin.shutdown()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary")
    parser.add_argument("--tun", action="store_true")
    args = parser.parse_args()
    binary = args.binary
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
        server_config = {"inbounds": [inbound], "outbounds": [{"type": "direct", "tag": "direct"}]}
        if args.tun:
            server_config["route"] = {"rules": [{
                "ip_cidr": [TUN_PREFIX], "action": "route", "outbound": "direct",
                "override_address": host,
            }]}
        with subprocess.Popen([binary, "run", "--disable-color", "-c", "stdin"],
                              stdin=subprocess.PIPE) as server:
            try:
                server.stdin.write(json.dumps(server_config).encode())
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
                exercise(binary,
                         {"type": "vless", "server": host, "server_port": port, "uuid": user,
                          "tls": {"enabled": True, "server_name": "localhost", "min_version": "1.3",
                                  "certificate_leaf_sha256": pin}},
                         args.tun)
            finally:
                server.kill()
                server.wait()


if __name__ == "__main__":
    main()
