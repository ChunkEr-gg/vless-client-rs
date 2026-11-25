"""Exercise the packaged desktop core's listener events and SOCKS forwarding."""

import json
import os
import socket
import struct
import subprocess
import sys
import threading
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


def main():
    config = {"inbounds": [{"type": "socks", "tag": "local", "listen": "127.0.0.1", "listen_port": 0}],
              "outbounds": [{"type": "direct"}]}
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


if __name__ == "__main__":
    main()
