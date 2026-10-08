#!/usr/bin/env python3
"""Minimal threaded HTTP/CONNECT forward proxy so the egress-less lab VM can install packages
through this host. Binds 0.0.0.0:8888. DNS resolves on this (internet-connected) host."""
import select, socket, threading

BIND = ("0.0.0.0", 8888)


def pipe(a, b):
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 60)
            if not r:
                break
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try: s.close()
            except OSError: pass


def handle(client):
    try:
        client.settimeout(30)
        buf = b""
        while b"\r\n\r\n" not in buf and b"\n\n" not in buf:
            chunk = client.recv(4096)
            if not chunk:
                client.close(); return
            buf += chunk
            if len(buf) > 65536:
                break
        head, _, rest = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        method, target, _ = lines[0].split(b" ", 2)
        method = method.decode(); target = target.decode()
        if method == "CONNECT":
            host, port = target.rsplit(":", 1)
            up = socket.create_connection((host, int(port)), timeout=30)
            client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            pipe(client, up)
        else:  # absolute-URI HTTP
            from urllib.parse import urlsplit
            u = urlsplit(target)
            host = u.hostname; port = u.port or 80
            path = (u.path or "/") + (("?" + u.query) if u.query else "")
            newhead = b" ".join([method.encode(), path.encode(), b"HTTP/1.1"]) + b"\r\n" + b"\r\n".join(lines[1:])
            up = socket.create_connection((host, port), timeout=30)
            up.sendall(newhead + b"\r\n\r\n" + rest)
            pipe(client, up)
    except Exception:
        try: client.close()
        except OSError: pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(BIND); srv.listen(128)
    print(f"proxy on {BIND[0]}:{BIND[1]}", flush=True)
    while True:
        cl, _ = srv.accept()
        threading.Thread(target=handle, args=(cl,), daemon=True).start()


if __name__ == "__main__":
    main()
