"""Client thử đăng nhập TCP/TLS (chỉ để test server, không phải client thật).

Ví dụ::

    python tools/login_client.py user01 <mật khẩu>                      # TLS, CA certs/ca.crt
    python tools/login_client.py user01 <mật khẩu> --host 192.168.1.10 --cafile certs/ca.crt
    python tools/login_client.py user01 <mật khẩu> --no-tls             # server chạy --no-tls

Khóa phiên trong LOGIN_OK được che bớt khi in ra màn hình.
"""

import argparse
import json
import os
import socket
import ssl
import sys

# Cho phép chạy từ thư mục gốc repo hoặc từ tools/.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from framing import recv_frame, send_frame  # noqa: E402

SECRET_FIELDS = ("c2s_key", "s2c_key", "c2s_nonce_prefix", "s2c_nonce_prefix")


def login(host, port, username, password, cafile=None, timeout=10.0):
    """Gửi LOGIN và trả về phản hồi của server (dict).

    Khi có ``cafile`` thì dùng TLS và LUÔN xác minh chứng chỉ + hostname/IP.
    """
    raw = socket.create_connection((host, port), timeout=timeout)
    sock = raw
    try:
        if cafile:
            ctx = ssl.create_default_context(cafile=cafile)   # CERT_REQUIRED + check_hostname
            sock = ctx.wrap_socket(raw, server_hostname=host)
        send_frame(sock, {"type": "LOGIN", "username": username, "password": password})
        return recv_frame(sock)
    finally:
        sock.close()


def main(argv=None):
    p = argparse.ArgumentParser(description="Client thử đăng nhập")
    p.add_argument("username")
    p.add_argument("password")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9000)
    p.add_argument("--no-tls", action="store_true", help="tắt TLS (chỉ khi server chạy --no-tls)")
    p.add_argument("--cafile", default="certs/ca.crt", help="CA để xác minh server")
    args = p.parse_args(argv)

    reply = login(args.host, args.port, args.username, args.password,
                  cafile=None if args.no_tls else args.cafile)
    shown = {k: ("***" if k in SECRET_FIELDS else v) for k, v in reply.items()}
    print(json.dumps(shown, ensure_ascii=False, indent=2))
    return 0 if reply.get("type") == "LOGIN_OK" else 2


if __name__ == "__main__":
    sys.exit(main())
