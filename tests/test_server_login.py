"""Kiểm thử Việc 1: framing TCP và server đăng nhập (TCP/TLS).

Dùng ``FakeSessions`` thay cho ``sessions.py`` để test server độc lập.

Chạy từ thư mục gốc repo::

    python -m unittest discover -s tests -v
"""

import base64
import os
import socket
import ssl
import struct
import sys
import tempfile
import threading
import unittest
from dataclasses import dataclass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import server  # noqa: E402
from framing import (ConnectionClosed, encode_frame, recv_exact, recv_frame,  # noqa: E402
                     send_frame)
from server import CollabServer  # noqa: E402
from protocol import AppError  # noqa: E402


# ---------------------------------------------------------------------------
# Backend phiên giả lập
# ---------------------------------------------------------------------------

@dataclass
class FakeSession:
    session_id: int
    user_id: str
    username: str
    c2s_key: bytes
    s2c_key: bytes
    c2s_nonce_prefix: bytes
    s2c_nonce_prefix: bytes


class FakeSessions:
    """Tài khoản userNN / passNN, một phiên mỗi tài khoản, thread-safe."""

    def __init__(self, n=20):
        self.accounts = {f"user{i:02d}": (f"u{i:02d}", f"pass{i:02d}") for i in range(1, n + 1)}
        self.active = {}          # user_id -> FakeSession
        self.removed = []
        self.lock = threading.Lock()
        self.next_id = 1000

    def authenticate(self, username, password):
        acc = self.accounts.get(username)
        if acc is None or acc[1] != password:
            raise AppError("INVALID_CREDENTIALS", "Sai thông tin đăng nhập")
        with self.lock:
            if acc[0] in self.active:
                raise AppError("ALREADY_LOGGED_IN", "Tài khoản đang đăng nhập")
            self.next_id += 1
            s = FakeSession(self.next_id, acc[0], username, os.urandom(32), os.urandom(32),
                            os.urandom(4), os.urandom(4))
            self.active[acc[0]] = s
            return s

    def remove_session(self, session_id):
        with self.lock:
            self.removed.append(session_id)
            for uid, s in list(self.active.items()):
                if s.session_id == session_id:
                    del self.active[uid]


# ---------------------------------------------------------------------------
# Tiện ích
# ---------------------------------------------------------------------------

def login_frame(username, password):
    return encode_frame({"type": "LOGIN", "username": username, "password": password})


class ServerTestBase(unittest.TestCase):
    ssl_context = None

    def setUp(self):
        self.backend = FakeSessions()
        self.server = CollabServer(self.backend, host="127.0.0.1", tcp_port=0, udp_port=9001,
                                   ssl_context=self.ssl_context, login_timeout=1.0)
        self.server.start()
        self.port = self.server.tcp_port

    def tearDown(self):
        self.server.stop()

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=5)

    def exchange(self, raw: bytes) -> dict:
        """Gửi byte thô, nhận một frame trả lời."""
        with self.connect() as s:
            s.sendall(raw)
            return recv_frame(s)

    def login(self, username, password):
        return self.exchange(login_frame(username, password))

    def assert_alive(self):
        """Server vẫn phục vụ được sau sự cố."""
        reply = self.login("user20", "pass20")
        self.assertEqual(reply["type"], "LOGIN_OK")


# ---------------------------------------------------------------------------
# Framing
# ---------------------------------------------------------------------------

class FramingTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = socket.socketpair()
        self.a.settimeout(2)
        self.b.settimeout(2)

    def tearDown(self):
        self.a.close()
        self.b.close()

    def test_roundtrip_unicode(self):
        send_frame(self.a, {"type": "X", "text": "Chào bạn!"})
        self.assertEqual(recv_frame(self.b), {"type": "X", "text": "Chào bạn!"})

    def test_split_byte_by_byte(self):
        data = encode_frame({"type": "LOGIN", "username": "a", "password": "b"})

        def slow_send():
            for i in range(len(data)):
                self.a.send(data[i:i + 1])
        t = threading.Thread(target=slow_send)
        t.start()
        self.assertEqual(recv_frame(self.b)["username"], "a")
        t.join()

    def test_coalesced_frames(self):
        self.a.sendall(encode_frame({"n": 1}) + encode_frame({"n": 2}))
        self.assertEqual(recv_frame(self.b), {"n": 1})
        self.assertEqual(recv_frame(self.b), {"n": 2})

    def test_eof_midway(self):
        self.a.sendall(struct.pack("!I", 10) + b"{\"a\"")
        self.a.close()
        with self.assertRaises(ConnectionClosed):
            recv_frame(self.b)

    def test_recv_exact_eof_in_header(self):
        self.a.sendall(b"\x00\x00")
        self.a.close()
        with self.assertRaises(ConnectionClosed):
            recv_exact(self.b, 4)

    def test_length_too_large(self):
        self.a.sendall(struct.pack("!I", 65537))
        with self.assertRaises(AppError) as cm:
            recv_frame(self.b)
        self.assertEqual(cm.exception.code, "PAYLOAD_TOO_LARGE")

    def test_bad_lengths_and_json(self):
        for raw in (struct.pack("!I", 0),
                    struct.pack("!I", 3) + b"{x}",
                    struct.pack("!I", 2) + b"\xff\xfe",
                    struct.pack("!I", 2) + b"[]",
                    struct.pack("!I", 9) + b'{"a":NaN}'):
            self.a.sendall(raw)
            with self.assertRaises(AppError) as cm:
                recv_frame(self.b)
            self.assertEqual(cm.exception.code, "INVALID_PACKET")

    def test_encode_rejects_oversize(self):
        with self.assertRaises(AppError) as cm:
            encode_frame({"x": "a" * 70000})
        self.assertEqual(cm.exception.code, "PAYLOAD_TOO_LARGE")

    def test_max_frame_ok(self):
        # Body đúng 65536 byte vẫn hợp lệ (biên trên).
        obj = {"x": "a" * (65536 - len('{"x":""}'))}
        raw = encode_frame(obj)
        self.assertEqual(len(raw), 4 + 65536)
        t = threading.Thread(target=self.a.sendall, args=(raw,))
        t.start()
        self.assertEqual(recv_frame(self.b), obj)
        t.join()

    def test_shared_app_error(self):
        # sessions.AppError phải là cùng lớp với protocol.AppError của nhóm.
        import sessions
        self.assertIs(sessions.AppError, AppError)


# ---------------------------------------------------------------------------
# Server không TLS
# ---------------------------------------------------------------------------

class LoginTests(ServerTestBase):
    def test_login_ok(self):
        reply = self.login("user01", "pass01")
        self.assertEqual(reply["type"], "LOGIN_OK")
        self.assertEqual(reply["user_id"], "u01")
        self.assertEqual(reply["udp_port"], 9001)
        self.assertIsInstance(reply["session_id"], int)
        for field, size in (("c2s_key", 32), ("s2c_key", 32),
                            ("c2s_nonce_prefix", 4), ("s2c_nonce_prefix", 4)):
            self.assertEqual(len(base64.b64decode(reply[field], validate=True)), size)

    def test_server_closes_after_reply(self):
        with self.connect() as s:
            s.sendall(login_frame("user01", "pass01"))
            recv_frame(s)
            self.assertEqual(s.recv(1), b"")   # server đã đóng TCP

    def test_wrong_password(self):
        reply = self.login("user01", "sai")
        self.assertEqual(reply["type"], "ERROR")
        self.assertEqual(reply["code"], "INVALID_CREDENTIALS")
        self.assertIsNone(reply["reference_id"])

    def test_unknown_user(self):
        self.assertEqual(self.login("nobody", "x")["code"], "INVALID_CREDENTIALS")

    def test_already_logged_in(self):
        self.assertEqual(self.login("user02", "pass02")["type"], "LOGIN_OK")
        self.assertEqual(self.login("user02", "pass02")["code"], "ALREADY_LOGGED_IN")

    def test_split_byte_by_byte(self):
        data = login_frame("user03", "pass03")
        with self.connect() as s:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            for i in range(len(data)):
                s.send(data[i:i + 1])
            self.assertEqual(recv_frame(s)["type"], "LOGIN_OK")

    def test_coalesced_frames(self):
        # Hai frame gộp trong một lần gửi: server xử lý frame đầu, bỏ phần dư.
        reply = self.exchange(login_frame("user04", "pass04") + login_frame("user05", "pass05"))
        self.assertEqual(reply["user_id"], "u04")
        self.assertNotIn("u05", self.backend.active)
        self.assert_alive()

    def test_length_zero(self):
        self.assertEqual(self.exchange(struct.pack("!I", 0))["code"], "INVALID_PACKET")
        self.assert_alive()

    def test_length_too_large(self):
        reply = self.exchange(struct.pack("!I", 65537) + b"x" * 1000)
        self.assertEqual(reply["code"], "PAYLOAD_TOO_LARGE")
        self.assert_alive()

    def test_bad_json(self):
        body = b'{"type":"LOGIN",'
        self.assertEqual(self.exchange(struct.pack("!I", len(body)) + body)["code"],
                         "INVALID_PACKET")
        self.assert_alive()

    def test_missing_field_and_unknown_type(self):
        for msg in ({"type": "LOGIN", "username": "user01"},
                    {"type": "LOGIN", "username": 1, "password": "x"},
                    {"type": "HELLO"},
                    {"username": "user01", "password": "pass01"}):
            self.assertEqual(self.exchange(encode_frame(msg))["code"], "INVALID_PACKET")
        self.assertEqual(self.backend.active, {})

    def test_field_too_long(self):
        reply = self.login("u" * 100, "x")
        self.assertEqual(reply["code"], "PAYLOAD_TOO_LARGE")

    def test_client_closes_midway(self):
        # Đóng sau một phần header, sau một phần body, và RST đột ngột.
        with self.connect() as s:
            s.sendall(b"\x00\x00")
        with self.connect() as s:
            s.sendall(struct.pack("!I", 50) + b'{"type":')
        s = self.connect()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.sendall(struct.pack("!I", 50))
        s.close()   # gửi RST
        self.assert_alive()

    def test_idle_client_times_out(self):
        with self.connect() as s:
            s.settimeout(5)
            # Không gửi gì; server (login_timeout=1s) phải tự đóng.
            self.assertEqual(s.recv(1), b"")
        self.assert_alive()

    def test_20_concurrent_logins(self):
        results = [None] * 20
        barrier = threading.Barrier(20)

        def worker(i):
            barrier.wait()
            results[i] = self.login(f"user{i + 1:02d}", f"pass{i + 1:02d}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(10)
        self.assertTrue(all(r and r["type"] == "LOGIN_OK" for r in results), results)
        self.assertEqual(len({r["session_id"] for r in results}), 20)


class CliTests(unittest.TestCase):
    def test_tls_on_by_default(self):
        self.assertFalse(server.parse_args([]).no_tls)
        self.assertTrue(server.parse_args(["--no-tls"]).no_tls)


# ---------------------------------------------------------------------------
# Server có TLS
# ---------------------------------------------------------------------------

class TLSLoginTests(ServerTestBase):
    @classmethod
    def setUpClass(cls):
        import gen_cert
        cls.tmp = tempfile.TemporaryDirectory()
        cls.paths = gen_cert.generate(cls.tmp.name)
        cls.ssl_context = server.build_tls_context(cls.paths["server.crt"],
                                                   cls.paths["server.key"])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def tls_login(self, ctx, hostname="127.0.0.1"):
        raw = self.connect()
        with ctx.wrap_socket(raw, server_hostname=hostname) as s:
            send_frame(s, {"type": "LOGIN", "username": "user01", "password": "pass01"})
            return recv_frame(s)

    def test_tls_login_verified(self):
        ctx = ssl.create_default_context(cafile=self.paths["ca.crt"])
        self.assertEqual(self.tls_login(ctx)["type"], "LOGIN_OK")

    def test_tls_localhost_name(self):
        ctx = ssl.create_default_context(cafile=self.paths["ca.crt"])
        self.assertEqual(self.tls_login(ctx, hostname="localhost")["type"], "LOGIN_OK")

    def test_tls_rejects_unknown_ca(self):
        ctx = ssl.create_default_context()   # không có CA của dự án
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.tls_login(ctx)

    def test_tls_wrong_hostname(self):
        ctx = ssl.create_default_context(cafile=self.paths["ca.crt"])
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.tls_login(ctx, hostname="example.com")

    def test_plaintext_client_on_tls_server(self):
        # Client không TLS gửi frame thường: chỉ kết nối đó hỏng.
        with self.connect() as s:
            s.sendall(login_frame("user01", "pass01"))
            try:
                s.recv(100)
            except OSError:
                pass
        ctx = ssl.create_default_context(cafile=self.paths["ca.crt"])
        self.assertEqual(self.tls_login(ctx)["type"], "LOGIN_OK")


if __name__ == "__main__":
    unittest.main()
