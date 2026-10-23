"""Kiểm thử phần client (Người 3): client.py, messaging.py, http_bridge.py.

* Unit: EventLog, LOGIN_OK, USER_LIST phân trang, Messenger (client giả).
* End-to-end: server.py thật (TLS + UDP localhost) + 2 ChatClient: đăng nhập, danh
  sách online, chat riêng/chung, sai mật khẩu, truyền tệp, đăng xuất.
* HTTP: HttpBridge thật trên cổng ngẫu nhiên, gọi bằng http.client.

Chạy::

    python -m unittest tests.test_client -v
"""

import hashlib
import http.client
import json
import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tools"))

import client as client_mod  # noqa: E402
from client import ChatClient, CursorExpired, EventLog, parse_login_ok  # noqa: E402
from file_transfer import FileTransferManager  # noqa: E402
from http_bridge import HttpBridge  # noqa: E402
from messaging import Messenger  # noqa: E402
from protocol import AppError, PacketType  # noqa: E402

TIMEOUT = 15.0


def wait_until(predicate, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def events_of(c, kind):
    return [e["data"] for e in c.events.get(0, limit=10**6)["events"] if e["type"] == kind]


# ============================================================================
# Unit
# ============================================================================

class EventLogTests(unittest.TestCase):
    def test_cursor_and_limit(self):
        log = EventLog(maxlen=500)
        for i in range(150):
            log.emit("x", {"i": i})
        first = log.get(0)
        self.assertEqual(len(first["events"]), 100)
        self.assertEqual(first["next_cursor"], 100)
        rest = log.get(first["next_cursor"])
        self.assertEqual([e["event_id"] for e in rest["events"]], list(range(101, 151)))
        self.assertEqual(log.get(150), {"events": [], "next_cursor": 150})

    def test_expired_cursor(self):
        log = EventLog(maxlen=10)
        for i in range(30):
            log.emit("x", {})
        with self.assertRaises(CursorExpired) as cm:
            log.get(5)                       # sự kiện 6..20 đã bị đẩy ra
        self.assertEqual(cm.exception.current_cursor, 30)
        with self.assertRaises(CursorExpired):
            log.get(99)                      # cursor lớn hơn id cuối (bridge khởi động lại)
        self.assertEqual(len(log.get(20)["events"]), 10)

    def test_long_poll_wakes_up(self):
        log = EventLog()
        threading.Timer(0.2, log.emit, args=("x", {})).start()
        start = time.monotonic()
        result = log.get(0, timeout=5)
        self.assertEqual(len(result["events"]), 1)
        self.assertLess(time.monotonic() - start, 2)


class LoginOkTests(unittest.TestCase):
    OK = {"type": "LOGIN_OK", "user_id": "u01", "session_id": 7, "udp_port": 9001,
          "c2s_key": "A" * 43 + "=", "s2c_key": "B" * 43 + "=",
          "c2s_nonce_prefix": "AAAAAA==", "s2c_nonce_prefix": "BBBBBA=="}

    def test_ok(self):
        creds = parse_login_ok(dict(self.OK))
        self.assertEqual((creds["user_id"], creds["session_id"]), ("u01", 7))
        self.assertEqual(len(creds["c2s_key"]), 32)
        self.assertEqual(len(creds["s2c_nonce_prefix"]), 4)

    def test_error_from_server(self):
        with self.assertRaises(AppError) as cm:
            parse_login_ok({"type": "ERROR", "code": "INVALID_CREDENTIALS", "message": "x"})
        self.assertEqual(cm.exception.code, "INVALID_CREDENTIALS")

    def test_bad_fields(self):
        for field, value in (("c2s_key", "abc"), ("session_id", 0), ("udp_port", True),
                             ("user_id", "")):
            with self.subTest(field=field), self.assertRaises(AppError):
                parse_login_ok({**self.OK, field: value})


class UserListTests(unittest.TestCase):
    def test_parts_assembled_by_revision(self):
        c = ChatClient("127.0.0.1")
        u = lambda i: {"user_id": f"u{i:02d}", "username": f"user{i:02d}"}   # noqa: E731
        c._on_user_list({"revision": 2, "part_index": 1, "part_count": 2, "users": [u(3)]})
        self.assertEqual(events_of(c, "users_updated"), [])            # chưa đủ phần
        c._on_user_list({"revision": 1, "part_index": 0, "part_count": 1, "users": [u(9)]})
        c._on_user_list({"revision": 2, "part_index": 0, "part_count": 2, "users": [u(1), u(2)]})
        updates = events_of(c, "users_updated")
        self.assertEqual(updates, [{"revision": 2, "users": [u(1), u(2), u(3)]}])
        c._on_user_list({"revision": 1, "part_index": 0, "part_count": 1, "users": [u(9)]})
        self.assertEqual(len(events_of(c, "users_updated")), 1)        # revision cũ bị bỏ


class FakeClient:
    """Phần ChatClient mà Messenger dùng."""

    def __init__(self):
        self.sent, self.events, self.results = [], [], {}
        self.users = None

    def require_connected(self):
        return {"user_id": "u01", "username": "user01"}

    def is_online(self, user_id):
        return None if self.users is None else user_id in self.users

    def send_reliable(self, stream_id, packet_type, payload, on_result=None):
        delivery_id = str(uuid.uuid4())
        self.sent.append((stream_id, packet_type, json.loads(payload)))
        self.results[delivery_id] = on_result
        return delivery_id

    def emit(self, kind, data):
        self.events.append((kind, data))


class MessengerTests(unittest.TestCase):
    def setUp(self):
        self.fc = FakeClient()
        self.m = Messenger(self.fc)

    def test_send_validation(self):
        with self.assertRaises(AppError):
            self.m.send_message(None, "   ")
        with self.assertRaises(AppError) as cm:
            self.m.send_message(None, "ạ" * 300)                 # 900 byte UTF-8
        self.assertEqual(cm.exception.code, "PAYLOAD_TOO_LARGE")
        self.m.send_message(None, "ạ" * 266)                     # 798 byte: hợp lệ
        self.fc.users = ["u01", "u02"]
        with self.assertRaises(AppError) as cm:
            self.m.send_message("u09", "hi")
        self.assertEqual(cm.exception.code, "USER_OFFLINE")

    def test_packet_and_status_flow(self):
        mid = self.m.send_message("u02", "Chào bạn!")
        stream, kind, body = self.fc.sent[-1]
        self.assertEqual((stream, kind), (2, PacketType.CHAT))
        self.assertEqual(body, {"message_id": mid, "to": "u02", "text": "Chào bạn!"})
        for status in ("accepted", "accepted", "delivered", "failed"):
            self.m.handle_status({"message_id": mid, "recipient_id": "u02",
                                  "status": status, "error_code": None})
        self.assertEqual([d["status"] for k, d in self.fc.events if k == "message_status"],
                         ["accepted", "delivered"])        # không lặp, không lùi

    def test_hop_failure_marks_failed(self):
        mid = self.m.send_message(None, "hi")
        on_result = next(iter(self.fc.results.values()))
        on_result("DELIVERY_TIMEOUT")
        self.assertIn(("message_status", {"message_id": mid, "recipient_id": None,
                                          "status": "failed", "error_code": "DELIVERY_TIMEOUT"}),
                      self.fc.events)

    def test_incoming_dedupe(self):
        msg = {"message_id": str(uuid.uuid4()), "from": "u02", "to": None,
               "text": "hi", "sent_at": "2026-10-24T00:00:00Z"}
        self.m.handle_message("server", msg)
        self.m.handle_message("server", msg)
        self.m.handle_message("server", {**msg, "text": None})    # sai kiểu: bỏ
        self.assertEqual(self.fc.events, [("message_received", msg)])


# ============================================================================
# End-to-end với server.py thật (TLS + UDP localhost)
# ============================================================================

class LiveServer:
    """server.py của Người 2, chạy trong tiến trình test trên cổng ngẫu nhiên."""

    def __init__(self, n_users=3):
        import gen_cert
        from server import CollabServer, UdpService, build_tls_context, open_udp_socket
        from server_udp import ServerUDP
        from sessions import Account, AccountStore, SessionManager, hash_password

        self.tmp = tempfile.mkdtemp(prefix="cc-test-")
        certs = gen_cert.generate(os.path.join(self.tmp, "certs"), dns_names=("localhost",))
        self.ca_file = certs["ca.crt"]
        store = AccountStore(Account(f"u{i:02d}", f"user{i:02d}",
                                     hash_password(f"pass{i:02d}", iterations=1_000))
                             for i in range(1, n_users + 1))
        self.sessions = SessionManager(store)
        udp = open_udp_socket("127.0.0.1", 0)
        self.udp = ServerUDP(udp, role="server")
        UdpService(self.sessions, self.udp)
        self.udp.start()
        self.tcp = CollabServer(self.sessions, host="127.0.0.1", tcp_port=0,
                                udp_port=udp.getsockname()[1],
                                ssl_context=build_tls_context(certs["server.crt"],
                                                              certs["server.key"]))
        self.tcp.start()

    def client(self):
        return ChatClient("127.0.0.1", self.tcp.tcp_port, ca_file=self.ca_file)

    def close(self):
        self.tcp.stop()
        self.udp.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.server = LiveServer()
        self.clients = []

    def tearDown(self):
        for c in self.clients:
            c.close()
        self.server.close()

    def connect(self, n):
        c = self.server.client()
        self.clients.append(c)
        c.login(f"user{n:02d}", f"pass{n:02d}")
        self.assertTrue(wait_until(lambda: c.get_status()["state"] == "connected"),
                        c.get_status())
        return c

    def test_login_users_and_chat(self):
        a, b = self.connect(1), self.connect(2)
        self.assertEqual(a.get_status()["user"], {"user_id": "u01", "username": "user01"})
        self.assertTrue(wait_until(lambda: len(a.list_users()["users"]) == 2))

        mid = a.send_message("u02", "Chào Bob")
        self.assertTrue(wait_until(lambda: any(m["message_id"] == mid
                                               for m in events_of(b, "message_received"))))
        got = next(m for m in events_of(b, "message_received") if m["message_id"] == mid)
        self.assertEqual((got["from"], got["to"], got["text"]), ("u01", "u02", "Chào Bob"))
        self.assertTrue(wait_until(lambda: [s["status"] for s in events_of(a, "message_status")
                                            if s["message_id"] == mid] == ["accepted", "delivered"]))

        gid = b.send_message(None, "Chào cả nhóm")
        self.assertTrue(wait_until(lambda: any(m["message_id"] == gid and m["to"] is None
                                               for m in events_of(a, "message_received"))))

        with self.assertRaises(AppError) as cm:               # u03 chưa đăng nhập: chặn ngay
            a.send_message("u03", "có ai không")
        self.assertEqual(cm.exception.code, "USER_OFFLINE")

        self.assertEqual(a.logout(), "disconnecting")
        self.assertTrue(wait_until(lambda: a.get_status()["state"] == "disconnected"))
        self.assertTrue(wait_until(lambda: [u["user_id"] for u in b.list_users()["users"]] == ["u02"]))
        with self.assertRaises(AppError):
            a.send_message(None, "sau khi logout")

    def test_wrong_password(self):
        c = self.server.client()
        self.clients.append(c)
        c.login("user01", "sai")
        self.assertTrue(wait_until(lambda: c.get_status()["state"] == "disconnected"
                                   and c.get_status()["last_error"] is not None))
        self.assertEqual(c.get_status()["last_error"]["code"], "INVALID_CREDENTIALS")

    def test_missing_ca(self):
        c = ChatClient("127.0.0.1", self.server.tcp.tcp_port, ca_file="/khong/co/ca.crt")
        self.clients.append(c)
        c.login("user01", "pass01")
        self.assertTrue(wait_until(lambda: c.get_status()["last_error"] is not None))
        self.assertEqual(c.get_status()["last_error"]["code"], "CA_NOT_FOUND")

    def test_file_transfer(self):
        a, b = self.connect(1), self.connect(2)
        tmp = tempfile.mkdtemp(prefix="cc-dl-")
        self.addCleanup(shutil.rmtree, tmp, True)
        a.attach_file_service(FileTransferManager(a, download_dir=os.path.join(tmp, "a")))
        b.attach_file_service(FileTransferManager(b, download_dir=os.path.join(tmp, "b")))
        self.assertTrue(wait_until(lambda: a.is_online("u02")))

        data = os.urandom(50_000)
        tid = a.create_upload("u02", "báo cáo.pdf", len(data))
        path = a.begin_upload(tid, len(data))
        with open(path, "wb") as f:
            f.write(data)
        a.submit_uploaded_file(tid, path, hashlib.sha256(data).hexdigest())

        self.assertTrue(wait_until(lambda: any(o["transfer_id"] == tid for o in events_of(b, "file_offer"))))
        offer = next(o for o in events_of(b, "file_offer") if o["transfer_id"] == tid)
        self.assertEqual(offer["filename"], "báo cáo.pdf")      # tên gốc, không phải UUID
        b.accept_transfer(tid)
        done = lambda c: any(e["transfer_id"] == tid for e in events_of(c, "file_completed"))  # noqa: E731
        self.assertTrue(wait_until(lambda: done(a) and done(b), timeout=30))
        with open(b.get_download_path(tid), "rb") as f:
            self.assertEqual(f.read(), data)
        self.assertTrue(wait_until(lambda: not os.path.exists(path)))   # tệp tạm đã dọn


# ============================================================================
# HTTP bridge
# ============================================================================

class HttpBridgeTests(unittest.TestCase):
    def setUp(self):
        self.server = LiveServer()
        self.client = self.server.client()
        self.bridge = HttpBridge(self.client, "127.0.0.1", 0,
                                 static_dir=os.path.join(self.server.tmp, "web"))
        threading.Thread(target=self.bridge.serve_forever, daemon=True).start()
        self.assertTrue(self.bridge.ready.wait(5))
        self.token = self.call("GET", "/api/bootstrap")[1]["data"]["local_token"]

    def tearDown(self):
        self.bridge.shutdown()
        self.client.close()
        self.server.close()

    def call(self, method, path, body=None, *, token=True, headers=None, raw=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.bridge.port, timeout=10)
        h = dict(headers or {})
        if token and method != "GET":
            h["X-Local-Token"] = self.token
        if body is not None:
            raw = json.dumps(body).encode()
            h["Content-Type"] = "application/json"
        conn.request(method, path, body=raw, headers=h)
        resp = conn.getresponse()
        data = resp.read()
        conn.close()
        is_json = resp.getheader("Content-Type", "").startswith("application/json")
        return resp.status, (json.loads(data) if is_json else data)

    def test_api_flow(self):
        self.assertEqual(self.call("POST", "/api/login", {"username": "user01", "password": "pass01"},
                                   token=False)[0], 403)
        self.assertEqual(self.call("GET", "/api/users")[1]["error"]["code"], "NOT_AUTHENTICATED")
        status, body = self.call("POST", "/api/login", {"username": "user01", "password": "pass01"})
        self.assertEqual((status, body), (202, {"ok": True, "data": {"status": "connecting"}}))
        self.assertTrue(wait_until(lambda: self.call("GET", "/api/status")[1]["data"]["state"] == "connected"))
        self.assertEqual(self.call("POST", "/api/login", {"username": "user01", "password": "pass01"})[0], 409)

        status, body = self.call("GET", "/api/users")
        self.assertEqual(status, 200)
        self.assertEqual(body["data"]["users"], [{"user_id": "u01", "username": "user01"}])

        status, body = self.call("POST", "/api/messages", {"to": None, "text": "hi"})
        self.assertEqual((status, body["data"]["status"]), (202, "queued"))
        self.assertEqual(self.call("POST", "/api/messages", {"to": None, "text": "x" * 801})[0], 413)

        status, body = self.call("GET", "/api/events?after=0")
        types = [e["type"] for e in body["data"]["events"]]
        self.assertIn("connection_changed", types)
        # Chỉ có user01 online → tin chung thất bại NO_RECIPIENTS (báo qua sự kiện).
        self.assertTrue(wait_until(lambda: any(
            e["type"] == "message_status" and e["data"]["error_code"] == "NO_RECIPIENTS"
            for e in self.call("GET", "/api/events?after=0")[1]["data"]["events"])))
        status, body = self.call("GET", "/api/events?after=999999")
        self.assertEqual((status, body["error"]["code"]), (409, "EVENT_CURSOR_EXPIRED"))
        self.assertIn("current_cursor", body["error"])

        status, body = self.call("POST", "/api/logout", {})
        self.assertIn(status, (200, 202))
        self.assertTrue(wait_until(lambda: self.call("GET", "/api/status")[1]["data"]["state"] == "disconnected"))

    def test_http_errors(self):
        self.assertEqual(self.call("GET", "/api/khong-co")[0], 404)
        self.assertEqual(self.call("DELETE", "/api/status")[0], 405)
        self.assertEqual(self.call("GET", "/api/status", headers={"Host": "evil.com"})[0], 403)
        self.assertEqual(self.call("POST", "/api/messages", {"text": "x"},
                                   headers={"Origin": "http://evil.com"})[0], 403)
        self.assertEqual(self.call("POST", "/api/login", raw=b"{not json",
                                   headers={"Content-Type": "application/json"})[0], 400)
        self.assertEqual(self.call("GET", "/index.html")[0], 404)       # chưa có web/
        self.assertEqual(self.call("GET", "/../../etc/passwd")[0], 404)

    def test_file_upload_flow(self):
        self.client.attach_file_service(FileTransferManager(
            self.client, download_dir=os.path.join(self.server.tmp, "dl")))
        other = self.server.client()
        self.addCleanup(other.close)
        other.login("user02", "pass02")
        self.call("POST", "/api/login", {"username": "user01", "password": "pass01"})
        self.assertTrue(wait_until(lambda: self.client.is_online("u02")))

        status, body = self.call("POST", "/api/files/offers", {"to": "u02", "filename": "a.txt", "size": 5})
        self.assertEqual((status, body["data"]["status"]), (201, "awaiting_upload"))
        tid = body["data"]["transfer_id"]
        self.assertEqual(self.call("GET", "/api/files")[1]["data"]["transfers"][0]["status"],
                         "awaiting_upload")
        self.assertEqual(self.call("PUT", f"/api/files/{tid}/content", raw=b"12345",
                                   headers={"Content-Type": "application/octet-stream"})[0], 202)
        self.assertEqual(self.call("PUT", f"/api/files/{tid}/content", raw=b"12345")[0], 404)
        self.assertEqual(self.call("GET", f"/api/files/{tid}/download")[0], 409)   # chiều gửi

        status, body = self.call("POST", "/api/files/offers", {"to": "u02", "filename": "b.txt", "size": 5})
        tid2 = body["data"]["transfer_id"]
        status, body = self.call("PUT", f"/api/files/{tid2}/content", raw=b"123")
        self.assertEqual((status, body["error"]["code"]), (400, "INVALID_INPUT"))   # sai size


if __name__ == "__main__":
    unittest.main()
