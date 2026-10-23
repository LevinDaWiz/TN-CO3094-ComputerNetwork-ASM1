"""Kiểm thử tải: 20 client đồng thời trên socket thật (TCP 9000 + UDP 9001 localhost).

Yêu cầu đề bài / phân công Người 2: server phục vụ ít nhất 10–20 client cùng lúc.
Luồng giống client thật: đăng nhập TCP -> UDP_BIND -> USER_LIST -> chat -> LOGOUT.

Chạy::

    python -m unittest tests.test_many_clients -v
"""

import base64
import os
import socket
import sys
import threading
import time
import unittest
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from framing import encode_frame, recv_frame  # noqa: E402
from protocol import CryptoContext, PacketType, decode_json, encode_json  # noqa: E402
from reliable_udp import ReliableUDP  # noqa: E402
from server import CollabServer, UdpService, open_udp_socket  # noqa: E402
from server_udp import ServerUDP  # noqa: E402
from sessions import Account, AccountStore, SessionManager, hash_password  # noqa: E402

N = 20
STORE = AccountStore(Account(f"u{i:02d}", f"user{i:02d}",
                             hash_password(f"pass{i:02d}", iterations=1_000))
                     for i in range(1, N + 1))
TIMEOUT = 15.0          # giây cho mỗi bước (rộng tay cho máy chậm / Windows)


def wait_until(predicate, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


class Client:
    """Client tối giản: TCP login rồi ReliableUDP thật, ghi lại mọi gói nhận được."""

    def __init__(self, n, tcp_port):
        self.n = n
        self.user_id = f"u{n:02d}"
        self.tcp_port = tcp_port
        self.lock = threading.Lock()
        self.bound = threading.Event()
        self.users = []                 # user_id trong USER_LIST mới nhất (revision lớn nhất)
        self.revision = -1
        self.chats = []
        self.statuses = []
        self.transport = None

    def login(self):
        with socket.create_connection(("127.0.0.1", self.tcp_port), timeout=10) as s:
            s.sendall(encode_frame({"type": "LOGIN", "username": f"user{self.n:02d}",
                                    "password": f"pass{self.n:02d}"}))
            self.reply = recv_frame(s)
        return self.reply

    def start_udp(self):
        r = self.reply
        key = lambda f: base64.b64decode(r[f])   # noqa: E731
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        self.transport = ReliableUDP(sock, role="client")
        self.transport.on_payload(self._on_payload)
        self.transport.register_peer("server", r["session_id"], ("127.0.0.1", r["udp_port"]),
                                     CryptoContext(key("c2s_key"), key("c2s_nonce_prefix")),
                                     CryptoContext(key("s2c_key"), key("s2c_nonce_prefix")))
        self.transport.start()
        self.send(1, PacketType.UDP_BIND, {})

    def send(self, stream, kind, obj):
        return self.transport.send("server", stream, kind, encode_json(obj))

    def chat(self, to, text):
        mid = str(uuid.uuid4())
        self.send(2, PacketType.CHAT, {"message_id": mid, "to": to, "text": text})
        return mid

    def _on_payload(self, peer, stream, kind, payload):
        obj = decode_json(payload)
        with self.lock:
            if kind == PacketType.UDP_BIND_OK:
                self.transport.activate_peer("server")
                self.bound.set()
            elif kind == PacketType.USER_LIST and obj["revision"] >= self.revision:
                # Danh sách nhỏ (20 user) nên luôn vừa 1 phần.
                self.revision = obj["revision"]
                self.users = [u["user_id"] for u in obj["users"]]
            elif kind == PacketType.CHAT:
                self.chats.append(obj)
            elif kind == PacketType.CHAT_STATUS:
                self.statuses.append(obj)

    def snapshot(self):
        with self.lock:
            return list(self.users), list(self.chats), list(self.statuses)

    def close(self):
        if self.transport is not None:
            self.transport.close()


class TwentyClientsTests(unittest.TestCase):
    def setUp(self):
        self.mgr = SessionManager(STORE)
        udp = open_udp_socket("127.0.0.1", 0)
        self.udp_transport = ServerUDP(udp, role="server")
        UdpService(self.mgr, self.udp_transport)
        self.udp_transport.start()
        self.tcp = CollabServer(self.mgr, host="127.0.0.1", tcp_port=0,
                                udp_port=udp.getsockname()[1])
        self.tcp.start()
        self.clients = [Client(n, self.tcp.tcp_port) for n in range(1, N + 1)]

    def tearDown(self):
        for c in self.clients:
            c.close()
        self.tcp.stop()
        self.udp_transport.close()

    def run_parallel(self, fn):
        barrier = threading.Barrier(N)
        errors = []

        def worker(c):
            try:
                barrier.wait()
                fn(c)
            except Exception as exc:          # gom lỗi về thread test
                errors.append((c.user_id, exc))
        threads = [threading.Thread(target=worker, args=(c,)) for c in self.clients]
        for t in threads:
            t.start()
        for t in threads:
            t.join(TIMEOUT)
        self.assertEqual(errors, [])

    def test_twenty_clients_full_flow(self):
        everyone = sorted(c.user_id for c in self.clients)

        # 1. 20 client đăng nhập TCP cùng lúc: 20 session_id khác nhau.
        self.run_parallel(lambda c: c.login())
        self.assertTrue(all(c.reply["type"] == "LOGIN_OK" for c in self.clients),
                        [c.reply for c in self.clients if c.reply["type"] != "LOGIN_OK"])
        self.assertEqual(len({c.reply["session_id"] for c in self.clients}), N)

        # 2. 20 client UDP_BIND cùng lúc.
        self.run_parallel(lambda c: c.start_udp())
        self.assertTrue(all(c.bound.wait(TIMEOUT) for c in self.clients), "có client không bind được")

        # 3. Ai cũng thấy đủ 20 người online; server ghi đúng địa chỉ UDP từng người.
        self.assertTrue(wait_until(lambda: all(c.snapshot()[0] == everyone for c in self.clients)),
                        [len(c.snapshot()[0]) for c in self.clients])
        self.assertEqual(len(self.mgr.list_online_users()), N)
        for c in self.clients:
            s = self.mgr.get_session(c.reply["session_id"])
            self.assertEqual(s.udp_addr, c.transport.sock.getsockname())

        # 4. Mỗi người gửi 1 tin chung -> mỗi người nhận đủ 19 tin của người khác, không lặp.
        for c in self.clients:
            c.chat(None, f"chung từ {c.user_id}")
        self.assertTrue(wait_until(lambda: all(len(c.snapshot()[1]) == N - 1 for c in self.clients)),
                        sorted({len(c.snapshot()[1]) for c in self.clients}))
        for c in self.clients:
            senders = sorted(m["from"] for m in c.snapshot()[1])
            self.assertEqual(senders, [u for u in everyone if u != c.user_id])

        # 5. Chat riêng theo vòng i -> i+1: ai cũng nhận đúng 1 tin riêng, người gửi thấy delivered.
        mids = {}
        for i, c in enumerate(self.clients):
            target = self.clients[(i + 1) % N].user_id
            mids[c.user_id] = (c.chat(target, f"riêng {c.user_id}->{target}"), target)

        def private_done():
            for c in self.clients:
                mid, target = mids[c.user_id]
                if not any(s["message_id"] == mid and s["status"] == "delivered"
                           and s["recipient_id"] == target for s in c.snapshot()[2]):
                    return False
            return True
        self.assertTrue(wait_until(private_done), "thiếu trạng thái delivered cho tin riêng")
        for i, c in enumerate(self.clients):
            prev = self.clients[i - 1].user_id
            private = [m for m in c.snapshot()[1] if m["to"] == c.user_id]
            self.assertEqual([m["from"] for m in private], [prev])

        # 6. 10 người LOGOUT: 10 người còn lại thấy danh sách online còn đúng 10.
        leaving, staying = self.clients[:N // 2], self.clients[N // 2:]
        for c in leaving:
            c.send(1, PacketType.LOGOUT, {})
        remaining = sorted(c.user_id for c in staying)
        self.assertTrue(wait_until(lambda: all(c.snapshot()[0] == remaining for c in staying)),
                        [c.snapshot()[0] for c in staying])
        self.assertTrue(wait_until(lambda: len(self.mgr.list_online_users()) == N // 2))
        for c in leaving:
            self.assertIsNone(self.mgr.get_session(c.reply["session_id"]))

        # Server vẫn phục vụ bình thường: người đã logout đăng nhập lại được.
        self.assertEqual(leaving[0].login()["type"], "LOGIN_OK")


if __name__ == "__main__":
    unittest.main()
