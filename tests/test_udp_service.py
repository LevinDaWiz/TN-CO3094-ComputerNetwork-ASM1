"""Kiểm thử ``server.UdpService``: UDP_BIND, USER_LIST, chat qua UDP, timeout, LOGOUT.

Phần lớn dùng mạng giả lập trong bộ nhớ (transport chế độ thủ công, server là
``ServerUDP`` thật, client là ``ReliableUDP`` thật của Người 1). Cuối file có một
test end-to-end bằng socket thật: TCP login + UDP bind + chat.

Chạy::

    python -m unittest tests.test_udp_service -v
"""

import base64
import os
import socket
import sys
import threading
import unittest
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from framing import encode_frame, recv_frame  # noqa: E402
from protocol import (CryptoContext, Header, PacketType, decode_ack, decode_json,  # noqa: E402
                      decode_packet, encode_json, encode_packet, peek_header)
from reliable_udp import ReliableUDP  # noqa: E402
from server import ChatRouter, CollabServer, UdpService, open_udp_socket  # noqa: E402
from server_udp import ServerUDP  # noqa: E402
from sessions import Account, AccountStore, SessionManager, hash_password  # noqa: E402

STORE = AccountStore(Account(f"u{i:02d}", f"user{i:02d}",
                             hash_password(f"pass{i:02d}", iterations=1_000))
                     for i in range(1, 11))
SERVER = ("10.0.0.1", 9001)
SENT_AT = "2026-10-16T10:00:00Z"


def new_id():
    return str(uuid.uuid4())


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


class Net:
    """Mạng giả: chuyển datagram giữa các endpoint, có thể chặn theo đích."""

    def __init__(self):
        self.endpoints = {}
        self.queue = []
        self.log = []                 # mọi datagram đã gửi: (src, dst, wire)
        self.blocked = set()          # địa chỉ đích bị "đứt mạng"

    def sender(self, src):
        def send(wire, dst):
            self.queue.append((src, dst, wire))
            self.log.append((src, dst, wire))
        return send

    def pump(self, rounds=60):
        """Giao gói -> dispatch callback -> tick, lặp đến khi yên."""
        for _ in range(rounds):
            queue, self.queue = self.queue, []
            for src, dst, wire in queue:
                if dst not in self.blocked and dst in self.endpoints:
                    self.endpoints[dst].receive_datagram(wire, src)
            events = sum(t.dispatch_events() for t in self.endpoints.values())
            for t in self.endpoints.values():
                t.tick()
            if not queue and not self.queue and events == 0:
                return


class Client:
    """Client giả: dùng khóa từ authenticate (bỏ qua TCP), transport ReliableUDP thật."""

    def __init__(self, net, mgr, n, port):
        self.addr = ("10.0.0.2", port)
        self.session = mgr.authenticate(f"user{n:02d}", f"pass{n:02d}")
        s = self.session
        self.t = ReliableUDP(send_datagram=net.sender(self.addr), role="client")
        self.t.register_peer("server", s.session_id, SERVER,
                             CryptoContext(s.c2s_key, s.c2s_nonce_prefix),
                             CryptoContext(s.s2c_key, s.s2c_nonce_prefix))
        self.received = []
        self.t.on_payload(lambda p, st, kind, pl: self.received.append(
            (st, PacketType(kind), decode_json(pl))))
        net.endpoints[self.addr] = self.t

    def send(self, stream, kind, obj):
        return self.t.send("server", stream, kind, encode_json(obj))

    def bind(self):
        self.send(1, PacketType.UDP_BIND, {})

    def chat(self, to, text, message_id=None):
        mid = message_id or new_id()
        self.send(2, PacketType.CHAT, {"message_id": mid, "to": to, "text": text})
        return mid

    def of(self, kind):
        return [d for _, k, d in self.received if k == kind]

    def last_users(self):
        return [u["user_id"] for u in self.of(PacketType.USER_LIST)[-1]["users"]]


class UdpServiceTestBase(unittest.TestCase):
    def setUp(self):
        self.net = Net()
        self.clock = FakeClock()
        self.mgr = SessionManager(STORE)
        self.server = ServerUDP(send_datagram=self.net.sender(SERVER), role="server",
                                clock=self.clock)
        self.net.endpoints[SERVER] = self.server
        self.service = UdpService(self.mgr, self.server,
                                  router=ChatRouter(self.mgr, clock=lambda: SENT_AT),
                                  clock=self.clock)
        self.ports = iter(range(50001, 50100))

    def client(self, n, bind=True):
        c = Client(self.net, self.mgr, n, next(self.ports))
        if bind:
            c.bind()
            self.net.pump()
        return c


class BindAndPresenceTests(UdpServiceTestBase):
    def test_bind_ok_then_user_list(self):
        a = self.client(1)
        self.assertEqual(a.of(PacketType.UDP_BIND_OK), [{}])
        kinds = [k for st, k, _ in a.received if st == 1]
        self.assertEqual(kinds[:2], [PacketType.UDP_BIND_OK, PacketType.USER_LIST])   # đúng thứ tự
        self.assertEqual(a.last_users(), ["u01"])
        s = self.mgr.get_session(a.session.session_id)
        self.assertEqual((s.bound, s.udp_addr), (True, a.addr))

    def test_user_list_broadcast_on_join(self):
        a = self.client(1)
        rev_a = a.of(PacketType.USER_LIST)[-1]["revision"]
        b = self.client(2)
        self.assertEqual(a.last_users(), ["u01", "u02"])
        self.assertEqual(b.last_users(), ["u01", "u02"])
        self.assertGreater(a.of(PacketType.USER_LIST)[-1]["revision"], rev_a)

    def test_forged_bind_is_ignored(self):
        c = Client(self.net, self.mgr, 3, 50099)
        s = c.session
        forged = encode_packet(Header(PacketType.UDP_BIND, s.session_id, 1, 1), encode_json({}),
                               CryptoContext(os.urandom(32), s.c2s_nonce_prefix))
        self.server.receive_datagram(forged, c.addr)
        self.net.pump()
        self.assertFalse(self.mgr.get_session(s.session_id).bound)
        self.assertEqual(c.received, [])

    def test_bind_for_expired_session_is_ignored(self):
        c = Client(self.net, self.mgr, 4, 50098)
        self.mgr.remove_session(c.session.session_id)      # như sweeper xóa sau 15 s
        c.bind()
        self.net.pump()
        self.assertEqual(c.received, [])
        self.assertEqual(self.server.peers, {})

    def test_garbage_does_not_crash(self):
        a = self.client(1)
        for raw in (b"", os.urandom(30), b"CC" + os.urandom(60), os.urandom(1300)):
            self.server.receive_datagram(raw, ("10.9.9.9", 1234))
        self.net.pump()
        a.chat("u01", "vẫn sống")
        self.net.pump()
        self.assertEqual(a.of(PacketType.CHAT)[-1]["text"], "vẫn sống")


class ChatOverUdpTests(UdpServiceTestBase):
    def setUp(self):
        super().setUp()
        self.a, self.b, self.c = self.client(1), self.client(2), self.client(3)

    def statuses(self, client, mid):
        return [(s["recipient_id"], s["status"], s["error_code"])
                for s in client.of(PacketType.CHAT_STATUS) if s["message_id"] == mid]

    def test_private_chat_accepted_then_delivered(self):
        mid = self.a.chat("u02", "Chào bạn!")
        self.net.pump()
        self.assertEqual(self.b.of(PacketType.CHAT),
                         [{"message_id": mid, "from": "u01", "to": "u02",
                           "text": "Chào bạn!", "sent_at": SENT_AT}])
        self.assertEqual(self.statuses(self.a, mid),
                         [("u02", "accepted", None), ("u02", "delivered", None)])
        self.assertEqual(self.c.of(PacketType.CHAT), [])

    def test_global_chat_per_recipient_status(self):
        mid = self.a.chat(None, "Xin chào cả nhóm")
        self.net.pump()
        self.assertEqual(len(self.b.of(PacketType.CHAT)), 1)
        self.assertEqual(len(self.c.of(PacketType.CHAT)), 1)
        self.assertEqual(self.a.of(PacketType.CHAT), [])        # không gửi lại người gửi
        st = self.statuses(self.a, mid)
        self.assertEqual(sorted(x for x in st if x[1] == "accepted"),
                         [("u02", "accepted", None), ("u03", "accepted", None)])
        self.assertEqual(sorted(x for x in st if x[1] == "delivered"),
                         [("u02", "delivered", None), ("u03", "delivered", None)])

    def test_private_to_offline(self):
        mid = self.a.chat("u09", "x")
        self.net.pump()
        self.assertEqual(self.statuses(self.a, mid), [("u09", "failed", "USER_OFFLINE")])

    def test_invalid_message_id_gets_error(self):
        self.a.send(2, PacketType.CHAT, {"message_id": "abc", "to": "u02", "text": "x"})
        self.net.pump()
        err = self.a.of(PacketType.ERROR)
        self.assertEqual((err[0]["code"], err[0]["reference_id"]), ("INVALID_PACKET", None))
        self.assertEqual(self.b.of(PacketType.CHAT), [])

    def test_duplicate_message_id_delivered_once(self):
        mid = self.a.chat("u02", "một lần")
        self.a.chat("u02", "một lần", message_id=mid)    # seq mới, cùng message_id
        self.net.pump()
        self.assertEqual(len(self.b.of(PacketType.CHAT)), 1)

    def test_recipient_lost_before_ack_reports_failed(self):
        self.net.blocked.add(self.b.addr)                # mạng tới B bị đứt
        mid = self.a.chat("u02", "không tới")
        self.net.pump()
        self.assertEqual(self.statuses(self.a, mid), [("u02", "accepted", None)])
        # 16 s sau: A còn gửi heartbeat, B im lặng -> transport đóng B.
        self.clock.now += 16
        self.a.t.send("server", 0, PacketType.HEARTBEAT, encode_json({}))
        self.c.t.send("server", 0, PacketType.HEARTBEAT, encode_json({}))
        self.a.t.tick()
        self.c.t.tick()
        self.net.pump()
        self.assertIsNone(self.mgr.get_session(self.b.session.session_id))
        self.assertIn(("u02", "failed", "USER_OFFLINE"), self.statuses(self.a, mid))
        self.assertEqual(self.a.last_users(), ["u01", "u03"])


class TimeoutAndLogoutTests(UdpServiceTestBase):
    def test_heartbeat_timeout_removes_user(self):
        a, b = self.client(1), self.client(2)
        self.clock.now += 16
        a.t.send("server", 0, PacketType.HEARTBEAT, encode_json({}))   # chỉ A còn sống
        a.t.tick()
        self.net.pump()
        self.assertIsNone(self.mgr.get_session(b.session.session_id))
        self.assertIsNotNone(self.mgr.get_session(a.session.session_id))
        self.assertEqual(a.last_users(), ["u01"])
        self.assertEqual(self.mgr.list_online_users(), [{"user_id": "u01", "username": "user01"}])
        # B đăng nhập lại được ngay (phiên cũ đã dọn).
        self.mgr.authenticate("user02", "pass02")

    def test_logout_cleans_up_and_updates_list(self):
        a, b = self.client(1), self.client(2)
        a.send(1, PacketType.LOGOUT, {})
        self.net.pump()
        self.assertIsNone(self.mgr.get_session(a.session.session_id))
        self.assertNotIn(str(a.session.session_id), self.server.peers)
        self.assertEqual(b.last_users(), ["u02"])
        # Sau logout: chat của A bị bỏ, B không nhận gì.
        before = len(b.received)
        raw = encode_packet(Header(PacketType.CHAT, a.session.session_id, 2, 9),
                            encode_json({"message_id": new_id(), "to": "u02", "text": "x"}),
                            CryptoContext(a.session.c2s_key, a.session.c2s_nonce_prefix,
                                          counter=10_000))
        self.server.receive_datagram(raw, a.addr)
        self.net.pump()
        self.assertEqual(len(b.received), before)
        # Đăng nhập lại được.
        self.mgr.authenticate("user01", "pass01")

    def logout_wire(self, a):
        """Datagram LOGOUT mà A đã gửi (để giả lập gói bị truyền lại)."""
        rx = CryptoContext(a.session.c2s_key, a.session.c2s_nonce_prefix)
        for src, dst, wire in self.net.log:
            if src == a.addr and peek_header(wire).packet_type == PacketType.LOGOUT:
                return wire, decode_packet(wire, rx).header.seq
        self.fail("không thấy LOGOUT")

    def acks_to(self, a):
        rx = CryptoContext(a.session.s2c_key, a.session.s2c_nonce_prefix)
        return [decode_ack(decode_packet(w, rx).payload) for src, dst, w in self.net.log
                if src == SERVER and dst == a.addr
                and peek_header(w).packet_type == PacketType.ACK]

    def test_duplicate_logout_acked_within_60s(self):
        a = self.client(1)
        a.send(1, PacketType.LOGOUT, {})
        self.net.pump()
        wire, seq = self.logout_wire(a)
        acks_before = self.acks_to(a).count((1, seq))
        self.assertEqual(acks_before, 1)                       # ACK lần đầu (transport)
        self.clock.now += 30
        self.server.receive_datagram(wire, a.addr)             # LOGOUT bị truyền lại
        self.assertEqual(self.acks_to(a).count((1, seq)), 2)  # ACK lại từ tombstone
        self.server.receive_datagram(wire, ("10.0.0.99", 1))   # sai địa chỉ: không ACK
        self.assertEqual(self.acks_to(a).count((1, seq)), 2)
        self.clock.now += 31                                   # quá 60 s
        self.server.receive_datagram(wire, a.addr)
        self.assertEqual(self.acks_to(a).count((1, seq)), 2)

    def test_logout_ack_uses_fresh_nonces(self):
        # Nonce của ACK từ tombstone không được trùng nonce transport đã dùng (AES-GCM).
        a = self.client(1)
        a.send(1, PacketType.LOGOUT, {})
        self.net.pump()
        wire, _ = self.logout_wire(a)
        self.server.receive_datagram(wire, a.addr)
        self.server.receive_datagram(wire, a.addr)
        nonces = [w[23:35] for src, dst, w in self.net.log if src == SERVER and dst == a.addr]
        self.assertEqual(len(nonces), len(set(nonces)))


class EndToEndRealSocketTests(unittest.TestCase):
    """TCP login (CollabServer) + UDP (ServerUDP + UdpService) trên localhost thật."""

    def test_login_bind_and_private_chat(self):
        mgr = SessionManager(STORE)
        udp_sock = open_udp_socket("127.0.0.1", 0)
        udp_port = udp_sock.getsockname()[1]
        transport = ServerUDP(udp_sock, role="server")
        UdpService(mgr, transport)
        transport.start()
        tcp = CollabServer(mgr, host="127.0.0.1", tcp_port=0, udp_port=udp_port)
        tcp.start()
        clients = []
        try:
            got = {}
            for n in (1, 2):
                with socket.create_connection(("127.0.0.1", tcp.tcp_port), timeout=5) as s:
                    s.sendall(encode_frame({"type": "LOGIN", "username": f"user{n:02d}",
                                            "password": f"pass{n:02d}"}))
                    ok = recv_frame(s)
                self.assertEqual(ok["type"], "LOGIN_OK")
                key = lambda f: base64.b64decode(ok[f])   # noqa: E731
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                t = ReliableUDP(sock, role="client")
                events = {"bind": threading.Event(), "chat": threading.Event(),
                          "delivered": threading.Event(), "list2": threading.Event()}

                def on_payload(peer, stream, kind, payload, ev=events, n=n):
                    obj = decode_json(payload)
                    if kind == PacketType.UDP_BIND_OK:
                        ev["bind"].set()
                    elif kind == PacketType.USER_LIST and len(obj["users"]) == 2:
                        ev["list2"].set()
                    elif kind == PacketType.CHAT:
                        got[n] = obj
                        ev["chat"].set()
                    elif kind == PacketType.CHAT_STATUS and obj["status"] == "delivered":
                        ev["delivered"].set()
                t.on_payload(on_payload)
                t.register_peer("server", ok["session_id"], ("127.0.0.1", ok["udp_port"]),
                                CryptoContext(key("c2s_key"), key("c2s_nonce_prefix")),
                                CryptoContext(key("s2c_key"), key("s2c_nonce_prefix")))
                t.start()
                t.send("server", 1, PacketType.UDP_BIND, encode_json({}))
                self.assertTrue(events["bind"].wait(5), f"user{n:02d} không nhận UDP_BIND_OK")
                clients.append((t, events))
            (ta, ea), (tb, eb) = clients
            self.assertTrue(ea["list2"].wait(5) and eb["list2"].wait(5), "USER_LIST thiếu người")
            ta.send("server", 2, PacketType.CHAT,
                    encode_json({"message_id": new_id(), "to": "u02", "text": "Chào qua UDP!"}))
            self.assertTrue(eb["chat"].wait(5), "B không nhận được chat")
            self.assertEqual((got[2]["from"], got[2]["text"]), ("u01", "Chào qua UDP!"))
            self.assertTrue(ea["delivered"].wait(5), "A không nhận được trạng thái delivered")
        finally:
            for t, _ in clients:
                t.close()
            tcp.stop()
            transport.close()


if __name__ == "__main__":
    unittest.main()
