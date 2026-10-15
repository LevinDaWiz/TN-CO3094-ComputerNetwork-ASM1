"""Kiểm thử ``server_udp.ServerUDP.on_unknown_datagram`` cho luồng UDP_BIND.

Mô phỏng đúng cách server sẽ dùng: gói UDP_BIND đầu tiên đến khi phiên chưa
``register_peer``; server xác thực bằng khóa phiên, ``bind_udp`` +
``register_peer`` với địa chỉ nguồn thực tế rồi đưa lại gói cho transport để
được ACK và giao lên ``on_payload``.

Chạy::

    python -m unittest tests.test_server_udp -v
"""

import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from protocol import (AppError, CryptoContext, Header, PacketType, decode_ack,  # noqa: E402
                      decode_packet, encode_json, encode_packet, peek_header)
from reliable_udp import ReliableUDP  # noqa: E402
from server_udp import ServerUDP  # noqa: E402
from sessions import Account, AccountStore, SessionManager, hash_password  # noqa: E402

STORE = AccountStore([Account("u01", "user01", hash_password("pass01", iterations=1_000)),
                      Account("u02", "user02", hash_password("pass02", iterations=1_000))])
SERVER_ADDR = ("127.0.0.1", 9001)
CLIENT_ADDR = ("127.0.0.1", 50001)


class Wire:
    """Ghi lại datagram mỗi bên gửi đi (transport chế độ thủ công)."""

    def __init__(self):
        self.sent = []

    def __call__(self, wire, address):
        self.sent.append((wire, address))

    def take(self):
        out, self.sent = self.sent, []
        return out


class UdpBindHookTests(unittest.TestCase):
    def setUp(self):
        self.mgr = SessionManager(STORE)
        self.session = self.mgr.authenticate("user01", "pass01")
        self.server_wire, self.client_wire = Wire(), Wire()
        self.server = ServerUDP(send_datagram=self.server_wire, role="server")
        self.client = ReliableUDP(send_datagram=self.client_wire, role="client")
        s = self.session
        # Client: biết địa chỉ server và khóa từ LOGIN_OK.
        self.client.register_peer("server", s.session_id, SERVER_ADDR,
                                  CryptoContext(s.c2s_key, s.c2s_nonce_prefix),
                                  CryptoContext(s.s2c_key, s.s2c_nonce_prefix))
        self.payloads = []
        self.server.on_payload(lambda *args: self.payloads.append(args))
        self.unknown_calls = []

    def bind_handler(self, raw, address):
        """Cách server.py sẽ xử lý gói của phiên chưa đăng ký."""
        self.unknown_calls.append(address)
        session = self.mgr.get_session(peek_header(raw).session_id)
        if session is None or session.bound:
            return
        rx = CryptoContext(session.c2s_key, session.c2s_nonce_prefix)
        try:
            packet = decode_packet(raw, rx)
        except AppError:
            return                                     # sai khóa/tag: bỏ, không ACK
        h = packet.header
        if h.packet_type != PacketType.UDP_BIND or h.stream_id != 1:
            return
        self.mgr.bind_udp(session.session_id, address)
        self.server.register_peer(str(session.session_id), session.session_id, address,
                                  CryptoContext(session.s2c_key, session.s2c_nonce_prefix), rx)
        self.server.receive_datagram(raw, address)     # để transport ACK + giao lên

    def client_send_bind(self):
        self.client.send("server", 1, PacketType.UDP_BIND, encode_json({}))
        self.client.tick()
        (raw, addr), = self.client_wire.take()
        self.assertEqual(addr, SERVER_ADDR)
        return raw

    # ----- luồng chuẩn ------------------------------------------------------

    def test_udp_bind_flow(self):
        self.server.on_unknown_datagram(self.bind_handler)
        raw = self.client_send_bind()
        self.assertFalse(self.server.receive_datagram(raw, CLIENT_ADDR))   # lần đầu: chưa có peer
        sid = self.session.session_id
        # sessions đã ghi địa chỉ nguồn thực tế, transport đã có peer.
        self.assertEqual(self.mgr.get_session(sid).udp_addr, CLIENT_ADDR)
        self.assertIn(str(sid), self.server.peers)
        # Transport server đã ACK gói UDP_BIND về đúng địa chỉ client.
        (ack, addr), = self.server_wire.take()
        self.assertEqual(addr, CLIENT_ADDR)
        self.assertTrue(self.client.receive_datagram(ack, SERVER_ADDR))
        rx_client = CryptoContext(self.session.s2c_key, self.session.s2c_nonce_prefix)
        self.assertEqual(decode_ack(decode_packet(ack, rx_client).payload), (1, 1))
        # UDP_BIND được giao lên ứng dụng đúng một lần.
        self.server.dispatch_events()
        self.assertEqual(self.payloads, [(str(sid), 1, PacketType.UDP_BIND, b"{}")])
        # Server trả UDP_BIND_OK được qua transport bình thường.
        self.server.send(str(sid), 1, PacketType.UDP_BIND_OK, encode_json({}))
        self.server.tick()
        (ok, addr), = self.server_wire.take()
        self.assertTrue(self.client.receive_datagram(ok, SERVER_ADDR))

    def test_retransmitted_bind_after_register_goes_normal_path(self):
        self.server.on_unknown_datagram(self.bind_handler)
        raw = self.client_send_bind()
        self.server.receive_datagram(raw, CLIENT_ADDR)
        self.server_wire.take()
        # Gói trùng (client chưa thấy ACK): đi đường thường, được ACK lại, không gọi hook.
        self.assertTrue(self.server.receive_datagram(raw, CLIENT_ADDR))
        self.assertEqual(len(self.unknown_calls), 1)
        self.assertEqual(len(self.server_wire.take()), 1)
        self.server.dispatch_events()
        self.assertEqual(len(self.payloads), 1)                            # không giao lại

    # ----- bảo mật / lỗi ------------------------------------------------------

    def test_wrong_key_is_dropped_without_ack(self):
        self.server.on_unknown_datagram(self.bind_handler)
        s = self.session
        forged = encode_packet(Header(PacketType.UDP_BIND, s.session_id, 1, 1),
                               encode_json({}), CryptoContext(os.urandom(32), s.c2s_nonce_prefix))
        self.assertFalse(self.server.receive_datagram(forged, CLIENT_ADDR))
        self.assertEqual(self.server_wire.take(), [])
        self.assertFalse(self.mgr.get_session(s.session_id).bound)
        self.assertEqual(self.server.peers, {})

    def test_garbage_does_not_reach_hook(self):
        self.server.on_unknown_datagram(self.bind_handler)
        for raw in (b"", b"xx", os.urandom(50), b"CC" + os.urandom(40)):
            self.assertFalse(self.server.receive_datagram(raw, CLIENT_ADDR))
        self.assertEqual(self.unknown_calls, [])

    def test_registered_peer_wrong_address_not_sent_to_hook(self):
        self.server.on_unknown_datagram(self.bind_handler)
        raw = self.client_send_bind()
        self.server.receive_datagram(raw, CLIENT_ADDR)
        self.server_wire.take()
        # Cùng phiên nhưng đổi địa chỉ: transport bỏ, không gọi hook (1b: không đổi địa chỉ).
        self.assertFalse(self.server.receive_datagram(raw, ("127.0.0.1", 50999)))
        self.assertEqual(len(self.unknown_calls), 1)
        self.assertEqual(self.server_wire.take(), [])

    def test_without_hook_behaviour_unchanged(self):
        raw = self.client_send_bind()
        self.assertFalse(self.server.receive_datagram(raw, CLIENT_ADDR))
        self.assertEqual(self.server_wire.take(), [])

    def test_hook_exception_is_contained(self):
        def bad(raw, address):
            raise RuntimeError("lỗi trong hook")
        self.server.on_unknown_datagram(bad)
        raw = self.client_send_bind()
        with self.assertLogs("server_udp", level="ERROR"):
            self.assertFalse(self.server.receive_datagram(raw, CLIENT_ADDR))

    def test_hook_not_called_after_close(self):
        self.server.on_unknown_datagram(self.bind_handler)
        self.server.close()
        raw = self.client_send_bind()
        self.assertFalse(self.server.receive_datagram(raw, CLIENT_ADDR))
        self.assertEqual(self.unknown_calls, [])


class UdpBindRealSocketTests(unittest.TestCase):
    """Cùng luồng nhưng dùng socket UDP thật và start() (hook chạy trên thread I/O)."""

    def test_bind_over_localhost(self):
        import socket
        import threading
        mgr = SessionManager(STORE)
        s = mgr.authenticate("user02", "pass02")
        srv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv_sock.bind(("127.0.0.1", 0))
        cli_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        cli_sock.bind(("127.0.0.1", 0))
        server = ServerUDP(srv_sock, role="server")
        client = ReliableUDP(cli_sock, role="client")
        got_bind, got_ok = threading.Event(), threading.Event()

        def hook(raw, address):
            sess = mgr.get_session(peek_header(raw).session_id)
            if sess is None or sess.bound:
                return
            rx = CryptoContext(sess.c2s_key, sess.c2s_nonce_prefix)
            try:
                pkt = decode_packet(raw, rx)
            except AppError:
                return
            if pkt.header.packet_type == PacketType.UDP_BIND and pkt.header.stream_id == 1:
                mgr.bind_udp(sess.session_id, address)
                server.register_peer(str(sess.session_id), sess.session_id, address,
                                     CryptoContext(sess.s2c_key, sess.s2c_nonce_prefix), rx)
                server.receive_datagram(raw, address)

        def on_server_payload(peer_id, stream_id, kind, payload):
            if kind == PacketType.UDP_BIND:
                got_bind.set()
                server.send(peer_id, 1, PacketType.UDP_BIND_OK, encode_json({}))
                server.activate_peer(peer_id)

        server.on_unknown_datagram(hook)
        server.on_payload(on_server_payload)
        client.on_payload(lambda p, st, kind, pl: kind == PacketType.UDP_BIND_OK and got_ok.set())
        client.register_peer("server", s.session_id, srv_sock.getsockname(),
                             CryptoContext(s.c2s_key, s.c2s_nonce_prefix),
                             CryptoContext(s.s2c_key, s.s2c_nonce_prefix))
        server.start()
        client.start()
        try:
            client.send("server", 1, PacketType.UDP_BIND, encode_json({}))
            self.assertTrue(got_bind.wait(5), "server không nhận được UDP_BIND")
            self.assertTrue(got_ok.wait(5), "client không nhận được UDP_BIND_OK")
            self.assertEqual(mgr.get_session(s.session_id).udp_addr, cli_sock.getsockname())
            self.assertEqual(mgr.list_online_users(), [{"user_id": "u02", "username": "user02"}])
        finally:
            client.close()
            server.close()


if __name__ == "__main__":
    unittest.main()
