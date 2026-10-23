"""Kiểm thử chuyển tiếp tệp qua server thật (``server.FileRelay`` trong ``UdpService``).

Client là ``FileTransferManager`` thật của Người 4 (qua ``tests/fake_client.py``),
server là ``ServerUDP`` + ``UdpService`` + ``SessionManager`` thật. Mạng giả lập
trong bộ nhớ có thể mất/trùng/đảo gói, đồng hồ giả để timeout chạy nhanh. Cuối
file có một test bằng socket UDP thật.

Bảng báo lỗi đã chốt với Người 4:
  người nhận offline lúc offer      -> người gửi nhận FILE_RESULT failed/USER_OFFLINE
  người nhận mất kết nối giữa chừng -> người gửi nhận FILE_RESULT failed/USER_OFFLINE
  người gửi mất kết nối giữa chừng  -> người nhận nhận ERROR USER_OFFLINE

Chạy::

    python -m unittest tests.test_file_relay -v
"""

import os
import random
import shutil
import socket
import sys
import tempfile
import threading
import time
import unittest
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import file_transfer as ft  # noqa: E402
from fake_client import FakeClient  # noqa: E402
from protocol import CryptoContext, PacketType, decode_json, encode_json  # noqa: E402
from reliable_udp import ReliableUDP  # noqa: E402
from server import UdpService, open_udp_socket  # noqa: E402
from server_udp import ServerUDP  # noqa: E402
from sessions import Account, AccountStore, SessionManager, hash_password  # noqa: E402

STORE = AccountStore(Account(f"u{i:02d}", f"user{i:02d}",
                             hash_password(f"pass{i:02d}", iterations=1_000))
                     for i in range(1, 6))
STEP = 0.02
SERVER = ("10.0.0.9", 9001)


def payload_of(size, seed=1):
    return random.Random(seed).randbytes(size)


class Net:
    """A, B (client Người 4) <-> S (server thật), chạy thủ công bằng step()."""

    def __init__(self, tmp, *, loss=0.0, dup=0.0, reorder=False, seed=2026,
                 accept_timeout=60.0, idle_timeout=60.0, file_queue_limit=None, names=("A", "B")):
        self.now = 0.0
        self.rng = random.Random(seed)
        self.loss, self.dup, self.reorder = loss, dup, reorder
        self.tmp = tmp
        self.wire = []
        self.down = set()
        clock = lambda: self.now  # noqa: E731
        self.mgr = SessionManager(STORE)
        self.server = ServerUDP(send_datagram=self._sender(SERVER), clock=clock, role="server")
        kw = {} if file_queue_limit is None else {"file_queue_limit": file_queue_limit}
        self.service = UdpService(self.mgr, self.server, clock=clock, **kw)
        self.endpoints = {SERVER: self.server}
        self.addr, self.t, self.files, self.events, self.chats, self.session = {}, {}, {}, {}, {}, {}
        for i, name in enumerate(names, start=1):
            addr = (f"10.0.0.{i}", 40000 + i)
            s = self.mgr.authenticate(f"user{i:02d}", f"pass{i:02d}")
            t = ReliableUDP(send_datagram=self._sender(addr), clock=clock, role="client")
            t.register_peer("server", s.session_id, SERVER,
                            CryptoContext(s.c2s_key, s.c2s_nonce_prefix),
                            CryptoContext(s.s2c_key, s.s2c_nonce_prefix))
            self.addr[name], self.t[name], self.session[name] = addr, t, s
            self.endpoints[addr] = t
        # UDP_BIND như client thật, rồi mới gắn module tệp của Người 4.
        for name in names:
            self.t[name].send("server", 1, PacketType.UDP_BIND, encode_json({}))
        self.settle(20)
        for name in names:
            self.t[name].activate_peer("server")      # client gửi heartbeat như thật
            self.events[name] = []
            client = FakeClient(
                self.t[name], download_dir=os.path.join(tmp, "dl_" + name),
                on_event=lambda kind, data, n=name: self.events[n].append((kind, data)),
                clock=clock, accept_timeout=accept_timeout, idle_timeout=idle_timeout,
                autostart=False)
            self.files[name], self.chats[name] = client.files, client.chats

    def _sender(self, src):
        def send(raw, dst):
            self.wire.append((raw, src, dst))
        return send

    def step(self):
        batch, self.wire = self.wire, []
        if self.reorder:
            self.rng.shuffle(batch)
        for raw, src, dst in batch:
            if src in self.down or dst in self.down or self.rng.random() < self.loss:
                continue
            for _ in range(2 if self.rng.random() < self.dup else 1):
                if dst in self.endpoints:
                    self.endpoints[dst].receive_datagram(raw, src)
        for t in self.endpoints.values():
            t.tick()
        for t in self.endpoints.values():
            t.dispatch_events(100_000)
        for f in self.files.values():
            f.tick()
        self.now += STEP

    def run_until(self, predicate, max_steps=50_000):
        for _ in range(max_steps):
            if predicate():
                return True
            self.step()
        return predicate()

    def settle(self, steps=300):
        for _ in range(steps):
            self.step()

    def cut(self, name):
        """Mất mạng hẳn một client (không gửi/nhận gì nữa)."""
        self.down.add(self.addr[name])

    # ----- tiện ích -----

    def status(self, name, tid):
        try:
            return self.files[name].get_transfer(tid)
        except ft.AppError:
            return None

    def state(self, name, tid):
        t = self.status(name, tid)
        return t["status"] if t else None

    def error(self, name, tid):
        t = self.status(name, tid)
        return t["error_code"] if t else None

    def write_source(self, data, filename="data.bin"):
        folder = os.path.join(self.tmp, "src_" + uuid.uuid4().hex[:6])
        os.makedirs(folder)
        path = os.path.join(folder, filename)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def offer(self, data, sender="A", to="u02", **kw):
        return self.files[sender].offer_file(to, self.write_source(data), **kw)

    def offer_and_accept(self, data, sender="A", receiver="B", to="u02"):
        tid = self.offer(data, sender, to)
        assert self.run_until(lambda: self.state(receiver, tid) == ft.OFFERED, 2000)
        self.files[receiver].accept_transfer(tid)
        return tid

    def finished(self, tid, a="A", b="B"):
        return lambda: self.state(a, tid) in ft.TERMINAL and self.state(b, tid) in ft.TERMINAL

    def download_files(self, name="B"):
        folder = os.path.join(self.tmp, "dl_" + name)
        return sorted(os.listdir(folder)) if os.path.isdir(folder) else []


class FileRelayTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def net(self, **kw):
        net = Net(tempfile.mkdtemp(dir=self.tmp), **kw)
        for files in net.files.values():
            self.addCleanup(files.close)
        return net

    def assert_received(self, net, tid, data, a="A", b="B"):
        self.assertEqual(net.state(a, tid), ft.COMPLETED)
        self.assertEqual(net.state(b, tid), ft.COMPLETED)
        with open(net.files[b].get_download_path(tid), "rb") as f:
            self.assertEqual(f.read(), data)
        self.assertFalse([n for n in net.download_files(b) if n.endswith(".part")])

    # ----- thành công ------------------------------------------------------------

    def test_sizes_end_to_end_through_real_server(self):
        for size in (0, 1, 1023, 1025, 20_000):
            with self.subTest(size=size):
                net = self.net()
                data = payload_of(size)
                tid = net.offer_and_accept(data)
                self.assertTrue(net.run_until(net.finished(tid), 5000))
                self.assert_received(net, tid, data)
                net.settle(50)
                self.assertEqual(net.service.files.active_links(), 0)   # ánh xạ đã dọn

    def test_offer_has_from_from_session_and_even_stream(self):
        net = self.net()
        seen = []
        original = net.files["B"].handle_packet

        def spy(peer, stream, kind, payload):
            if kind == PacketType.FILE_OFFER:
                seen.append((stream, decode_json(payload)))
            return original(peer, stream, kind, payload)
        net.files["B"].handle_packet = spy
        tid = net.offer(b"hello")
        net.run_until(lambda: net.state("B", tid) == ft.OFFERED, 2000)
        (stream, offer), = seen
        self.assertEqual(offer["from"], "u01")
        self.assertTrue(stream >= 4 and stream % 2 == 0)       # server mở luồng chẵn

    def test_lossy_network(self):
        net = self.net(loss=0.12, dup=0.1, reorder=True, seed=5)
        data = payload_of(120_000, seed=5)
        tid = net.offer_and_accept(data)
        self.assertTrue(net.run_until(net.finished(tid), 60_000))
        self.assert_received(net, tid, data)

    def test_both_directions_at_once(self):
        net = self.net()
        d1, d2 = payload_of(30_000, 1), payload_of(25_000, 2)
        t1 = net.offer_and_accept(d1, "A", "B", "u02")
        t2 = net.offer_and_accept(d2, "B", "A", "u01")
        self.assertTrue(net.run_until(lambda: net.finished(t1)() and net.finished(t2, "B", "A")(),
                                      20_000))
        self.assert_received(net, t1, d1, "A", "B")
        self.assert_received(net, t2, d2, "B", "A")

    def test_chat_not_blocked_by_file(self):
        net = self.net(loss=0.1, seed=11)
        tid = net.offer_and_accept(payload_of(300_000))
        net.run_until(lambda: net.state("B", tid) == ft.TRANSFERRING, 5000)
        net.t["A"].send("server", 2, PacketType.CHAT,
                        encode_json({"message_id": str(uuid.uuid4()), "to": "u02", "text": "hi"}))
        self.assertTrue(net.run_until(lambda: net.chats["B"], 2000))
        self.assertNotIn(net.state("B", tid), ft.TERMINAL)     # tệp vẫn đang truyền
        self.assertEqual(net.chats["B"][0]["from"], "u01")
        self.assertTrue(net.run_until(net.finished(tid), 60_000))
        self.assertEqual(net.state("B", tid), ft.COMPLETED)

    # ----- từ chối / timeout -------------------------------------------------------

    def test_reject_forwarded(self):
        net = self.net()
        tid = net.offer(b"hello")
        net.run_until(lambda: net.state("B", tid) == ft.OFFERED, 2000)
        net.files["B"].reject_transfer(tid, "Không cần")
        self.assertTrue(net.run_until(lambda: net.state("A", tid) == ft.REJECTED, 2000))
        self.assertEqual(net.error("A", tid), ft.TRANSFER_REJECTED)
        net.settle(50)
        self.assertEqual(net.service.files.active_links(), 0)

    def test_accept_timeout_forwarded(self):
        net = self.net(accept_timeout=2.0)
        tid = net.offer(b"x" * 3000)
        self.assertTrue(net.run_until(net.finished(tid), 2000))
        self.assertEqual(net.error("A", tid), ft.TRANSFER_TIMEOUT)
        self.assertEqual(net.error("B", tid), ft.TRANSFER_TIMEOUT)
        net.settle(50)
        self.assertEqual(net.service.files.active_links(), 0)

    def test_checksum_mismatch_reaches_sender(self):
        net = self.net()
        tid = net.files["A"].offer_file("u02", net.write_source(payload_of(5000)), sha256="0" * 64)
        net.run_until(lambda: net.state("B", tid) == ft.OFFERED, 2000)
        net.files["B"].accept_transfer(tid)
        self.assertTrue(net.run_until(net.finished(tid), 5000))
        self.assertEqual(net.error("A", tid), ft.CHECKSUM_MISMATCH)
        self.assertEqual(net.download_files(), [])

    # ----- bảng báo lỗi đã chốt với Người 4 -------------------------------------

    def test_recipient_not_logged_in(self):
        net = self.net()
        tid = net.offer(b"abc", to="u05")                     # u05 chưa đăng nhập
        self.assertTrue(net.run_until(lambda: net.state("A", tid) == ft.FAILED, 2000))
        self.assertEqual(net.error("A", tid), ft.USER_OFFLINE)

    def test_recipient_unknown_user(self):
        net = self.net()
        tid = net.offer(b"abc", to="u99")
        self.assertTrue(net.run_until(lambda: net.state("A", tid) == ft.FAILED, 2000))
        self.assertEqual(net.error("A", tid), ft.USER_OFFLINE)

    def test_recipient_logged_in_but_not_bound(self):
        net = self.net()
        net.mgr.authenticate("user04", "pass04")              # có phiên, chưa UDP_BIND
        tid = net.offer(b"abc", to="u04")
        self.assertTrue(net.run_until(lambda: net.state("A", tid) == ft.FAILED, 2000))
        self.assertEqual(net.error("A", tid), ft.USER_OFFLINE)

    def test_receiver_disconnects_mid_transfer(self):
        net = self.net()
        tid = net.offer_and_accept(payload_of(400_000))
        net.run_until(lambda: net.status("B", tid)["bytes_done"] > 50_000, 5000)
        net.cut("B")                                           # B mất mạng hẳn
        # Server phát hiện sau 15 s không có gói -> báo A FILE_RESULT failed/USER_OFFLINE.
        self.assertTrue(net.run_until(lambda: net.state("A", tid) == ft.FAILED, 2000))
        self.assertEqual(net.error("A", tid), ft.USER_OFFLINE)
        self.assertIsNone(net.mgr.get_session(net.session["B"].session_id))
        # B tự phát hiện mất server, dọn tệp tạm.
        self.assertTrue(net.run_until(lambda: net.state("B", tid) == ft.FAILED, 2000))
        self.assertEqual(net.download_files(), [])
        self.assertEqual(net.service.files.active_links(), 0)

    def test_sender_disconnects_mid_transfer(self):
        net = self.net()
        tid = net.offer_and_accept(payload_of(400_000))
        net.run_until(lambda: net.status("B", tid)["bytes_done"] > 50_000, 5000)
        net.cut("A")
        # Server báo B: ERROR USER_OFFLINE (reference_id = transfer_id).
        self.assertTrue(net.run_until(lambda: net.state("B", tid) == ft.FAILED, 2000))
        self.assertEqual(net.error("B", tid), ft.USER_OFFLINE)
        self.assertEqual(net.download_files(), [])
        self.assertEqual(net.service.files.active_links(), 0)

    def test_sender_disconnects_while_waiting_accept(self):
        net = self.net()
        tid = net.offer(b"x" * 5000)
        net.run_until(lambda: net.state("B", tid) == ft.OFFERED, 2000)
        net.cut("A")
        self.assertTrue(net.run_until(lambda: net.state("B", tid) == ft.FAILED, 2000))
        self.assertEqual(net.error("B", tid), ft.USER_OFFLINE)

    def test_receiver_logs_out_mid_transfer(self):
        net = self.net()
        tid = net.offer_and_accept(payload_of(300_000))
        net.run_until(lambda: net.status("B", tid)["bytes_done"] > 30_000, 5000)
        net.t["B"].send("server", 1, PacketType.LOGOUT, encode_json({}))
        self.assertTrue(net.run_until(lambda: net.state("A", tid) == ft.FAILED, 2000))
        self.assertEqual(net.error("A", tid), ft.USER_OFFLINE)

    # ----- kiểm tra offer / chiều gói / backpressure -------------------------------

    def test_invalid_offer_refused_with_file_result(self):
        net = self.net()
        got = []
        original = net.files["A"].handle_packet

        def spy(peer, stream, kind, payload):
            got.append((stream, kind, decode_json(payload)))
            return original(peer, stream, kind, payload)
        net.files["A"].handle_packet = spy
        stream = net.t["A"].allocate_stream("server")
        tid = str(uuid.uuid4())
        bad = {"transfer_id": tid, "to": "u02", "filename": "x.bin", "size": 200 * 1024 * 1024,
               "chunk_size": 1024, "total_chunks": 204800, "sha256": "a" * 64}
        net.t["A"].send("server", stream, PacketType.FILE_OFFER, encode_json(bad))
        net.settle(30)
        self.assertEqual(got, [(stream, PacketType.FILE_RESULT,
                                {"transfer_id": tid, "status": "failed",
                                 "error_code": "FILE_TOO_LARGE"})])
        self.assertEqual(net.files["B"].list_transfers(), [])
        self.assertEqual(net.service.files.active_links(), 0)

    def test_wrong_direction_packet_dropped(self):
        net = self.net()
        tid = net.offer(b"x" * 3000)
        net.run_until(lambda: net.state("B", tid) == ft.OFFERED, 2000)
        # Người gửi tự gửi FILE_ACCEPT trên luồng của mình: server phải bỏ.
        stream = net.files["A"]._transfers[tid].stream_id
        net.t["A"].send("server", stream, PacketType.FILE_ACCEPT,
                        encode_json({"transfer_id": tid}))
        net.settle(30)
        self.assertEqual(net.state("A", tid), ft.OFFERED)       # vẫn chờ B chấp nhận
        self.assertEqual(net.state("B", tid), ft.OFFERED)

    def test_slow_receiver_overflow_aborts_without_unbounded_buffer(self):
        net = self.net(file_queue_limit=8)
        tid = net.offer_and_accept(payload_of(600_000))
        net.run_until(lambda: net.status("B", tid)["bytes_done"] > 10_000, 5000)
        net.down.add(net.addr["B"])            # B chỉ "chậm": chặn tạm mạng tới B
        self.assertTrue(net.run_until(lambda: net.state("A", tid) == ft.FAILED, 3000))
        self.assertEqual(net.error("A", tid), "DELIVERY_TIMEOUT")
        relay = net.service.files
        self.assertLessEqual(max((len(q) for q in relay._queues.values()), default=0), 8)
        net.down.discard(net.addr["B"])
        self.assertTrue(net.run_until(lambda: net.state("B", tid) == ft.FAILED, 3000))
        self.assertEqual(net.error("B", tid), "DELIVERY_TIMEOUT")


class FileRelayRealSocketTests(unittest.TestCase):
    """Client Người 4 (timer thật) <-> server thật qua socket UDP localhost."""

    def test_transfer_over_localhost(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        mgr = SessionManager(STORE)
        udp = open_udp_socket("127.0.0.1", 0)
        server = ServerUDP(udp, role="server")
        UdpService(mgr, server)
        server.start()
        transports, clients = [], []
        try:
            for n in (1, 2):
                s = mgr.authenticate(f"user{n:02d}", f"pass{n:02d}")
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.bind(("127.0.0.1", 0))
                t = ReliableUDP(sock, role="client")
                bound = threading.Event()
                t.on_payload(lambda p, st, k, pl, ev=bound: k == PacketType.UDP_BIND_OK and ev.set())
                t.register_peer("server", s.session_id, udp.getsockname(),
                                CryptoContext(s.c2s_key, s.c2s_nonce_prefix),
                                CryptoContext(s.s2c_key, s.s2c_nonce_prefix))
                t.start()
                t.send("server", 1, PacketType.UDP_BIND, encode_json({}))
                self.assertTrue(bound.wait(5))
                t.activate_peer("server")
                transports.append(t)
                clients.append(FakeClient(t, download_dir=os.path.join(tmp, f"dl{n}")))
            a, b = clients
            data = payload_of(80_000, seed=9)
            src = os.path.join(tmp, "src.bin")
            with open(src, "wb") as f:
                f.write(data)
            tid = a.files.offer_file("u02", src)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                try:
                    if b.files.get_transfer(tid)["status"] == ft.OFFERED:
                        break
                except ft.AppError:
                    pass
                time.sleep(0.02)
            b.files.accept_transfer(tid)
            while time.monotonic() < deadline:
                if a.files.get_transfer(tid)["status"] in ft.TERMINAL and \
                        b.files.get_transfer(tid)["status"] in ft.TERMINAL:
                    break
                time.sleep(0.02)
            self.assertEqual(a.files.get_transfer(tid)["status"], ft.COMPLETED)
            self.assertEqual(b.files.get_transfer(tid)["status"], ft.COMPLETED)
            with open(b.files.get_download_path(tid), "rb") as f:
                self.assertEqual(f.read(), data)
        finally:
            for c in clients:
                c.files.close()
            for t in transports:
                t.close()
            server.close()


if __name__ == "__main__":
    unittest.main()
