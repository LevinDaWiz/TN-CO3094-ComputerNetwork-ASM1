"""Kiểm thử truyền tệp (``file_transfer.py``) trên transport thật, mạng giả lập.

Ba ``ReliableUDP`` (client A, server S, client B) với AES-GCM thật; datagram đi
qua hàng đợi trong bộ nhớ có thể mất / trùng / đảo thứ tự, đồng hồ giả để
timeout chạy nhanh. Server là ``FakeFileServer`` và client là ``FakeClient``
(giả lập tối giản, không phải server.py / client.py).

Chạy từ thư mục gốc repo::

    python -m unittest tests.test_file_transfer -v
"""

import hashlib
import os
import random
import shutil
import sys
import tempfile
import unittest
import uuid

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import file_transfer as ft  # noqa: E402
from fake_client import FakeClient  # noqa: E402
from fake_file_server import FakeFileServer  # noqa: E402
from file_transfer import (AppError,  # noqa: E402
                           chunk_length, safe_filename, total_chunks, unique_path,
                           validate_offer)
from protocol import CryptoContext, PacketType, decode_json, encode_json  # noqa: E402
from reliable_udp import ReliableUDP  # noqa: E402

STEP = 0.02     # giây đồng hồ giả mỗi bước mô phỏng
USERS = {"A": "u01", "B": "u02"}


class Net:
    """Mạng A <-> S <-> B chạy thủ công: step() = giao datagram, tick, dispatch."""

    def __init__(self, tmp, *, loss=0.0, dup=0.0, reorder=False, seed=2026,
                 accept_timeout=60.0, idle_timeout=60.0):
        self.now = 0.0
        self.rng = random.Random(seed)
        self.loss, self.dup, self.reorder = loss, dup, reorder
        self.tmp = tmp
        self.wire = []
        self.down = set()
        self.addr = {"A": ("10.0.0.1", 40001), "B": ("10.0.0.2", 40002), "S": ("10.0.0.9", 9001)}
        clock = lambda: self.now  # noqa: E731
        self.t = {
            "A": ReliableUDP(send_datagram=self._sender("A"), clock=clock, role="client"),
            "B": ReliableUDP(send_datagram=self._sender("B"), clock=clock, role="client"),
            "S": ReliableUDP(send_datagram=self._sender("S"), clock=clock, role="server"),
        }
        for name, session_id in (("A", 101), ("B", 202)):
            c2s, s2c = os.urandom(32), os.urandom(32)
            pc, ps = os.urandom(4), os.urandom(4)
            self.t[name].register_peer("server", session_id, self.addr["S"],
                                       CryptoContext(c2s, pc), CryptoContext(s2c, ps))
            self.t["S"].register_peer(name, session_id, self.addr[name],
                                      CryptoContext(s2c, ps), CryptoContext(c2s, pc))
        self.events = {"A": [], "B": []}
        self.clients, self.files, self.chats = {}, {}, {}
        for name in ("A", "B"):
            client = FakeClient(
                self.t[name], download_dir=os.path.join(tmp, "dl_" + name),
                on_event=lambda kind, data, n=name: self.events[n].append((kind, data)),
                clock=clock, accept_timeout=accept_timeout, idle_timeout=idle_timeout,
                autostart=False)
            self.clients[name], self.files[name], self.chats[name] = client, client.files, client.chats
        self.server = FakeFileServer(self.t["S"], USERS)
        s = self.t["S"]
        s.on_payload(self._server_payload)
        s.on_delivery(self.server.handle_delivery)
        s.on_failure(self.server.handle_failure)
        s.on_peer_closed(self.server.handle_peer_closed)

    def _sender(self, name):
        def send(raw, address):
            dst = next(k for k, v in self.addr.items() if v == address)
            self.wire.append((raw, name, dst))
        return send

    def _server_payload(self, peer, stream, kind, payload):
        if self.server.handle_packet(peer, stream, kind, payload):
            return
        if kind == PacketType.CHAT:
            self.t["S"].send("B" if peer == "A" else "A", 2, PacketType.CHAT, payload)

    def step(self):
        batch, self.wire = self.wire, []
        if self.reorder:
            self.rng.shuffle(batch)
        for raw, src, dst in batch:
            if src in self.down or dst in self.down or self.rng.random() < self.loss:
                continue
            for _ in range(2 if self.rng.random() < self.dup else 1):
                self.t[dst].receive_datagram(raw, self.addr[src])
        for t in self.t.values():
            t.tick()
        for t in self.t.values():
            t.dispatch_events(100_000)
        for f in self.files.values():
            f.tick()
        self.server.flush()
        self.now += STEP

    def run_until(self, predicate, max_steps=50_000, on_step=None):
        for _ in range(max_steps):
            if predicate():
                return True
            self.step()
            if on_step:
                on_step()
        return predicate()

    def settle(self, steps=300):
        for _ in range(steps):
            self.step()

    def disconnect(self, name):
        """Mất mạng một client: hai phía đóng peer (như hết heartbeat)."""
        self.down.add(name)
        self.t["S"].close_peer(name, "PEER_TIMEOUT")
        self.t[name].close_peer("server", "PEER_TIMEOUT")

    # ----- tiện ích -----

    def status(self, name, tid):
        try:
            return self.files[name].get_transfer(tid)["status"]
        except AppError:
            return None

    def write_source(self, data, filename="data.bin"):
        folder = os.path.join(self.tmp, "src_" + uuid.uuid4().hex[:6])
        os.makedirs(folder)
        path = os.path.join(folder, filename)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def offer_and_accept(self, data, filename="data.bin", **kw):
        path = self.write_source(data, filename)
        tid = self.files["A"].offer_file("u02", path, **kw)
        assert self.run_until(lambda: self.status("B", tid) == ft.OFFERED, 2000)
        self.files["B"].accept_transfer(tid)
        return tid, path

    def finished(self, tid):
        return lambda: (self.status("A", tid) in ft.TERMINAL
                        and self.status("B", tid) in ft.TERMINAL)

    def download_files(self, name="B"):
        folder = os.path.join(self.tmp, "dl_" + name)
        return sorted(os.listdir(folder)) if os.path.isdir(folder) else []

    def kinds(self, name, tid):
        return [k for k, d in self.events[name] if d.get("transfer_id") == tid]


def payload_of(size, seed=1):
    return random.Random(seed).randbytes(size)


class HelperTests(unittest.TestCase):
    def test_chunk_math(self):
        self.assertEqual([total_chunks(n) for n in (0, 1, 1024, 1025, 2048)], [0, 1, 1, 2, 2])
        self.assertEqual(chunk_length(0, 1025), 1024)
        self.assertEqual(chunk_length(1, 1025), 1)
        self.assertEqual(chunk_length(1, 2048), 1024)

    def test_safe_filename(self):
        cases = {
            "../../etc/passwd": "passwd",
            "C:\\Windows\\evil.exe": "evil.exe",
            "a<b>c?.txt": "a_b_c_.txt",
            "..": "file",
            "": "file",
            "CON.txt": "_CON.txt",
            "báo cáo.pdf": "báo cáo.pdf",
            "name. ": "name",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(safe_filename(raw), expected)
        long_name = "ệ" * 200 + ".pdf"
        cleaned = safe_filename(long_name)
        self.assertLessEqual(len(cleaned.encode("utf-8")), 255)
        self.assertTrue(cleaned.endswith(".pdf"))

    def test_unique_path_never_overwrites(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        first = unique_path(tmp, "a.txt")
        second = unique_path(tmp, "a.txt")
        self.assertEqual(os.path.basename(first), "a.txt")
        self.assertEqual(os.path.basename(second), "a (1).txt")

    def test_validate_offer(self):
        good = {"transfer_id": str(uuid.uuid4()), "from": "u01", "filename": "x.bin",
                "size": 1025, "chunk_size": 1024, "total_chunks": 2, "sha256": "A" * 64}
        self.assertEqual(validate_offer(good, require_from=True)["sha256"], "a" * 64)
        bad = [("transfer_id", "123", "INVALID_PACKET"), ("total_chunks", 3, "INVALID_PACKET"),
               ("chunk_size", 512, "INVALID_PACKET"), ("sha256", "z" * 64, "INVALID_PACKET"),
               ("size", -1, "INVALID_PACKET"), ("size", True, "INVALID_PACKET"),
               ("size", ft.MAX_FILE_SIZE + 1, "FILE_TOO_LARGE"), ("from", None, "INVALID_PACKET"),
               ("filename", "x" * 256, "INVALID_PACKET")]
        for key, value, code in bad:
            with self.subTest(key=key, value=value):
                offer = dict(good, **{key: value})
                with self.assertRaises(AppError) as ctx:
                    validate_offer(offer, require_from=True)
                self.assertEqual(ctx.exception.code, code)


class TransferTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def net(self, **kw):
        sub = tempfile.mkdtemp(dir=self.tmp)
        net = Net(sub, **kw)
        for files in net.files.values():
            self.addCleanup(files.close)
        return net

    def assert_received(self, net, tid, data):
        self.assertEqual(net.status("A", tid), ft.COMPLETED)
        self.assertEqual(net.status("B", tid), ft.COMPLETED)
        path = net.files["B"].get_download_path(tid)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), data)
        self.assertFalse([n for n in net.download_files() if n.endswith(".part")])

    def test_sizes_end_to_end(self):
        for size in (0, 1, 1023, 1024, 1025, 20_000):
            with self.subTest(size=size):
                net = self.net()
                data = payload_of(size)
                tid, _ = net.offer_and_accept(data)
                self.assertTrue(net.run_until(net.finished(tid), 5000))
                self.assert_received(net, tid, data)
                self.assertIn("file_offer", net.kinds("B", tid))
                self.assertIn("file_completed", net.kinds("A", tid))
                self.assertIn("file_completed", net.kinds("B", tid))
                self.assertEqual(net.files["A"].get_transfer(tid)["progress"], 100.0)
                net.settle(50)
                self.assertEqual(net.server.links, {})

    def test_status_sequence_for_ui(self):
        net = self.net()
        tid, _ = net.offer_and_accept(payload_of(5000))
        net.run_until(net.finished(tid), 5000)

        def statuses(name):
            return [d["status"] for k, d in net.events[name]
                    if k == "file_status" and d["transfer_id"] == tid]
        self.assertEqual(statuses("A"), ["offered", "accepted", "transferring", "verifying", "completed"])
        self.assertEqual(statuses("B"), ["offered", "accepted", "transferring", "verifying", "completed"])

    def test_lossy_network(self):
        net = self.net(loss=0.15, dup=0.1, reorder=True, seed=7)
        data = payload_of(150_000, seed=7)
        tid, _ = net.offer_and_accept(data)
        self.assertTrue(net.run_until(net.finished(tid), 60_000))
        self.assert_received(net, tid, data)

    def test_large_file_bounded_inflight_and_throttled_progress(self):
        net = self.net()
        data = payload_of(2 * 1024 * 1024, seed=3)
        tid, _ = net.offer_and_accept(data)
        start = net.now
        peak = [0]

        def watch():
            peer = net.t["A"].peers.get("server")
            stream = peer.streams.get(3) if peer else None
            if stream is not None:
                peak[0] = max(peak[0], len(stream.pending))
        self.assertTrue(net.run_until(net.finished(tid), 60_000, on_step=watch))
        self.assert_received(net, tid, data)
        self.assertLessEqual(peak[0], ft.MAX_INFLIGHT)
        progress = [d for k, d in net.events["A"] if k == "file_progress"]
        self.assertLessEqual(len(progress), (net.now - start) / ft.PROGRESS_INTERVAL + 5)
        self.assertEqual(progress[-1]["progress"], 100.0)

    def test_reject(self):
        net = self.net()
        path = net.write_source(b"hello")
        tid = net.files["A"].offer_file("u02", path)
        net.run_until(lambda: net.status("B", tid) == ft.OFFERED, 2000)
        net.files["B"].reject_transfer(tid, "Không cần")
        self.assertTrue(net.run_until(lambda: net.status("A", tid) == ft.REJECTED, 2000))
        self.assertEqual(net.files["A"].get_transfer(tid)["error_code"], ft.TRANSFER_REJECTED)
        reasons = [d.get("reason") for k, d in net.events["A"]
                   if k == "file_status" and d["status"] == ft.REJECTED]
        self.assertEqual(reasons, ["Không cần"])
        self.assertEqual(net.download_files(), [])
        net.settle(50)
        self.assertEqual(net.server.links, {})

    def test_accept_timeout(self):
        net = self.net(accept_timeout=2.0)
        tid = net.files["A"].offer_file("u02", net.write_source(b"x" * 3000))
        self.assertTrue(net.run_until(net.finished(tid), 2000))
        self.assertEqual(net.files["A"].get_transfer(tid)["error_code"], ft.TRANSFER_TIMEOUT)
        self.assertEqual(net.files["B"].get_transfer(tid)["error_code"], ft.TRANSFER_TIMEOUT)

    def test_checksum_mismatch_cleans_temp(self):
        net = self.net()
        tid, _ = net.offer_and_accept(payload_of(10_000), sha256="0" * 64)
        self.assertTrue(net.run_until(net.finished(tid), 5000))
        self.assertEqual(net.files["B"].get_transfer(tid)["error_code"], ft.CHECKSUM_MISMATCH)
        self.assertEqual(net.files["A"].get_transfer(tid)["error_code"], ft.CHECKSUM_MISMATCH)
        self.assertEqual(net.download_files(), [])

    def test_recipient_offline(self):
        net = self.net()
        net.server.users.pop("B")
        tid = net.files["A"].offer_file("u02", net.write_source(b"abc"))
        self.assertTrue(net.run_until(lambda: net.status("A", tid) == ft.FAILED, 2000))
        self.assertEqual(net.files["A"].get_transfer(tid)["error_code"], ft.USER_OFFLINE)

    def test_receiver_disconnects_mid_transfer(self):
        net = self.net()
        tid, _ = net.offer_and_accept(payload_of(400_000))
        net.run_until(lambda: net.files["B"].get_transfer(tid)["bytes_done"] > 50_000, 5000)
        net.disconnect("B")
        self.assertTrue(net.run_until(net.finished(tid), 5000))
        self.assertEqual(net.files["A"].get_transfer(tid)["error_code"], ft.USER_OFFLINE)
        self.assertEqual(net.status("B", tid), ft.FAILED)
        self.assertEqual(net.download_files(), [])      # .part đã bị xóa
        net.settle(50)
        self.assertEqual(net.server.links, {})

    def test_sender_disconnects_mid_transfer(self):
        net = self.net()
        tid, _ = net.offer_and_accept(payload_of(400_000))
        net.run_until(lambda: net.files["B"].get_transfer(tid)["bytes_done"] > 50_000, 5000)
        net.disconnect("A")
        self.assertTrue(net.run_until(net.finished(tid), 5000))
        self.assertEqual(net.files["B"].get_transfer(tid)["error_code"], ft.USER_OFFLINE)
        self.assertEqual(net.download_files(), [])

    def test_chat_not_blocked_by_lossy_file(self):
        net = self.net(loss=0.1, seed=11)
        tid, _ = net.offer_and_accept(payload_of(400_000))
        net.run_until(lambda: net.status("B", tid) == ft.TRANSFERRING, 5000)
        chat = {"message_id": str(uuid.uuid4()), "to": "u02", "text": "xin chào"}
        net.t["A"].send("server", 2, PacketType.CHAT, encode_json(chat))
        self.assertTrue(net.run_until(lambda: net.chats["B"], 2000))
        self.assertNotIn(net.status("B", tid), ft.TERMINAL)    # tệp vẫn đang truyền
        self.assertTrue(net.run_until(net.finished(tid), 60_000))
        self.assertEqual(net.status("B", tid), ft.COMPLETED)

    def test_existing_file_not_overwritten(self):
        net = self.net()
        folder = os.path.join(net.tmp, "dl_B")
        os.makedirs(folder)
        with open(os.path.join(folder, "report.txt"), "wb") as f:
            f.write(b"old")
        tid, _ = net.offer_and_accept(b"new content", filename="report.txt")
        net.run_until(net.finished(tid), 5000)
        self.assertEqual(net.download_files(), ["report (1).txt", "report.txt"])
        with open(os.path.join(folder, "report.txt"), "rb") as f:
            self.assertEqual(f.read(), b"old")

    def test_path_in_filename_is_stripped(self):
        net = self.net()
        tid, _ = net.offer_and_accept(b"x", filename="data.bin")
        net.run_until(net.finished(tid), 5000)
        path = net.write_source(b"evil")
        tid = net.files["A"].offer_file("u02", path, filename="..\\..\\evil.txt")
        net.run_until(lambda: net.status("B", tid) == ft.OFFERED, 2000)
        net.files["B"].accept_transfer(tid)
        net.run_until(net.finished(tid), 5000)
        saved = net.files["B"].get_download_path(tid)
        self.assertEqual(os.path.dirname(saved), os.path.join(net.tmp, "dl_B"))
        self.assertEqual(os.path.basename(saved), "evil.txt")

    def test_two_concurrent_transfers(self):
        net = self.net(loss=0.05, seed=5)
        d1, d2 = payload_of(60_000, 1), payload_of(45_000, 2)
        t1, _ = net.offer_and_accept(d1, filename="one.bin")
        t2, _ = net.offer_and_accept(d2, filename="two.bin")
        self.assertTrue(net.run_until(lambda: net.finished(t1)() and net.finished(t2)(), 60_000))
        self.assert_received(net, t1, d1)
        self.assert_received(net, t2, d2)

    def test_both_directions_at_once(self):
        net = self.net()
        d1, d2 = payload_of(30_000, 1), payload_of(30_000, 2)
        t1 = net.files["A"].offer_file("u02", net.write_source(d1))
        t2 = net.files["B"].offer_file("u01", net.write_source(d2))
        net.run_until(lambda: net.status("B", t1) == ft.OFFERED and net.status("A", t2) == ft.OFFERED, 2000)
        net.files["B"].accept_transfer(t1)
        net.files["A"].accept_transfer(t2)
        self.assertTrue(net.run_until(lambda: net.finished(t1)() and net.finished(t2)(), 10_000))
        self.assertEqual(net.status("B", t1), ft.COMPLETED)
        self.assertEqual(net.status("A", t2), ft.COMPLETED)

    def test_api_state_errors(self):
        net = self.net()
        files = net.files["B"]
        with self.assertRaises(AppError) as ctx:
            files.accept_transfer(str(uuid.uuid4()))
        self.assertEqual(ctx.exception.code, ft.TRANSFER_NOT_FOUND)
        tid, _ = net.offer_and_accept(payload_of(50_000))
        with self.assertRaises(AppError) as ctx:
            files.get_download_path(tid)               # chưa xong
        self.assertEqual(ctx.exception.code, ft.INVALID_STATE)
        with self.assertRaises(AppError) as ctx:
            net.files["A"].accept_transfer(tid)        # tệp gửi đi, không phải tệp đến
        self.assertEqual(ctx.exception.code, ft.INVALID_STATE)
        big = net.write_source(b"")
        with open(big, "r+b") as f:
            f.truncate(ft.MAX_FILE_SIZE + 1)
        with self.assertRaises(AppError) as ctx:
            net.files["A"].offer_file("u02", big)
        self.assertEqual(ctx.exception.code, ft.FILE_TOO_LARGE)
        with self.assertRaises(AppError) as ctx:
            net.files["A"].offer_file("u02", net.write_source(b"x"), tid)   # trùng transfer_id
        self.assertEqual(ctx.exception.code, ft.INVALID_STATE)

    def test_close_cleans_partial_download(self):
        net = self.net()
        tid, _ = net.offer_and_accept(payload_of(300_000))
        net.run_until(lambda: net.files["B"].get_transfer(tid)["bytes_done"] > 10_000, 5000)
        self.assertTrue(any(n.endswith(".part") for n in net.download_files()))
        net.files["B"].close()
        self.assertEqual(net.download_files(), [])
        self.assertEqual(net.files["B"].get_transfer(tid)["error_code"], ft.CLIENT_CLOSED)

    def test_invalid_offer_is_refused(self):
        net = self.net()
        stream = net.t["A"].allocate_stream("server")
        bad = {"transfer_id": str(uuid.uuid4()), "to": "u02", "filename": "x", "size": 10,
               "chunk_size": 1024, "total_chunks": 5, "sha256": "0" * 64}
        net.t["A"].send("server", stream, PacketType.FILE_OFFER, encode_json(bad))
        net.settle(100)
        self.assertEqual(net.files["B"].list_transfers(), [])
        self.assertEqual(net.server.links, {})

    def test_real_udp_sockets_localhost(self):
        """Socket UDP thật + thread thật (tools/file_transfer_demo.py)."""
        sys.path.insert(0, os.path.join(ROOT, "tools"))
        from file_transfer_demo import run_demo
        source = os.path.join(self.tmp, "real.bin")
        with open(source, "wb") as f:
            f.write(payload_of(1024 * 1024 + 123))
        result = run_demo(source, self.tmp, timeout=60, log=lambda *_: None)
        self.assertEqual((result["sender"], result["receiver"]), ("completed", "completed"))
        self.assertTrue(result["hash_ok"])
        self.assertTrue(result["chat_before_done"])

    def test_sha256_matches_hashlib(self):
        tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, tmp)
        path = os.path.join(tmp, "f")
        data = payload_of(3 * 1024 * 1024 + 7)
        with open(path, "wb") as f:
            f.write(data)
        self.assertEqual(ft.sha256_file(path), hashlib.sha256(data).hexdigest())


if __name__ == "__main__":
    unittest.main()
