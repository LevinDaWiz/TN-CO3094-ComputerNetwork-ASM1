"""Kiểm thử codec CC v1 (``protocol.py``) và transport ``reliable_udp.py``.

Không cần server/client: hai đối tượng ``ReliableUDP`` (A = client, S = server)
nối với nhau bằng mạng giả lập trong bộ nhớ (có thể mất, nhân đôi, đảo thứ tự),
đồng hồ giả (mỗi bước 0,02 s, RTT mô phỏng 0,04 s), AES-GCM thật, seed cố định.
Thời gian trong test là giờ mô phỏng, không phải giờ thật.

Chạy từ thư mục gốc repo::

    python -m unittest tests.test_protocol_transport -v
"""

import heapq
import itertools
import os
import random
import socket
import sys
import threading
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from protocol import (CRYPTO_OVERHEAD, HEADER_SIZE, HEADER_STRUCT, MAX_DATAGRAM,  # noqa: E402
                      MAX_PLAINTEXT, UINT64_MAX, AppError, CryptoContext, Flags, Header,
                      PacketType, UNRELIABLE_TYPES, decode_ack, decode_json, decode_packet,
                      encode_ack, encode_chunk, encode_json, encode_packet, peek_header)
from reliable_udp import AIMD, FixedWindow, ReliableUDP  # noqa: E402

A_ADDR = ("10.0.0.1", 5000)
S_ADDR = ("10.0.0.2", 9001)
SESSION_ID = 101
STEP = 0.02


def flags_for(kind):
    return int(Flags.ENCRYPTED | (0 if kind in UNRELIABLE_TYPES else Flags.RELIABLE))


def chunk(i):
    return encode_chunk(i, bytes([i % 256]) * 1024)


def crypto_pair(seed=0):
    """Hai CryptoContext độc lập, cùng khóa/prefix (một cho gửi, một cho nhận)."""
    rng = random.Random(seed)
    key, prefix = bytes(rng.randrange(256) for _ in range(32)), bytes(rng.randrange(256) for _ in range(4))
    return CryptoContext(key, prefix), CryptoContext(key, prefix)


# ---------------------------------------------------------------------------
# Mạng giả lập
# ---------------------------------------------------------------------------

class Sim:
    """A (client) <-> S (server) qua hàng đợi datagram có độ trễ, mất, trùng, đảo."""

    def __init__(self, seed=1, loss=0.0, dup=0.0, reorder=0.0, delay=0.02, drop=None,
                 window=16, activate=False, **options):
        self.rng = random.Random(seed)
        self.now = 0.0
        self.loss, self.dup, self.reorder, self.delay = loss, dup, reorder, delay
        self.drop = drop                                   # drop(now, src, raw) -> bool
        self.queue, self._order = [], itertools.count()
        self.sent = {"A": [], "S": []}                     # (thời điểm, raw)
        self.rx = {"A": [], "S": []}                       # (thời điểm, peer, stream, kind, payload)
        self.delivered = {"A": [], "S": []}
        self.failures = {"A": [], "S": []}                 # (thời điểm, delivery_id, mã lỗi)
        self.closed = {"A": [], "S": []}                   # (thời điểm, peer, lý do)
        clock = lambda: self.now                           # noqa: E731
        self.A = ReliableUDP(send_datagram=lambda w, a: self._send("A", w), clock=clock,
                             role="client", window=window, **options)
        self.S = ReliableUDP(send_datagram=lambda w, a: self._send("S", w), clock=clock,
                             role="server", window=window, **options)
        self.ends = {"A": self.A, "S": self.S}
        c2s_tx, c2s_rx = crypto_pair(1)
        s2c_tx, s2c_rx = crypto_pair(2)
        self.A.register_peer("server", SESSION_ID, S_ADDR, c2s_tx, s2c_rx)
        self.S.register_peer("client", SESSION_ID, A_ADDR, s2c_tx, c2s_rx)
        for name, end in self.ends.items():
            end.on_payload(lambda p, st, k, pl, n=name: self.rx[n].append((self.now, p, st, k, pl)))
            end.on_delivery(lambda d, n=name: self.delivered[n].append(d))
            end.on_failure(lambda d, e, n=name: self.failures[n].append((self.now, d, e)))
            end.on_peer_closed(lambda p, r, n=name: self.closed[n].append((self.now, p, r)))
        if activate:
            self.A.activate_peer("server")
            self.S.activate_peer("client")

    # ----- mạng -----

    def _send(self, src, raw):
        self.sent[src].append((self.now, raw))
        if self.drop is not None and self.drop(self.now, src, raw):
            return
        if self.rng.random() < self.loss:
            return
        for _ in range(2 if self.rng.random() < self.dup else 1):
            extra = self.rng.random() * 0.2 if self.rng.random() < self.reorder else 0.0
            heapq.heappush(self.queue, (self.now + self.delay + extra, next(self._order),
                                        "S" if src == "A" else "A", raw))

    def step(self):
        self.now = round(self.now + STEP, 6)
        while self.queue and self.queue[0][0] <= self.now + 1e-9:
            _, _, dst, raw = heapq.heappop(self.queue)
            self.ends[dst].receive_datagram(raw, A_ADDR if dst == "S" else S_ADDR)
        for end in (self.A, self.S):
            end.tick()
        for end in (self.A, self.S):
            end.dispatch_events()

    def run(self, predicate, limit=600.0, observer=None):
        while self.now < limit and not predicate():
            self.step()
            if observer is not None:
                observer(self)
        return predicate()

    def run_for(self, seconds, observer=None):
        end = self.now + seconds
        self.run(lambda: False, limit=end, observer=observer)

    # ----- tiện ích -----

    def chunks_at_s(self, stream):
        return [decode_chunk_index(pl) for _, _, st, k, pl in self.rx["S"]
                if st == stream and k == PacketType.FILE_CHUNK]

    def count_sent(self, src, kind):
        return sum(peek_header(raw).packet_type == kind for _, raw in self.sent[src])

    def craft(self, kind, stream, seq, payload, session=SESSION_ID, crypto=None):
        """Datagram do 'A' tạo tay (dùng đúng khóa gửi của A để mô phỏng gói hợp lệ)."""
        crypto = crypto or self.A.peers["server"].tx_crypto
        return encode_packet(Header(kind, session, stream, seq, flags_for(kind)), payload, crypto)

    def inflight(self, stream=3):
        s = self.A.peers["server"].streams.get(stream)
        return 0 if s is None else sum(p.deadline is not None for p in s.pending.values())


def decode_chunk_index(payload):
    from protocol import decode_chunk
    return decode_chunk(payload)[0]


def send_chunks(sim, n, stream=None):
    stream = stream or sim.A.allocate_stream("server")
    for i in range(n):
        sim.A.send("server", stream, PacketType.FILE_CHUNK, chunk(i))
    return stream


# ---------------------------------------------------------------------------
# 1. Codec
# ---------------------------------------------------------------------------

PACKETS = [
    (PacketType.UDP_BIND, 1, encode_json({})),
    (PacketType.UDP_BIND_OK, 1, encode_json({})),
    (PacketType.HEARTBEAT, 0, encode_json({})),
    (PacketType.USER_LIST, 1, encode_json({"revision": 1, "part_index": 0, "part_count": 1, "users": []})),
    (PacketType.CHAT, 2, encode_json({"message_id": "m", "to": None, "text": "Chào bạn"})),
    (PacketType.ACK, 0, encode_ack(2, 7)),
    (PacketType.CHAT_STATUS, 2, encode_json({"message_id": "m", "status": "accepted"})),
    (PacketType.FILE_OFFER, 3, encode_json({"transfer_id": "t", "filename": "báo cáo.pdf"})),
    (PacketType.FILE_ACCEPT, 3, encode_json({"transfer_id": "t"})),
    (PacketType.FILE_REJECT, 3, encode_json({"transfer_id": "t", "reason": "no"})),
    (PacketType.FILE_CHUNK, 3, encode_chunk(5, b"x" * 1024)),
    (PacketType.FILE_END, 3, encode_json({"transfer_id": "t"})),
    (PacketType.FILE_RESULT, 3, encode_json({"transfer_id": "t", "status": "completed"})),
    (PacketType.ERROR, 1, encode_json({"code": "X", "message": "y", "reference_id": None})),
    (PacketType.LOGOUT, 1, encode_json({})),
]


class CodecTests(unittest.TestCase):
    def setUp(self):
        self.tx, self.rx = crypto_pair()

    def enc(self, kind=PacketType.CHAT, stream=2, seq=1, payload=b'{"a":"abcde"}', **header):
        flags = header.pop("flags", flags_for(kind))
        session = header.pop("session", SESSION_ID)
        return encode_packet(Header(kind, session, stream, seq, flags), payload, self.tx)

    def test_constants(self):
        self.assertEqual(HEADER_STRUCT.size, 23)
        self.assertEqual((HEADER_SIZE, CRYPTO_OVERHEAD, MAX_DATAGRAM, MAX_PLAINTEXT), (23, 28, 1200, 1149))

    def test_all_15_types_roundtrip(self):
        self.assertEqual(len(PACKETS), 15)
        self.assertEqual({k for k, _, _ in PACKETS}, set(PacketType))
        for i, (kind, stream, payload) in enumerate(PACKETS, start=1):
            raw = encode_packet(Header(kind, SESSION_ID, stream, i, flags_for(kind)), payload, self.tx)
            pkt = decode_packet(raw, self.rx)
            h = pkt.header
            self.assertEqual((h.packet_type, h.session_id, h.stream_id, h.seq), (kind, SESSION_ID, stream, i))
            self.assertEqual(h.flags, flags_for(kind))
            self.assertEqual(pkt.payload, payload)
            self.assertEqual(len(raw), HEADER_SIZE + len(payload) + CRYPTO_OVERHEAD)

    def test_measured_sizes(self):
        sizes = {PacketType.ACK: 59, PacketType.HEARTBEAT: 53, PacketType.FILE_CHUNK: 1079}
        self.assertEqual(len(self.enc(PacketType.ACK, 0, 1, encode_ack(2, 1))), sizes[PacketType.ACK])
        self.assertEqual(len(self.enc(PacketType.HEARTBEAT, 0, 1, b"{}")), sizes[PacketType.HEARTBEAT])
        full = self.enc(PacketType.FILE_CHUNK, 3, 1, encode_chunk(0, b"z" * 1024))
        self.assertEqual(len(full), sizes[PacketType.FILE_CHUNK])
        self.assertAlmostEqual(1024 / len(full), 0.949, places=3)

    def test_max_datagram_is_1200(self):
        raw = self.enc(PacketType.CHAT, 2, 1, b'{"t":"' + b"a" * (MAX_PLAINTEXT - 8) + b'"}')
        self.assertEqual(len(raw), MAX_DATAGRAM)
        self.assertEqual(decode_json(decode_packet(raw, self.rx).payload)["t"], "a" * (MAX_PLAINTEXT - 8))

    def test_header_bytes_example(self):
        # Ví dụ mục 3.5: CHAT, stream 2, seq 1, phiên 101, JSON 13 byte -> payload_len 41.
        raw = self.enc(PacketType.CHAT, 2, 1, b'{"a":"abcde"}')
        self.assertEqual(len(b'{"a":"abcde"}'), 13)
        expected = "4343 01 05 03 0000000000000065 00000002 00000001 0029".replace(" ", "")
        self.assertEqual(raw[:HEADER_SIZE].hex(), expected)

    def test_unreliable_types_have_only_encrypted_flag(self):
        for kind in (PacketType.ACK, PacketType.HEARTBEAT):
            payload = encode_ack(1, 1) if kind == PacketType.ACK else b"{}"
            h = peek_header(self.enc(kind, 0, 1, payload))
            self.assertEqual(h.flags, 2)
        self.assertEqual(peek_header(self.enc()).flags, 3)

    def test_rejected_inputs(self):
        cases = {
            "payload 1150 byte": (lambda: self.enc(payload=b'{"t":"' + b"a" * 1142 + b'"}'), "PAYLOAD_TOO_LARGE"),
            "CHAT trên stream 3": (lambda: self.enc(PacketType.CHAT, 3), "INVALID_PACKET"),
            "FILE_CHUNK trên stream 2": (lambda: self.enc(PacketType.FILE_CHUNK, 2, 1, encode_chunk(0, b"x")), "INVALID_PACKET"),
            "seq = 0": (lambda: self.enc(seq=0), "INVALID_PACKET"),
            "session_id = 0": (lambda: self.enc(session=0), "INVALID_PACKET"),
            "RELIABLE trên ACK": (lambda: self.enc(PacketType.ACK, 0, 1, encode_ack(1, 1), flags=3), "INVALID_PACKET"),
            "ACK 7 byte": (lambda: self.enc(PacketType.ACK, 0, 1, b"1234567"), "INVALID_PACKET"),
            "JSON không phải object": (lambda: self.enc(payload=b"[]"), "INVALID_PACKET"),
            "JSON chứa NaN": (lambda: self.enc(payload=b'{"a":NaN}'), "INVALID_PACKET"),
            "chunk rỗng": (lambda: self.enc(PacketType.FILE_CHUNK, 3, 1, b"\x00\x00\x00\x00"), "INVALID_PACKET"),
            "seq vượt 32 bit": (lambda: self.enc(seq=2 ** 32), "INVALID_PACKET"),
        }
        for name, (call, code) in cases.items():
            with self.subTest(name), self.assertRaises(AppError) as cm:
                call()
            self.assertEqual(cm.exception.code, code)

    def test_corrupted_datagrams_rejected(self):
        raw = self.enc(seq=2)

        def flip(i, mask=1):
            b = bytearray(raw)
            b[i] ^= mask
            return bytes(b)
        cases = {
            "sai magic": flip(0), "sai version": flip(2), "sai type": flip(3, 0x20),
            "lật bit tag GCM": flip(-1), "lật bit ciphertext": flip(HEADER_SIZE + 12 + 1),
            "lật bit nonce": flip(HEADER_SIZE), "lật bit header (seq)": flip(20, 0x04),
            "lật bit header (stream)": flip(16, 0x01), "cắt ngắn": raw[:-5],
            "ngắn hơn header": raw[:10], "rỗng": b"", "thừa byte": raw + b"\x00",
        }
        for name, bad in cases.items():
            with self.subTest(name), self.assertRaises(AppError) as cm:
                decode_packet(bad, self.rx)
            self.assertEqual(cm.exception.code, "INVALID_PACKET")

    def test_wrong_key_rejected(self):
        other, _ = crypto_pair(99)
        with self.assertRaises(AppError):
            decode_packet(self.enc(), other)

    def test_nonce_counter_increments_and_exhausts(self):
        a = self.enc(seq=1)
        b = self.enc(seq=1)
        self.assertNotEqual(a[HEADER_SIZE:HEADER_SIZE + 12], b[HEADER_SIZE:HEADER_SIZE + 12])
        self.assertEqual(int.from_bytes(b[HEADER_SIZE + 4:HEADER_SIZE + 12], "big"), 1)
        ctx = CryptoContext(os.urandom(32), os.urandom(4), counter=UINT64_MAX)
        ctx.encrypt(b"aad", b"x")                     # nonce cuối cùng còn dùng được
        with self.assertRaises(AppError) as cm:
            ctx.encrypt(b"aad", b"x")
        self.assertEqual(cm.exception.code, "SESSION_EXHAUSTED")

    def test_ack_helpers(self):
        self.assertEqual(decode_ack(encode_ack(9, 3)), (9, 3))
        for bad in (b"", b"\x00" * 7, b"\x00" * 8):
            with self.assertRaises(AppError):
                decode_ack(bad)


# ---------------------------------------------------------------------------
# 2. Selective Repeat (tiêm gói thủ công)
# ---------------------------------------------------------------------------

class SelectiveRepeatManualTests(unittest.TestCase):
    def setUp(self):
        self.sim = Sim()

    def inject(self, seq, address=A_ADDR):
        raw = self.sim.craft(PacketType.CHAT, 2, seq, encode_json({"n": seq}))
        before = len(self.sim.sent["S"])
        ok = self.sim.S.receive_datagram(raw, address)
        self.sim.S.dispatch_events()
        acks = len(self.sim.sent["S"]) - before
        delivered = [decode_json(pl)["n"] for _, _, _, _, pl in self.sim.rx["S"]]
        return ok, acks, delivered

    def test_early_duplicate_and_out_of_window(self):
        self.assertEqual(self.inject(3), (True, 1, []))                  # đến sớm: đệm, ACK, chưa giao
        self.assertEqual(self.inject(1), (True, 1, [1]))
        self.assertEqual(self.inject(2), (True, 1, [1, 2, 3]))           # lấp khoảng trống
        self.assertEqual(self.inject(2), (True, 1, [1, 2, 3]))           # trùng: ACK lại, không giao lại
        self.assertEqual(self.inject(19), (True, 1, [1, 2, 3]))          # recv_base(4) + 15: còn trong cửa sổ
        self.assertEqual(self.inject(20), (False, 0, [1, 2, 3]))         # recv_base + 16: bị loại, không ACK

    def test_ack_payload_names_stream_and_seq(self):
        self.inject(1)
        _, raw = self.sim.sent["S"][-1]
        pkt = decode_packet(raw, self.sim.A.peers["server"].rx_crypto)
        self.assertEqual(pkt.header.packet_type, PacketType.ACK)
        self.assertEqual((pkt.header.stream_id, pkt.header.flags), (0, 2))
        self.assertEqual(decode_ack(pkt.payload), (2, 1))

    def test_wrong_stream_parity_rejected(self):
        # Server không chấp nhận luồng chẵn do client mở.
        raw = self.sim.craft(PacketType.FILE_OFFER, 4, 1, encode_json({"transfer_id": "t"}))
        self.assertFalse(self.sim.S.receive_datagram(raw, A_ADDR))
        raw = self.sim.craft(PacketType.FILE_OFFER, 3, 1, encode_json({"transfer_id": "t"}))
        self.assertTrue(self.sim.S.receive_datagram(raw, A_ADDR))

    def test_sender_window_does_not_slide_past_gap(self):
        sim = Sim(congestion_factory=FixedWindow)       # chỉ kiểm tra cửa sổ, không có giới hạn cwnd
        stream = send_chunks(sim, 6)
        sim.A.tick()
        st = sim.A.peers["server"].streams[stream]
        # ACK seq 2 và 3 nhưng không ACK seq 1: send_base phải kẹt ở 1.
        for seq in (2, 3):
            raw = encode_packet(Header(PacketType.ACK, SESSION_ID, 0, seq, 2), encode_ack(stream, seq),
                                sim.S.peers["client"].tx_crypto)
            self.assertTrue(sim.A.receive_datagram(raw, S_ADDR))
        self.assertEqual((st.send_base, st.acked), (1, {2, 3}))
        raw = encode_packet(Header(PacketType.ACK, SESSION_ID, 0, 9, 2), encode_ack(stream, 1),
                            sim.S.peers["client"].tx_crypto)
        sim.A.receive_datagram(raw, S_ADDR)
        self.assertEqual((st.send_base, st.acked), (4, set()))           # trượt qua 1, 2, 3


# ---------------------------------------------------------------------------
# 3. Mạng mất gói, trùng, đảo thứ tự
# ---------------------------------------------------------------------------

class LossyNetworkTests(unittest.TestCase):
    N = 200

    def transfer(self, **net):
        sim = Sim(**net)
        stream = send_chunks(sim, self.N)
        done = sim.run(lambda: len(sim.chunks_at_s(stream)) >= self.N)
        return sim, stream, done

    def test_correct_under_loss(self):
        for loss in (0.0, 0.05, 0.10, 0.20):
            for seed in (1, 2, 3):
                with self.subTest(loss=loss, seed=seed):
                    sim, stream, done = self.transfer(seed=seed, loss=loss)
                    self.assertTrue(done, f"không xong sau {sim.now:.1f}s mô phỏng")
                    self.assertEqual(sim.chunks_at_s(stream), list(range(self.N)))   # đủ, đúng thứ tự, không trùng
                    self.assertEqual(sim.failures["A"], [])
                    data_sent = sim.count_sent("A", PacketType.FILE_CHUNK)
                    if loss == 0:
                        self.assertEqual(data_sent, self.N)                          # không truyền lại thừa
                    else:
                        self.assertGreater(data_sent, self.N)

    def test_loss_makes_transfer_slower(self):
        times = {}
        for loss in (0.0, 0.05, 0.20):
            sim, _, done = self.transfer(seed=1, loss=loss)
            self.assertTrue(done)
            times[loss] = sim.now
        self.assertLess(times[0.0], times[0.05])
        self.assertLess(times[0.05], times[0.20])
        self.assertLess(times[0.0], 1.5)                                              # ~0,7 s mô phỏng khi không mất

    def test_every_datagram_duplicated(self):
        sim, stream, done = self.transfer(seed=1, dup=1.0)
        self.assertTrue(done)
        sim.run_for(0.5)
        self.assertEqual(sim.chunks_at_s(stream), list(range(self.N)))               # mỗi gói giao đúng 1 lần
        self.assertEqual(sim.count_sent("S", PacketType.ACK), 2 * self.N)            # ACK lại cho từng bản sao
        self.assertEqual(sim.S.peers["client"].streams[stream].received, {})         # bản trùng không bị đệm lại

    def test_reorder_only(self):
        sim, stream, done = self.transfer(seed=1, reorder=0.5)
        self.assertTrue(done)
        self.assertEqual(sim.chunks_at_s(stream), list(range(self.N)))
        s_stream = sim.S.peers["client"].streams[stream]
        self.assertLessEqual(len(s_stream.received), 16)                             # bộ đệm không vượt window

    def test_loss_duplicate_reorder_combined(self):
        for seed in (1, 2, 3):
            sim, stream, done = self.transfer(seed=seed, loss=0.15, dup=0.10, reorder=0.3)
            self.assertTrue(done)
            self.assertEqual(sim.chunks_at_s(stream), list(range(self.N)))

    def test_two_directions_at_once(self):
        sim = Sim(seed=4, loss=0.1)
        for i in range(30):
            sim.A.send("server", 2, PacketType.CHAT, encode_json({"from": "A", "n": i}))
            sim.S.send("client", 2, PacketType.CHAT, encode_json({"from": "S", "n": i}))
        self.assertTrue(sim.run(lambda: len(sim.rx["S"]) == 30 and len(sim.rx["A"]) == 30))
        for name in ("A", "S"):
            self.assertEqual([decode_json(pl)["n"] for *_, pl in sim.rx[name]], list(range(30)))

    def test_nonce_never_reused_for_different_data(self):
        sim, _, done = self.transfer(seed=2, loss=0.2)
        self.assertTrue(done)
        for src in ("A", "S"):
            unique = {raw for _, raw in sim.sent[src]}
            nonces = {raw[HEADER_SIZE:HEADER_SIZE + 12] for raw in unique}
            self.assertEqual(len(nonces), len(unique), f"{src} dùng lại nonce cho dữ liệu khác")
        # Có truyền lại, và bản truyền lại là đúng các byte đã mã hóa lần đầu.
        self.assertGreater(len(sim.sent["A"]), len({raw for _, raw in sim.sent["A"]}))


# ---------------------------------------------------------------------------
# 4. Cửa sổ trượt
# ---------------------------------------------------------------------------

class WindowTests(unittest.TestCase):
    def test_window_bounds_inflight_and_speed(self):
        times, peaks = {}, {}
        for window in (1, 2, 4, 8, 16):
            sim = Sim(window=window)
            stream = send_chunks(sim, 200)
            peak = [0]
            observe = lambda s, peak=peak, st=stream: peak.__setitem__(0, max(peak[0], s.inflight(st)))  # noqa: E731
            self.assertTrue(sim.run(lambda: len(sim.chunks_at_s(stream)) >= 200, observer=observe))
            self.assertEqual(sim.chunks_at_s(stream), list(range(200)))
            times[window], peaks[window] = sim.now, peak[0]
            self.assertLessEqual(peak[0], window)                                    # không bao giờ vượt window
        for small, big in ((1, 2), (4, 8), (8, 16)):
            self.assertGreater(times[small], times[big])
        self.assertAlmostEqual(times[1], 200 * 2 * STEP, delta=0.5)                  # stop-and-wait: ~1 gói / RTT
        self.assertGreater(times[1] / times[16], 5)
        # Luồng file chừa 2 chỗ cho chat/điều khiển nên window 2 và 4 cho cùng kết quả.
        self.assertLessEqual(peaks[4], 2)

    def test_invalid_settings(self):
        for kw in ({"window": 0}, {"window": 17}, {"role": "x"}, {"initial_rto": 5.0},
                   {"peer_timeout": 1.0}, {"max_pending": 0}):
            with self.subTest(kw), self.assertRaises(ValueError):
                ReliableUDP(send_datagram=lambda w, a: None, **kw)
        with self.assertRaises(ValueError):
            ReliableUDP()


# ---------------------------------------------------------------------------
# 5. Luồng độc lập
# ---------------------------------------------------------------------------

class IndependentStreamTests(unittest.TestCase):
    def send_chats(self, sim, n=20):
        for i in range(n):
            sim.A.send("server", 2, PacketType.CHAT, encode_json({"n": i}))

    def test_blocked_file_stream_does_not_block_chat(self):
        block = lambda now, src, raw: now < 3.0 and src == "A" and peek_header(raw).stream_id == 3  # noqa: E731
        sim = Sim(drop=block)
        file_stream = send_chunks(sim, 50)
        self.send_chats(sim)
        self.assertTrue(sim.run(lambda: len(sim.rx["S"]) >= 20, limit=10))
        chat_done = sim.now
        self.assertLess(chat_done, 0.5)                                              # chat xong rất sớm
        self.assertEqual(sim.chunks_at_s(file_stream), [])                           # file vẫn bị chặn
        self.assertTrue(sim.run(lambda: len(sim.chunks_at_s(file_stream)) >= 50, limit=30))
        self.assertGreaterEqual(sim.now, 3.0)
        self.assertEqual(sim.chunks_at_s(file_stream), list(range(50)))

    def test_loss_inside_chat_stream_does_block_that_stream(self):
        # Đối chứng: mất gói đầu ngay trong luồng chat thì các tin sau phải chờ RTO.
        seen = []

        def drop_first_chat(now, src, raw):
            h = peek_header(raw)
            if src == "A" and h.stream_id == 2 and h.seq == 1 and not seen:
                seen.append(now)
                return True
            return False
        sim = Sim(drop=drop_first_chat)
        self.send_chats(sim)
        self.assertTrue(sim.run(lambda: len(sim.rx["S"]) >= 20))
        self.assertGreaterEqual(min(t for t, *_ in sim.rx["S"]), 0.5)               # chờ truyền lại sau RTO 0,5 s
        self.assertEqual([decode_json(pl)["n"] for *_, pl in sim.rx["S"]], list(range(20)))

    def test_two_file_streams_share_bandwidth(self):
        sim = Sim()
        s1, s2 = sim.A.allocate_stream("server"), sim.A.allocate_stream("server")
        self.assertEqual((s1, s2), (3, 5))                                          # client mở luồng lẻ
        self.assertEqual(sim.S.allocate_stream("client"), 4)                        # server mở luồng chẵn
        send_chunks(sim, 100, s1)
        send_chunks(sim, 100, s2)
        done = {}

        def watch(s):
            for st in (s1, s2):
                if st not in done and len(s.chunks_at_s(st)) >= 100:
                    done[st] = s.now
        self.assertTrue(sim.run(lambda: len(done) == 2, observer=watch))
        self.assertLess(abs(done[s1] - done[s2]), 0.5)                              # round-robin: xong gần như cùng lúc
        for st in (s1, s2):
            self.assertEqual(sim.chunks_at_s(st), list(range(100)))

    def test_closed_stream_id_never_reused(self):
        sim = Sim()
        stream = sim.A.allocate_stream("server")
        sim.A.close_stream("server", stream)
        with self.assertRaises(AppError) as cm:
            sim.A.send("server", stream, PacketType.FILE_CHUNK, chunk(0))
        self.assertEqual(cm.exception.code, "STREAM_CLOSED")
        self.assertNotEqual(sim.A.allocate_stream("server"), stream)


# ---------------------------------------------------------------------------
# 6. Timeout và backoff
# ---------------------------------------------------------------------------

class TimeoutTests(unittest.TestCase):
    def test_backoff_schedule_and_delivery_timeout(self):
        sim = Sim(drop=lambda now, src, raw: True)                                   # đường truyền chết hoàn toàn
        stream = sim.A.allocate_stream("server")
        delivery = sim.A.send("server", stream, PacketType.FILE_CHUNK, chunk(0))
        self.assertTrue(sim.run(lambda: bool(sim.failures["A"]), limit=60))
        times = [t for t, _ in sim.sent["A"]]
        self.assertEqual(len(times), 9)                                              # 1 lần đầu + 8 lần truyền lại
        gaps = [b - a for a, b in zip(times, times[1:])]
        for got, want in zip(gaps, (0.5, 1, 2, 4, 4, 4, 4, 4)):
            self.assertAlmostEqual(got, want, delta=0.06)                            # trần 4 s
        when, failed_id, code = sim.failures["A"][0]
        self.assertEqual((failed_id, code), (delivery, "DELIVERY_TIMEOUT"))
        self.assertAlmostEqual(when, 27.6, delta=0.2)
        self.assertEqual(len({raw for _, raw in sim.sent["A"]}), 1)                  # truyền lại đúng byte cũ
        self.assertIn("server", sim.A.peers)                                         # luồng file lỗi: phiên vẫn sống
        self.assertEqual(sim.closed["A"], [])

    def test_chat_stream_timeout_closes_peer(self):
        sim = Sim(drop=lambda now, src, raw: True)
        sim.A.send("server", 2, PacketType.CHAT, encode_json({"n": 1}))
        self.assertTrue(sim.run(lambda: bool(sim.closed["A"]), limit=60))
        self.assertEqual(sim.closed["A"][0][1:], ("server", "RECONNECT_REQUIRED"))
        self.assertNotIn("server", sim.A.peers)
        with self.assertRaises(AppError):
            sim.A.send("server", 2, PacketType.CHAT, encode_json({"n": 2}))

    def test_delivery_callback_on_ack(self):
        sim = Sim()
        ids = [sim.A.send("server", 2, PacketType.CHAT, encode_json({"n": i})) for i in range(5)]
        self.assertTrue(sim.run(lambda: len(sim.delivered["A"]) == 5))
        self.assertCountEqual(sim.delivered["A"], ids)


# ---------------------------------------------------------------------------
# 7. Điều khiển tắc nghẽn AIMD
# ---------------------------------------------------------------------------

class CongestionTests(unittest.TestCase):
    def test_aimd_unit(self):
        c = AIMD(16)
        self.assertEqual((c.cwnd, c.ssthresh), (4.0, 16.0))
        for _ in range(12):
            c.on_ack()
        self.assertEqual(c.cwnd, 16.0)                                               # slow start, trần = window
        c.on_timeout()
        self.assertEqual((c.cwnd, c.ssthresh), (1.0, 8.0))
        for _ in range(7):
            c.on_ack()
        self.assertEqual(c.cwnd, 8.0)                                                # chạm ssthresh
        before = c.cwnd
        c.on_ack()
        self.assertAlmostEqual(c.cwnd, before + 1 / before)                          # additive increase
        for _ in range(5):
            c.on_timeout()
        self.assertEqual(c.ssthresh, 2.0)                                            # sàn ssthresh
        self.assertEqual(AIMD(2).cwnd, 2.0)
        f = FixedWindow(8)
        f.on_timeout()
        f.on_ack()
        self.assertEqual(f.cwnd, 8.0)

    def test_cwnd_grows_collapses_on_blackout_and_recovers(self):
        blackout = lambda now, src, raw: 2.0 <= now < 3.0  # noqa: E731
        sim = Sim(drop=blackout)
        stream = sim.A.allocate_stream("server")
        sent = [0]
        history = []

        def producer(s):
            st = s.A.peers["server"].streams[stream]
            while len(st.pending) < 100:
                s.A.send("server", stream, PacketType.FILE_CHUNK, chunk(sent[0]))
                sent[0] += 1
            history.append((s.now, s.A.peers["server"].controller.cwnd))
        sim.run_for(12.0, observer=producer)
        before = [c for t, c in history if t < 2.0]
        during = [c for t, c in history if 2.5 <= t <= 4.0]
        self.assertGreaterEqual(max(before), 15.9)                                   # slow start lên tới window
        self.assertEqual(min(during), 1.0)                                           # timeout -> cwnd = 1
        self.assertGreaterEqual(history[-1][1], 15.0)                                # hồi phục
        got = sim.chunks_at_s(stream)
        self.assertEqual(got, list(range(len(got))))                                 # vẫn đúng thứ tự, không trùng
        self.assertGreater(len(got), 500)


# ---------------------------------------------------------------------------
# 8. Heartbeat và hết hạn phiên
# ---------------------------------------------------------------------------

class HeartbeatTests(unittest.TestCase):
    def test_heartbeats_keep_session_alive_then_peer_timeout(self):
        sim = Sim(activate=True)
        sim.run_for(12.0)
        self.assertEqual(sim.count_sent("A", PacketType.HEARTBEAT), 2)              # chu kỳ 5 s: t = 5, 10
        self.assertEqual(sim.count_sent("S", PacketType.HEARTBEAT), 2)
        self.assertEqual((sim.closed["A"], sim.closed["S"]), ([], []))
        self.assertEqual((sim.rx["A"], sim.rx["S"]), ([], []))                      # heartbeat không lên ứng dụng
        sim.drop = lambda now, src, raw: True                                       # cắt đường truyền lúc t = 12
        self.assertTrue(sim.run(lambda: bool(sim.closed["A"]) and bool(sim.closed["S"]), limit=60))
        for name in ("A", "S"):
            when, _, reason = sim.closed[name][0]
            self.assertEqual(reason, "PEER_TIMEOUT")
            self.assertAlmostEqual(when, 25.1, delta=0.5)                            # 15 s sau gói hợp lệ cuối (~10 s)

    def test_no_heartbeat_before_activate(self):
        sim = Sim()
        sim.run_for(30.0)
        self.assertEqual(sim.count_sent("A", PacketType.HEARTBEAT), 0)
        self.assertEqual(sim.closed["A"], [])                                       # chưa activate thì không hết hạn

    def test_pending_deliveries_fail_when_peer_times_out(self):
        sim = Sim(activate=True, drop=lambda now, src, raw: True)
        stream = sim.A.allocate_stream("server")
        sim.A.send("server", stream, PacketType.FILE_CHUNK, chunk(0))
        self.assertTrue(sim.run(lambda: bool(sim.closed["A"]), limit=60))
        self.assertEqual(sim.closed["A"][0][2], "PEER_TIMEOUT")
        self.assertEqual([e for _, _, e in sim.failures["A"]], ["PEER_TIMEOUT"])


# ---------------------------------------------------------------------------
# 9. Gói giả mạo, hỏng và giới hạn hàng đợi
# ---------------------------------------------------------------------------

class ForgedPacketTests(unittest.TestCase):
    def setUp(self):
        self.sim = Sim()

    def receive(self, raw, address=A_ADDR):
        before = len(self.sim.sent["S"])
        ok = self.sim.S.receive_datagram(raw, address)
        return ok, len(self.sim.sent["S"]) - before

    def test_only_valid_packets_are_acked(self):
        good = self.sim.craft(PacketType.CHAT, 2, 1, encode_json({"t": "x"}))

        def flip(raw, i, mask):
            b = bytearray(raw)
            b[i] ^= mask
            return bytes(b)
        foreign = encode_packet(Header(PacketType.CHAT, 999, 2, 1), encode_json({"t": "x"}),
                                self.sim.A.peers["server"].tx_crypto)
        bad = {
            "rác ngẫu nhiên 100 byte": (random.Random(7).randbytes(100), A_ADDR),
            "sai magic": (flip(good, 0, 1), A_ADDR),
            "session ID lạ": (foreign, A_ADDR),
            "lật bit trong tag": (flip(good, -1, 1), A_ADDR),
            "lật bit trong header (seq)": (flip(self.sim.craft(PacketType.CHAT, 2, 2, b"{}"), 20, 0x04), A_ADDR),
            "sai địa chỉ nguồn": (good, ("10.0.0.99", 1234)),
            "bị cắt ngắn": (good[:-5], A_ADDR),
        }
        for name, (raw, addr) in bad.items():
            with self.subTest(name):
                self.assertEqual(self.receive(raw, addr), (False, 0))
        self.assertEqual(self.sim.rx["S"], [])
        self.assertEqual(self.receive(good), (True, 1))                              # gói hợp lệ: chấp nhận + 1 ACK
        self.assertEqual(self.receive(good), (True, 1))                              # gửi lại: chấp nhận (trùng) + ACK lại
        self.sim.S.dispatch_events()
        self.assertEqual(len(self.sim.rx["S"]), 1)                                  # nhưng chỉ giao 1 lần

    def test_forged_ack_is_ignored(self):
        stream = send_chunks(self.sim, 1)
        wrong_key, _ = crypto_pair(77)
        forged = encode_packet(Header(PacketType.ACK, SESSION_ID, 0, 1, 2), encode_ack(stream, 1), wrong_key)
        self.assertFalse(self.sim.A.receive_datagram(forged, S_ADDR))
        self.assertEqual(self.sim.A.peers["server"].streams[stream].send_base, 1)

    def test_transport_rejects_bad_sends(self):
        a = self.sim.A
        cases = [
            (lambda: a.send("server", 0, PacketType.ACK, encode_ack(1, 1)), "INVALID_PACKET"),
            (lambda: a.send("server", 3, PacketType.CHAT, b"{}"), "INVALID_PACKET"),
            (lambda: a.send("server", 2, PacketType.CHAT, b'{"t":"' + b"a" * 1200 + b'"}'), "PAYLOAD_TOO_LARGE"),
            (lambda: a.send("server", 2, 99, b"{}"), "INVALID_PACKET"),
            (lambda: a.send("nobody", 2, PacketType.CHAT, b"{}"), "INVALID_SESSION"),
        ]
        for call, code in cases:
            with self.subTest(code=code), self.assertRaises(AppError) as cm:
                call()
            self.assertEqual(cm.exception.code, code)

    def test_queue_full_does_not_consume_sequence(self):
        sim = Sim(max_queue_per_stream=4)
        stream = sim.A.allocate_stream("server")
        for i in range(4):
            sim.A.send("server", stream, PacketType.FILE_CHUNK, chunk(i))
        with self.assertRaises(AppError) as cm:
            sim.A.send("server", stream, PacketType.FILE_CHUNK, chunk(4))
        self.assertEqual(cm.exception.code, "QUEUE_FULL")
        self.assertEqual(sim.A.peers["server"].streams[stream].next_seq, 5)
        self.assertTrue(sim.run(lambda: len(sim.delivered["A"]) == 4))
        sim.A.send("server", stream, PacketType.FILE_CHUNK, chunk(4))               # hết đầy thì gửi lại được
        self.assertTrue(sim.run(lambda: len(sim.chunks_at_s(stream)) == 5))

    def test_global_pending_limit(self):
        sim = Sim(max_pending=3)
        for i in range(3):
            sim.A.send("server", 2, PacketType.CHAT, encode_json({"n": i}))
        with self.assertRaises(AppError) as cm:
            sim.A.send("server", 2, PacketType.CHAT, encode_json({"n": 3}))
        self.assertEqual(cm.exception.code, "QUEUE_FULL")

    def test_duplicate_peer_registration_rejected(self):
        tx, rx = crypto_pair(5)
        for peer_id, sid in (("server", 555), ("other", SESSION_ID)):
            with self.assertRaises(AppError):
                self.sim.A.register_peer(peer_id, sid, S_ADDR, tx, rx)
        with self.assertRaises(AppError):
            self.sim.A.register_peer("x", 0, S_ADDR, tx, rx)

    def test_closed_transport_refuses_work(self):
        self.sim.A.close()
        with self.assertRaises(AppError) as cm:
            self.sim.A.send("server", 2, PacketType.CHAT, b"{}")
        self.assertIn(cm.exception.code, ("TRANSPORT_CLOSED", "INVALID_SESSION"))
        self.assertFalse(self.sim.A.receive_datagram(b"x" * 50, S_ADDR))


# ---------------------------------------------------------------------------
# 10. Socket UDP thật trên localhost
# ---------------------------------------------------------------------------

class RealSocketTests(unittest.TestCase):
    def test_localhost_chat_and_file(self):
        sa = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sa.bind(("127.0.0.1", 0))
        ss.bind(("127.0.0.1", 0))
        a, s = ReliableUDP(sa, role="client"), ReliableUDP(ss, role="server")
        c2s_tx, c2s_rx = crypto_pair(11)
        s2c_tx, s2c_rx = crypto_pair(12)
        a.register_peer("server", 4242, ss.getsockname(), c2s_tx, s2c_rx)
        s.register_peer("client", 4242, sa.getsockname(), s2c_tx, c2s_rx)
        lock, got = threading.Lock(), []
        s.on_payload(lambda p, st, k, pl: (lock.acquire(), got.append((st, k, pl)), lock.release()))
        a.start()
        s.start()
        try:
            stream = a.allocate_stream("server")
            for i in range(40):
                a.send("server", 2, PacketType.CHAT, encode_json({"n": i}))
            for i in range(100):
                a.send("server", stream, PacketType.FILE_CHUNK, chunk(i))
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                with lock:
                    if len(got) >= 140:
                        break
                time.sleep(0.02)
            with lock:
                chats = [decode_json(pl)["n"] for st, k, pl in got if k == PacketType.CHAT]
                chunks = [decode_chunk_index(pl) for st, k, pl in got if k == PacketType.FILE_CHUNK]
            self.assertEqual(chats, list(range(40)))
            self.assertEqual(chunks, list(range(100)))
        finally:
            a.close()
            s.close()


# ---------------------------------------------------------------------------
# Bảng số đo cho báo cáo:  python tests/test_protocol_transport.py --report
# (Kết quả xác định: cùng seed + đồng hồ giả nên máy nào chạy cũng ra đúng số này.)
# ---------------------------------------------------------------------------

def _transfer(n=200, **net):
    sim = Sim(**net)
    stream = send_chunks(sim, n)
    peak = [0]

    def watch(s):
        st = s.S.peers["client"].streams.get(stream)
        if st is not None:
            peak[0] = max(peak[0], len(st.received))
    done = sim.run(lambda: len(sim.chunks_at_s(stream)) >= n or bool(sim.failures["A"]),
                   limit=600, observer=watch)
    ok = done and sim.chunks_at_s(stream) == list(range(n))
    return sim, stream, ok, peak[0]


def print_report():
    N = 200
    print("== B1. Mất gói: 200 FILE_CHUNK, seed 0..9 (trung bình các lần thành công) ==")
    print("loss  thanh_cong  that_bai  datagram_du_lieu  truyen_lai  thoi_gian_s  cham_hon")
    base = None
    for loss in (0.0, 0.02, 0.05, 0.10, 0.20, 0.30):
        rows = []
        for seed in range(10):
            sim, _, ok, _ = _transfer(seed=seed, loss=loss)
            if ok:
                rows.append((sim.count_sent("A", PacketType.FILE_CHUNK), sim.now))
        if rows:
            d = sum(r[0] for r in rows) / len(rows)
            t = sum(r[1] for r in rows) / len(rows)
            base = base or t
            print(f"{loss*100:>3.0f}%  {len(rows):>2}/10      {10-len(rows):>2}        {d:>7.0f}"
                  f"           +{(d / N - 1) * 100:>3.0f}%      {t:>8.2f}     {t / base:>4.0f}x")
        else:
            print(f"{loss*100:>3.0f}%   0/10      10")

    print("\n== B2. Trùng / đảo thứ tự / kết hợp: 200 gói, seed 0..4 ==")
    print("kich_ban                       dung_thu_tu  datagram_du_lieu  ACK   dem_sai_thu_tu_toi_da")
    for name, kw in (("moi datagram bi nhan doi", dict(dup=1.0)),
                     ("chi dao thu tu", dict(reorder=0.5)),
                     ("mat 15% + trung 10% + dao", dict(loss=0.15, dup=0.10, reorder=0.3))):
        res = []
        for seed in range(5):
            sim, _, ok, peak = _transfer(seed=seed, **kw)
            sim.run_for(0.5)
            res.append((ok, sim.count_sent("A", PacketType.FILE_CHUNK), sim.count_sent("S", PacketType.ACK), peak))
        print(f"{name:<30} {sum(r[0] for r in res)}/5          "
              f"{sum(r[1] for r in res) / 5:>7.0f}           {sum(r[2] for r in res) / 5:>5.0f}  {max(r[3] for r in res):>4}")

    print("\n== B3. Cửa sổ trượt: 200 gói, không mất ==")
    print("window  goi_bay_toi_da  thoi_gian_s  toc_do_KB/s")
    for window in (1, 2, 4, 8, 16):
        sim = Sim(window=window)
        stream = send_chunks(sim, N)
        peak = [0]
        sim.run(lambda: len(sim.chunks_at_s(stream)) >= N,
                observer=lambda s: peak.__setitem__(0, max(peak[0], s.inflight(stream))))
        print(f"{window:>6}  {peak[0]:>13}  {sim.now:>11.2f}  {N / sim.now:>10.0f}")

    print("\n== B4. AIMD: bình thường 0-2 s, mất hết 2-3 s, rồi bình thường ==")
    sim = Sim(drop=lambda now, src, raw: 2.0 <= now < 3.0)
    stream = sim.A.allocate_stream("server")
    counter, history = [0], []

    def producer(s):
        st = s.A.peers["server"].streams[stream]
        while len(st.pending) < 100:
            s.A.send("server", stream, PacketType.FILE_CHUNK, chunk(counter[0]))
            counter[0] += 1
        ctl = s.A.peers["server"].controller
        history.append((s.now, ctl.cwnd, ctl.ssthresh))
    sim.run_for(8.0, observer=producer)
    print("t(s)   cwnd   ssthresh")
    for t in (0.5, 1.0, 2.0, 2.5, 3.0, 3.5, 4.0, 4.5, 5.0, 6.0, 8.0):
        _, c, ss = min((h for h in history if h[0] >= t - 1e-9), key=lambda h: h[0])
        print(f"{t:<5}  {c:>5.1f}  {ss:>5.1f}")

    print("\n== B5. Nguyên nhân chậm khi mất gói: mất 5%, 200 gói, seed 0..9 ==")
    print("cau_hinh                              thoi_gian_trung_binh_s")
    for name, kw in (("mac dinh (AIMD, RTO 0,5 s)", {}),
                     ("khong ha cwnd (FixedWindow)", dict(congestion_factory=FixedWindow)),
                     ("RTO khoi dau 0,1 s", dict(initial_rto=0.1)),
                     ("FixedWindow + RTO 0,1 s", dict(congestion_factory=FixedWindow, initial_rto=0.1))):
        times = []
        for seed in range(10):
            sim, _, ok, _ = _transfer(seed=seed, loss=0.05, **kw)
            if ok:
                times.append(sim.now)
        print(f"{name:<37} {sum(times) / len(times):>8.2f}   ({len(times)}/10 xong)")

    print("\n== B6. Timeout/backoff và heartbeat ==")
    sim = Sim(drop=lambda now, src, raw: True)
    sim.A.send("server", sim.A.allocate_stream("server"), PacketType.FILE_CHUNK, chunk(0))
    sim.run(lambda: bool(sim.failures["A"]), limit=60)
    times = [t for t, _ in sim.sent["A"]]
    print("lan gui luc (s):", ", ".join(f"{t:.2f}" for t in times))
    print("khoang cach (s):", ", ".join(f"{b - a:.2f}" for a, b in zip(times, times[1:])))
    print(f"bao {sim.failures['A'][0][2]} luc {sim.failures['A'][0][0]:.2f} s")
    sim = Sim(activate=True)
    sim.run_for(12.0)
    hb = (sim.count_sent("A", PacketType.HEARTBEAT), sim.count_sent("S", PacketType.HEARTBEAT))
    sim.drop = lambda now, src, raw: True
    sim.run(lambda: bool(sim.closed["A"]), limit=60)
    print(f"heartbeat trong 12 s: A={hb[0]}, S={hb[1]}; cat duong truyen luc 12 s -> "
          f"{sim.closed['A'][0][2]} luc {sim.closed['A'][0][0]:.2f} s")

    print("\n== B7. Luồng độc lập: 20 tin chat + 50 chunk file ==")
    block = lambda now, src, raw: now < 3.0 and src == "A" and peek_header(raw).stream_id == 3  # noqa: E731
    sim = Sim(drop=block)
    fs = send_chunks(sim, 50)
    for i in range(20):
        sim.A.send("server", 2, PacketType.CHAT, encode_json({"n": i}))
    sim.run(lambda: len(sim.rx["S"]) >= 20, limit=10)
    chat_done, file_then = sim.now, len(sim.chunks_at_s(fs))
    sim.run(lambda: len(sim.chunks_at_s(fs)) >= 1, limit=30)
    first_file = sim.now
    sim.run(lambda: len(sim.chunks_at_s(fs)) >= 50, limit=30)
    print(f"chan luong file 3 s: chat xong luc {chat_done:.2f} s (file da toi {file_then} chunk); "
          f"chunk dau luc {first_file:.2f} s, file xong luc {sim.now:.2f} s")
    seen = []

    def drop_first_chat(now, src, raw):
        h = peek_header(raw)
        if src == "A" and h.stream_id == 2 and h.seq == 1 and not seen:
            seen.append(now)
            return True
        return False
    sim = Sim(drop=drop_first_chat)
    for i in range(20):
        sim.A.send("server", 2, PacketType.CHAT, encode_json({"n": i}))
    sim.run(lambda: len(sim.rx["S"]) >= 20)
    times = [t for t, *_ in sim.rx["S"]]
    print(f"doi chung, mat goi dau trong luong chat: 20 tin giao trong {min(times):.2f} - {max(times):.2f} s")


if __name__ == "__main__":
    if "--report" in sys.argv:
        print_report()
    else:
        unittest.main()
