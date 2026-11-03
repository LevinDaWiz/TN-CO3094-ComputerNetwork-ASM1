"""
Test lấy số liệu cho Security
"""

import os
import time
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from protocol import (
    AppError, CryptoContext, Header, PacketType,
    Flags, HEADER_SIZE, CRYPTO_OVERHEAD,
    MAX_DATAGRAM, MAX_PLAINTEXT,
    encode_packet, decode_packet
)


def make_pair():
    key = os.urandom(32)
    prefix = os.urandom(4)
    return (
        CryptoContext(key, prefix),
        CryptoContext(key, prefix),
        key,
        prefix
    )


def make_header(seq=1):
    return Header(
        PacketType.CHAT, 101, 2, seq,
        int(Flags.RELIABLE | Flags.ENCRYPTED)
    )


def make_payload(size):
    # JSON object có chính xác size bytes
    return b'{"x":"' + b'a' * (size - 8) + b'"}'


def run_test(code, description, expected, action):
    try:
        actual = action()
        print(f"{code}: PASS | {description} | {actual}")
    except Exception as e:
        print(f"{code}: FAIL | {description} | {type(e).__name__}: {e}")


# C1: Encrypt rồi decrypt bằng đúng key
def test_c1():
    tx, rx, _, _ = make_pair()
    plaintext = b'{"message":"Hello"}'
    raw = encode_packet(make_header(), plaintext, tx)
    result = decode_packet(raw, rx).payload
    assert result == plaintext
    return "Khôi phục đúng plaintext"


# C2: Kích thước datagram với payload 20 bytes
def test_c2():
    tx, _, _, _ = make_pair()
    payload = make_payload(20)
    raw = encode_packet(make_header(), payload, tx)
    expected = HEADER_SIZE + 20 + CRYPTO_OVERHEAD
    assert len(raw) == expected == 71
    return f"{len(raw)} bytes (23 + 20 + 28)"


# C3: MAX_PLAINTEXT
def test_c3():
    tx, _, _, _ = make_pair()
    payload = make_payload(MAX_PLAINTEXT)
    raw = encode_packet(make_header(), payload, tx)
    assert len(raw) == MAX_DATAGRAM

    try:
        encode_packet(make_header(), make_payload(1150), tx)
        raise AssertionError("Payload 1150 bytes was accepted")
    except AppError as e:
        assert e.code == "PAYLOAD_TOO_LARGE"

    return f"{MAX_PLAINTEXT} bytes accepted; 1150 bytes rejected"


# C4: Nonce counter tăng 1, prefix giữ nguyên
def test_c4():
    tx, _, _, prefix = make_pair()
    a = tx.encrypt(b"aad", b"message 1")
    b = tx.encrypt(b"aad", b"message 2")

    nonce_a = a[:12]
    nonce_b = b[:12]

    assert nonce_a[:4] == prefix
    assert nonce_b[:4] == prefix

    counter_a = int.from_bytes(nonce_a[4:], "big")
    counter_b = int.from_bytes(nonce_b[4:], "big")

    assert counter_b == counter_a + 1

    return (
        f"{nonce_a.hex()} -> {nonce_b.hex()}"
    )


# C5: Mã hóa cùng plaintext hai lần
def test_c5():
    tx, _, _, _ = make_pair()
    plaintext = b"same plaintext"

    a = tx.encrypt(b"aad", plaintext)
    b = tx.encrypt(b"aad", plaintext)

    assert a != b
    assert a[:12] != b[:12]

    return "Ciphertext khác nhau"


# C6: Lật một bit trong GCM tag
def test_c6():
    tx, rx, _, _ = make_pair()
    raw = bytearray(
        encode_packet(make_header(), b'{"x":"hello"}', tx)
    )

    raw[-1] ^= 1

    try:
        decode_packet(bytes(raw), rx)
        raise AssertionError("Tampered tag accepted")
    except AppError as e:
        assert e.code == "INVALID_PACKET"
        return f"{e.code}: {e.message}"


# C7: Lật một bit trong header (AAD)
def test_c7():
    tx, rx, _, _ = make_pair()
    raw = bytearray(
        encode_packet(make_header(seq=1), b'{"x":"hello"}', tx)
    )

    # Byte 20 thuộc trường seq.
    # XOR 0x04: seq 1 thành seq 5, vẫn là header hợp lệ.
    raw[20] ^= 0x04

    try:
        decode_packet(bytes(raw), rx)
        raise AssertionError("Modified AAD accepted")
    except AppError as e:
        assert e.code == "INVALID_PACKET"
        return f"{e.code}: Header authentication failed"


# C8: Giải mã bằng khóa sai
def test_c8():
    tx, _, _, _ = make_pair()
    wrong_key = os.urandom(32)

    raw = encode_packet(
        make_header(), b'{"x":"hello"}', tx
    )

    rx = CryptoContext(wrong_key, raw[HEADER_SIZE:HEADER_SIZE+4])

    try:
        decode_packet(raw, rx)
        raise AssertionError("Wrong key accepted")
    except AppError as e:
        assert e.code == "INVALID_PACKET"
        return e.code


# C9: Nonce prefix không khớp
def test_c9():
    tx, _, key, prefix = make_pair()
    raw = encode_packet(
        make_header(), b'{"x":"hello"}', tx
    )

    wrong_prefix = bytes([prefix[0] ^ 1]) + prefix[1:]
    rx = CryptoContext(key, wrong_prefix)

    try:
        decode_packet(raw, rx)
        raise AssertionError("Wrong prefix accepted")
    except AppError as e:
        assert e.code == "INVALID_PACKET"
        return f"{e.code}: {e.message}"


# C10: Khóa sai độ dài
def test_c10():
    try:
        CryptoContext(os.urandom(16), os.urandom(4))
        raise AssertionError("Invalid key accepted")
    except AppError as e:
        assert e.code == "INVALID_KEY"
        return f"AppError({e.code})"


def benchmark():
    key = os.urandom(32)
    prefix = os.urandom(4)
    plaintext = os.urandom(MAX_PLAINTEXT)
    aad = b"\x00" * HEADER_SIZE

    rounds = 10000
    measurements = []

    # Warm-up
    warmup = CryptoContext(key, prefix)
    for _ in range(100):
        warmup.encrypt(aad, plaintext)

    # Mỗi lần đo dùng context mới, counter bắt đầu từ 0.
    for _ in range(5):
        ctx = CryptoContext(key, prefix)

        start = time.perf_counter()

        for _ in range(rounds):
            ctx.encrypt(aad, plaintext)

        elapsed = time.perf_counter() - start
        measurements.append(elapsed)

    elapsed = statistics.median(measurements)

    pps = rounds / elapsed
    mbps = rounds * MAX_PLAINTEXT / elapsed / 1_000_000

    print("\n=== AES-256-GCM BENCHMARK ===")
    print(f"Packets       : {rounds}")
    print(f"Payload       : {MAX_PLAINTEXT} bytes")
    print(f"Median time   : {elapsed:.6f} seconds")
    print(f"Throughput    : {pps:,.0f} packets/second")
    print(f"Data rate     : {mbps:.2f} MB/s")


if __name__ == "__main__":
    tests = [
        ("C1", "Encrypt / Decrypt", test_c1),
        ("C2", "Datagram size", test_c2),
        ("C3", "MAX_PLAINTEXT", test_c3),
        ("C4", "Nonce counter", test_c4),
        ("C5", "Same plaintext twice", test_c5),
        ("C6", "Tampered GCM tag", test_c6),
        ("C7", "Tampered header / AAD", test_c7),
        ("C8", "Wrong key", test_c8),
        ("C9", "Wrong nonce prefix", test_c9),
        ("C10", "Invalid key length", test_c10),
    ]

    print("=== CRYPTOGRAPHY TESTS ===")

    for code, description, action in tests:
        run_test(code, description, "PASS", action)

    benchmark()
