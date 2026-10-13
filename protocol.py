"""CC v1 packet codec. No networking or application routing lives here."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
import json
import struct
import threading
from typing import Protocol

MAGIC = b"CC"
VERSION = 1
HEADER_STRUCT = struct.Struct("!2sBBBQIIH")
HEADER_SIZE = HEADER_STRUCT.size  # 23
ACK_STRUCT = struct.Struct("!II")
CHUNK_STRUCT = struct.Struct("!I")
MAX_DATAGRAM = 1200
CRYPTO_OVERHEAD = 28  # nonce 12 + GCM tag 16
MAX_PLAINTEXT = MAX_DATAGRAM - HEADER_SIZE - CRYPTO_OVERHEAD
UINT32_MAX = (1 << 32) - 1
UINT64_MAX = (1 << 64) - 1


class AppError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class PacketType(IntEnum):
    UDP_BIND = 1
    UDP_BIND_OK = 2
    HEARTBEAT = 3
    USER_LIST = 4
    CHAT = 5
    ACK = 6
    CHAT_STATUS = 7
    FILE_OFFER = 8
    FILE_ACCEPT = 9
    FILE_REJECT = 10
    FILE_CHUNK = 11
    FILE_END = 12
    FILE_RESULT = 13
    ERROR = 14
    LOGOUT = 15


class Flags(IntFlag):
    RELIABLE = 1
    ENCRYPTED = 2


UNRELIABLE_TYPES = frozenset((PacketType.ACK, PacketType.HEARTBEAT))
FILE_TYPES = frozenset((PacketType.FILE_OFFER, PacketType.FILE_ACCEPT,
                       PacketType.FILE_REJECT, PacketType.FILE_CHUNK,
                       PacketType.FILE_END, PacketType.FILE_RESULT))


class CryptoProvider(Protocol):
    """security.py can implement this adapter instead of the context below."""
    def encrypt(self, aad: bytes, plaintext: bytes) -> bytes: ...
    def decrypt(self, aad: bytes, wire_payload: bytes) -> bytes: ...


@dataclass
class CryptoContext:
    """One directional AES-256-GCM key. Never share a send counter across processes.

    Construct separate send/receive contexts with keys/prefixes supplied by TLS.
    A receive context checks the negotiated prefix; it does not reject transport
    retransmissions because valid duplicates must be ACKed again.
    """
    key: bytes = field(repr=False)
    nonce_prefix: bytes = field(repr=False)
    counter: int = field(default=0, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self):
        if len(self.key) != 32 or len(self.nonce_prefix) != 4:
            raise AppError("INVALID_KEY", "AES-256 key/prefix must be 32/4 bytes")
        if not 0 <= self.counter <= UINT64_MAX:
            raise AppError("INVALID_KEY", "Invalid nonce counter")
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        self._aes = AESGCM(self.key)

    def encrypt(self, aad: bytes, plaintext: bytes) -> bytes:
        with self._lock:
            if self.counter > UINT64_MAX:
                raise AppError("SESSION_EXHAUSTED", "Create a new session before nonce wrap")
            nonce = self.nonce_prefix + struct.pack("!Q", self.counter)
            self.counter += 1
        return nonce + self._aes.encrypt(nonce, plaintext, aad)

    def decrypt(self, aad: bytes, wire_payload: bytes) -> bytes:
        from cryptography.exceptions import InvalidTag
        if len(wire_payload) < CRYPTO_OVERHEAD:
            raise AppError("INVALID_PACKET", "Encrypted payload too short")
        nonce = wire_payload[:12]
        if nonce[:4] != self.nonce_prefix:
            raise AppError("INVALID_PACKET", "Unexpected nonce prefix")
        try:
            return self._aes.decrypt(nonce, wire_payload[12:], aad)
        except InvalidTag as exc:
            raise AppError("INVALID_PACKET", "Authentication failed") from exc


@dataclass(frozen=True)
class Header:
    packet_type: PacketType
    session_id: int
    stream_id: int
    seq: int
    flags: int = int(Flags.RELIABLE | Flags.ENCRYPTED)
    payload_len: int = 0

    def pack(self) -> bytes:
        validate_header(self)
        return HEADER_STRUCT.pack(MAGIC, VERSION, int(self.packet_type), self.flags,
                                  self.session_id, self.stream_id, self.seq,
                                  self.payload_len)


@dataclass(frozen=True)
class Packet:
    header: Header
    payload: bytes


def validate_header(h: Header) -> None:
    try:
        kind = PacketType(h.packet_type)
    except (ValueError, TypeError) as exc:
        raise AppError("INVALID_PACKET", "Unknown packet type") from exc
    for value, maximum in ((h.session_id, UINT64_MAX), (h.stream_id, UINT32_MAX),
                           (h.seq, UINT32_MAX), (h.payload_len, MAX_DATAGRAM - HEADER_SIZE)):
        if not isinstance(value, int) or not 0 <= value <= maximum:
            raise AppError("INVALID_PACKET", "Header field out of range")
    if h.session_id == 0 or h.seq == 0:
        raise AppError("INVALID_PACKET", "Session and sequence must be nonzero")
    expected = int(Flags.ENCRYPTED | (0 if kind in UNRELIABLE_TYPES else Flags.RELIABLE))
    if h.flags != expected:
        raise AppError("INVALID_PACKET", "Invalid flags for packet type")
    if kind in UNRELIABLE_TYPES:
        valid = h.stream_id == 0
    elif kind in FILE_TYPES:
        valid = h.stream_id >= 3
    elif kind in (PacketType.CHAT, PacketType.CHAT_STATUS):
        valid = h.stream_id == 2
    elif kind == PacketType.ERROR:
        valid = h.stream_id >= 1
    else:
        valid = h.stream_id == 1
    if not valid:
        raise AppError("INVALID_PACKET", "Packet type not allowed on this stream")


def peek_header(raw: bytes) -> Header:
    """Untrusted session lookup only. Authenticate before using any field."""
    if not isinstance(raw, bytes) or not HEADER_SIZE <= len(raw) <= MAX_DATAGRAM:
        raise AppError("INVALID_PACKET", "Invalid datagram length")
    magic, version, kind, flags, session, stream, seq, length = HEADER_STRUCT.unpack_from(raw)
    if magic != MAGIC or version != VERSION:
        raise AppError("INVALID_PACKET", "Wrong magic/version")
    h = Header(kind, session, stream, seq, flags, length)
    validate_header(h)
    if length < CRYPTO_OVERHEAD or len(raw) != HEADER_SIZE + length:
        raise AppError("INVALID_PACKET", "Payload length mismatch")
    return h


def encode_packet(header: Header, plaintext: bytes, crypto: CryptoProvider) -> bytes:
    if not isinstance(plaintext, bytes):
        raise AppError("INVALID_PACKET", "Payload must be bytes")
    if len(plaintext) > MAX_PLAINTEXT:
        raise AppError("PAYLOAD_TOO_LARGE", "Plaintext exceeds 1149 bytes")
    h = Header(header.packet_type, header.session_id, header.stream_id, header.seq,
               header.flags, len(plaintext) + CRYPTO_OVERHEAD)
    aad = h.pack()
    validate_payload(h.packet_type, plaintext)
    wire = crypto.encrypt(aad, plaintext)
    if len(wire) != h.payload_len:
        raise AppError("INVALID_PACKET", "Crypto adapter returned wrong wire length")
    return aad + wire


def decode_packet(raw: bytes, crypto: CryptoProvider) -> Packet:
    h = peek_header(raw)
    plaintext = crypto.decrypt(raw[:HEADER_SIZE], raw[HEADER_SIZE:])
    if len(plaintext) != h.payload_len - CRYPTO_OVERHEAD:
        raise AppError("INVALID_PACKET", "Decrypted length mismatch")
    validate_payload(h.packet_type, plaintext)
    return Packet(h, plaintext)


def encode_json(value: dict) -> bytes:
    try:
        raw = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as exc:
        raise AppError("INVALID_PACKET", "Invalid JSON") from exc
    if not isinstance(value, dict):
        raise AppError("INVALID_PACKET", "JSON payload must be an object")
    if len(raw) > MAX_PLAINTEXT:
        raise AppError("PAYLOAD_TOO_LARGE", "JSON exceeds 1149 UTF-8 bytes")
    return raw


def decode_json(raw: bytes) -> dict:
    try:
        value = json.loads(raw.decode("utf-8"), parse_constant=lambda x: (_ for _ in ()).throw(ValueError(x)))
    except (UnicodeError, ValueError) as exc:
        raise AppError("INVALID_PACKET", "Invalid JSON") from exc
    if not isinstance(value, dict):
        raise AppError("INVALID_PACKET", "JSON payload must be an object")
    return value


def encode_ack(stream_id: int, seq: int) -> bytes:
    if not 1 <= stream_id <= UINT32_MAX or not 1 <= seq <= UINT32_MAX:
        raise AppError("INVALID_PACKET", "Invalid ACK target")
    return ACK_STRUCT.pack(stream_id, seq)


def decode_ack(raw: bytes) -> tuple[int, int]:
    if len(raw) != ACK_STRUCT.size:
        raise AppError("INVALID_PACKET", "ACK must be 8 bytes")
    stream, seq = ACK_STRUCT.unpack(raw)
    if stream == 0 or seq == 0:
        raise AppError("INVALID_PACKET", "Invalid ACK target")
    return stream, seq


def encode_chunk(chunk_index: int, data: bytes) -> bytes:
    if not 0 <= chunk_index <= UINT32_MAX or not isinstance(data, bytes) or not 1 <= len(data) <= 1024:
        raise AppError("INVALID_PACKET", "Invalid file chunk")
    return CHUNK_STRUCT.pack(chunk_index) + data


def decode_chunk(raw: bytes) -> tuple[int, bytes]:
    if not 5 <= len(raw) <= 1028:
        raise AppError("INVALID_PACKET", "Invalid file chunk length")
    return CHUNK_STRUCT.unpack_from(raw)[0], raw[4:]


def validate_payload(kind: int, raw: bytes) -> None:
    if kind == PacketType.ACK:
        decode_ack(raw)
    elif kind == PacketType.FILE_CHUNK:
        decode_chunk(raw)
    else:
        decode_json(raw)
