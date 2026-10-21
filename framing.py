"""Framing TCP ``[length: uint32 big-endian][JSON UTF-8]`` dùng chung cho server và client.

1b_protocol_spec.md mục 2. Ví dụ::

    send_frame(sock, {"type": "LOGIN", "username": u, "password": p})
    reply = recv_frame(sock)          # dict
"""

import json
import socket
import struct

from protocol import AppError   # chỉ phụ thuộc thứ này + thư viện chuẩn

FRAME_HEADER = struct.Struct("!I")   # uint32 big-endian, không tính chính 4 byte này
MAX_FRAME_LEN = 65536                # body JSON hợp lệ: 1..65536 byte

INVALID_PACKET = "INVALID_PACKET"
PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"


class ConnectionClosed(ConnectionError):
    """Đầu bên kia đóng kết nối trước khi gửi đủ dữ liệu."""


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Đọc đúng ``n`` byte từ socket, lặp ``recv`` cho đến khi đủ.

    TCP là dòng byte, không giữ ranh giới thông điệp: một lần ``recv`` có thể chỉ
    có nửa frame hoặc chứa nhiều frame, nên phải đọc lặp.
    Raise ``ConnectionClosed`` nếu đầu kia đóng khi chưa đủ ``n`` byte;
    ``socket.timeout``/``OSError`` để nguyên cho nơi gọi xử lý.
    """
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionClosed(f"kết nối đóng sau {len(buf)}/{n} byte")
        buf += chunk
    return bytes(buf)


def encode_frame(obj: dict) -> bytes:
    """Mã hóa một object JSON thành frame ``[length][JSON UTF-8]``.

    Cùng quy ước JSON với ``protocol.encode_json``: compact, UTF-8,
    ``ensure_ascii=False``, không NaN/Infinity.
    Raise ``AppError(INVALID_PACKET)`` nếu không phải dict/không serialize được,
    ``AppError(PAYLOAD_TOO_LARGE)`` nếu body > 65536 byte.
    """
    if not isinstance(obj, dict):
        raise AppError(INVALID_PACKET, "JSON phải là object")
    try:
        body = json.dumps(obj, ensure_ascii=False, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise AppError(INVALID_PACKET, "không serialize được JSON") from exc
    if len(body) > MAX_FRAME_LEN:
        raise AppError(PAYLOAD_TOO_LARGE, f"frame dài {len(body)} byte > {MAX_FRAME_LEN}")
    return FRAME_HEADER.pack(len(body)) + body


def send_frame(sock: socket.socket, obj: dict) -> None:
    """Gửi trọn một frame JSON (``sendall`` tự gửi lặp đến khi hết dữ liệu)."""
    sock.sendall(encode_frame(obj))


def recv_frame(sock: socket.socket) -> dict:
    """Nhận một frame và trả về object JSON (dict).

    Đọc đủ 4 byte header, kiểm tra length rồi mới đọc đủ body. Khi length sai
    thì KHÔNG đọc body, vì không còn tin được phần còn lại của luồng byte.

    Lỗi: ``AppError(INVALID_PACKET)`` khi length = 0, body không phải JSON UTF-8,
    không phải object hoặc có NaN/Infinity; ``AppError(PAYLOAD_TOO_LARGE)`` khi
    length > 65536; ``ConnectionClosed`` khi đầu kia đóng giữa chừng.
    """
    (length,) = FRAME_HEADER.unpack(recv_exact(sock, FRAME_HEADER.size))
    if length == 0:
        raise AppError(INVALID_PACKET, "frame rỗng (length = 0)")
    if length > MAX_FRAME_LEN:
        raise AppError(PAYLOAD_TOO_LARGE, f"độ dài frame {length} > {MAX_FRAME_LEN}")
    body = recv_exact(sock, length)
    try:
        obj = json.loads(body.decode("utf-8"), parse_constant=_reject_constant)
    except (UnicodeDecodeError, ValueError):
        raise AppError(INVALID_PACKET, "body không phải JSON UTF-8 hợp lệ") from None
    if not isinstance(obj, dict):
        raise AppError(INVALID_PACKET, "JSON phải là object")
    return obj


def _reject_constant(name: str):
    """NaN/Infinity không phải JSON chuẩn: từ chối giống protocol.decode_json."""
    raise ValueError(f"hằng JSON không hợp lệ: {name}")
