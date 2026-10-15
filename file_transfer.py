"""Truyền tệp tin cậy qua luồng UDP riêng (Người 4) — phía client.

``FileTransferManager`` gửi/nhận tệp, ghi tệp tạm, kiểm tra SHA-256 và phát
event tiến độ. Module không mở socket mà đi qua ``ReliableUDP``; ACK, truyền
lại, sắp thứ tự và mã hóa do transport lo. Mỗi tệp chạy trên một luồng >=3
riêng nên mất gói ở tệp này không chặn chat (stream 2) hay tệp khác.

Phần chuyển tiếp ở server (S bên dưới) thuộc server.py, không nằm ở đây.

Vòng đời một lần truyền (1b_protocol_spec.md §7)::

    A --FILE_OFFER--> S --FILE_OFFER(+from)--> B   emit file_offer
    A <-FILE_ACCEPT-- S <-FILE_ACCEPT--------- B   (<=60s, không thì TRANSFER_TIMEOUT)
    A --FILE_CHUNK*-> S --FILE_CHUNK*--------> B   ghi .part, cập nhật SHA-256 dần
    A --FILE_END----> S --FILE_END-----------> B   kiểm tra số chunk, size, hash
    A <-FILE_RESULT-- S <-FILE_RESULT--------- B   đổi tên .part -> tên thật

Các hàm ``handle_*`` nhận callback của transport (payload, delivery, failure,
peer_closed) và trả True nếu gói/delivery thuộc module này. Callback chỉ làm
việc nhỏ (ghi 1 KiB, cập nhật hash) rồi trả về; event được phát qua ``emit``
sau khi nhả lock. ``start()`` chạy timer cho timeout và bơm chunk lại.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import logging
import math
import os
import threading
import time
import uuid
from typing import Callable

from protocol import (AppError, PacketType, decode_chunk, decode_json,
                      encode_chunk, encode_json)

log = logging.getLogger(__name__)

CHUNK_SIZE = 1024
MAX_FILE_SIZE = 100 * 1024 * 1024          # 100 MiB / tệp (giới hạn v1)
MAX_FILENAME_BYTES = 255
MAX_USER_ID_LEN = 32
MAX_REASON_CHARS = 200

ACCEPT_TIMEOUT = 60.0      # chờ người nhận chấp nhận
IDLE_TIMEOUT = 60.0        # không có tiến triển trong lúc truyền
# Chunk chưa ACK / tệp (transport giới hạn 256 / luồng). Đo trên localhost:
# 16 -> 0.6 MiB/s, 64 -> 2.2, 128 -> 3.3, 200 -> 3.0 (cửa sổ transport là trần).
MAX_INFLIGHT = 128
PROGRESS_INTERVAL = 0.2    # tối đa 5 event tiến độ / giây / tệp

# Trạng thái (1a_api.md §3). awaiting_upload thuộc bridge, không có ở đây.
OFFERED = "offered"
ACCEPTED = "accepted"
TRANSFERRING = "transferring"
VERIFYING = "verifying"
COMPLETED = "completed"
FAILED = "failed"
REJECTED = "rejected"
TERMINAL = frozenset((COMPLETED, FAILED, REJECTED))

OUTGOING = "outgoing"
INCOMING = "incoming"

# Mã lỗi (1b_protocol_spec.md §9) và vài mã cục bộ
INVALID_PACKET = "INVALID_PACKET"
USER_OFFLINE = "USER_OFFLINE"
TRANSFER_REJECTED = "TRANSFER_REJECTED"
TRANSFER_TIMEOUT = "TRANSFER_TIMEOUT"
CHECKSUM_MISMATCH = "CHECKSUM_MISMATCH"
FILE_TOO_LARGE = "FILE_TOO_LARGE"
IO_ERROR = "IO_ERROR"
DELIVERY_TIMEOUT = "DELIVERY_TIMEOUT"
QUEUE_FULL = "QUEUE_FULL"
TRANSFER_FAILED = "TRANSFER_FAILED"
TRANSFER_NOT_FOUND = "TRANSFER_NOT_FOUND"
INVALID_STATE = "INVALID_STATE"
DUPLICATE_TRANSFER = "DUPLICATE_TRANSFER"
CLIENT_CLOSED = "CLIENT_CLOSED"

# FILE_REJECT với reason là một trong các mã này = thất bại tự động, không phải người dùng từ chối.
_AUTO_REJECT_CODES = frozenset((TRANSFER_TIMEOUT, INVALID_PACKET, IO_ERROR, FILE_TOO_LARGE,
                                DUPLICATE_TRANSFER))

FILE_PACKETS = frozenset((PacketType.FILE_OFFER, PacketType.FILE_ACCEPT,
                          PacketType.FILE_REJECT, PacketType.FILE_CHUNK,
                          PacketType.FILE_END, PacketType.FILE_RESULT))

_FORBIDDEN_CHARS = set('<>:"/\\|?*')
_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL",
                   *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


# ---------------------------------------------------------------------------
# Hàm tiện ích (thuần, dễ test)
# ---------------------------------------------------------------------------

def total_chunks(size: int) -> int:
    return math.ceil(size / CHUNK_SIZE)


def chunk_length(index: int, size: int) -> int:
    """Mọi chunk đủ 1024 byte, trừ chunk cuối là phần còn lại."""
    return min(CHUNK_SIZE, size - index * CHUNK_SIZE)


def sha256_file(path: str) -> str:
    """Băm theo khối, không nạp cả tệp vào RAM."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def is_file_packet(stream_id: int, packet_type: int) -> bool:
    """FILE_* luôn ở luồng >=3; ERROR trên luồng >=3 cũng thuộc một tệp."""
    return stream_id >= 3 and (packet_type in FILE_PACKETS or packet_type == PacketType.ERROR)


def safe_filename(name) -> str:
    """Chỉ giữ basename an toàn: bỏ thư mục, ký tự cấm Windows, tên dành riêng.

    Không bao giờ dùng đường dẫn từ bên gửi (chống ghi ra ngoài thư mục tải).
    """
    if not isinstance(name, str):
        name = ""
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join("_" if c in _FORBIDDEN_CHARS or ord(c) < 32 or ord(c) == 127 else c
                   for c in name)
    name = name.strip().rstrip(". ")
    if not name:
        name = "file"
    if name.split(".")[0].upper() in _RESERVED_NAMES:
        name = "_" + name
    if len(name.encode("utf-8")) > MAX_FILENAME_BYTES:
        stem, ext = os.path.splitext(name)
        if len(ext.encode("utf-8")) > 32:
            stem, ext = name, ""
        budget = MAX_FILENAME_BYTES - len(ext.encode("utf-8"))
        stem = stem.encode("utf-8")[:budget].decode("utf-8", "ignore") or "file"
        name = stem + ext
    return name


def unique_path(directory: str, filename: str) -> str:
    """Giữ chỗ một tên chưa tồn tại (O_EXCL); trùng thì thêm " (1)", " (2)"..."""
    stem, ext = os.path.splitext(filename)
    for i in range(10_000):
        candidate = filename if i == 0 else f"{stem} ({i}){ext}"
        path = os.path.join(directory, candidate)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o644)
        except FileExistsError:
            continue
        os.close(fd)
        return path
    raise AppError(IO_ERROR, "Không tìm được tên tệp trống")


def _is_uuid(value) -> bool:
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _is_user_id(value) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= MAX_USER_ID_LEN
            and value.isascii() and value.isprintable() and " " not in value)


def _is_sha256(value) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdefABCDEF" for c in value))


def _is_size(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def validate_offer(payload: dict, *, require_from: bool) -> dict:
    """Kiểm tra FILE_OFFER; trả bản đã chuẩn hóa hoặc raise AppError."""
    tid = payload.get("transfer_id")
    if not _is_uuid(tid):
        raise AppError(INVALID_PACKET, "transfer_id phải là UUID")
    sender = payload.get("from")
    if require_from and not _is_user_id(sender):
        raise AppError(INVALID_PACKET, "Thiếu from")
    filename = payload.get("filename")
    if (not isinstance(filename, str) or not filename
            or len(filename.encode("utf-8")) > MAX_FILENAME_BYTES):
        raise AppError(INVALID_PACKET, "filename không hợp lệ")
    size = payload.get("size")
    if not _is_size(size):
        raise AppError(INVALID_PACKET, "size không hợp lệ")
    if size > MAX_FILE_SIZE:
        raise AppError(FILE_TOO_LARGE, "Tệp vượt 100 MiB")
    if payload.get("chunk_size") != CHUNK_SIZE:
        raise AppError(INVALID_PACKET, "chunk_size phải là 1024")
    if payload.get("total_chunks") != total_chunks(size):
        raise AppError(INVALID_PACKET, "total_chunks không khớp size")
    if not _is_sha256(payload.get("sha256")):
        raise AppError(INVALID_PACKET, "sha256 phải là 64 ký tự hex")
    return {"transfer_id": tid, "from": sender, "filename": safe_filename(filename),
            "size": size, "sha256": payload["sha256"].lower()}


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

@dataclass(eq=False)
class Transfer:
    transfer_id: str
    direction: str              # OUTGOING | INCOMING
    peer_id: str                # user_id bên kia
    filename: str
    size: int
    status: str
    sha256: str = ""
    stream_id: int = 0
    total_chunks: int = 0
    bytes_done: int = 0         # gửi: byte đã ACK chặng client->server; nhận: byte đã ghi
    error_code: str | None = None
    deadline: float = 0.0
    # Bên gửi
    source_path: str | None = None
    next_chunk: int = 0         # gửi: chunk sẽ đọc tiếp; nhận: chunk đang chờ
    acked_chunks: int = 0
    inflight: int = 0
    end_sent: bool = False
    # Bên nhận
    temp_path: str | None = None
    final_path: str | None = None
    hasher: object = field(default=None, repr=False)
    fh: object = field(default=None, repr=False)
    last_progress: float = float("-inf")

    @property
    def progress(self) -> float:
        if self.size == 0:
            return 100.0 if self.status == COMPLETED else 0.0
        return round(self.bytes_done * 100 / self.size, 1)

    def snapshot(self) -> dict:
        return {"transfer_id": self.transfer_id, "direction": self.direction,
                "peer_id": self.peer_id, "filename": self.filename, "size": self.size,
                "status": self.status, "bytes_done": self.bytes_done,
                "progress": self.progress, "error_code": self.error_code}


class FileTransferManager:
    """Gửi/nhận tệp ở client qua peer ``server_peer`` của transport.

    Một RLock bảo vệ mọi trạng thái. Được phép gọi ``transport.send`` khi đang
    giữ lock vì transport không bao giờ gọi ngược vào đây trong lock của nó.
    """

    def __init__(self, transport, *, server_peer: str = "server",
                 download_dir: str = "downloads",
                 emit: Callable[[str, dict], None] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 max_inflight: int = MAX_INFLIGHT,
                 accept_timeout: float = ACCEPT_TIMEOUT,
                 idle_timeout: float = IDLE_TIMEOUT):
        if max_inflight < 1:
            raise ValueError("max_inflight phải >= 1")
        self.transport = transport
        self.server_peer = server_peer
        self.download_dir = os.path.abspath(download_dir)
        self.clock = clock
        self.max_inflight = max_inflight
        self.accept_timeout = accept_timeout
        self.idle_timeout = idle_timeout
        self._emit_cb = emit
        self._lock = threading.RLock()
        self._flush_lock = threading.RLock()
        self._outbox: list[tuple[str, dict]] = []
        self._transfers: dict[str, Transfer] = {}
        self._by_stream: dict[int, str] = {}
        self._deliveries: dict[str, tuple[str, str, int]] = {}   # delivery_id -> (tid, kind, nbytes)
        self._stop = threading.Event()
        self._timer: threading.Thread | None = None

    # ----- API module (1a_api.md §5) -----

    def offer_file(self, to: str, path: str, transfer_id: str | None = None, *,
                   filename: str | None = None, sha256: str | None = None) -> str:
        """Gửi FILE_OFFER cho tệp ``path`` (đường dẫn do bên gọi quản lý).

        Tham số tùy chọn ngoài hợp đồng: ``transfer_id`` (None thì tự sinh),
        ``filename`` hiển thị khi tên tệp trên đĩa khác tên gốc, ``sha256`` nếu
        bên gọi đã băm sẵn. Tệp ``path`` phải giữ nguyên tới khi transfer kết thúc.
        """
        if not _is_user_id(to):
            raise AppError(INVALID_PACKET, "Người nhận không hợp lệ")
        if transfer_id is not None and not _is_uuid(transfer_id):
            raise AppError(INVALID_PACKET, "transfer_id phải là UUID")
        try:
            size = os.path.getsize(path)
        except OSError as exc:
            raise AppError(IO_ERROR, "Không đọc được tệp nguồn") from exc
        if size > MAX_FILE_SIZE:
            raise AppError(FILE_TOO_LARGE, "Tệp vượt 100 MiB")
        if sha256 is None:
            try:
                sha256 = sha256_file(path)      # ngoài lock: tệp lớn băm lâu
            except OSError as exc:
                raise AppError(IO_ERROR, "Không đọc được tệp nguồn") from exc
        elif not _is_sha256(sha256):
            raise AppError(INVALID_PACKET, "sha256 không hợp lệ")
        try:
            with self._lock:
                tid = transfer_id or str(uuid.uuid4())
                if tid in self._transfers:
                    raise AppError(INVALID_STATE, "transfer_id đã tồn tại")
                t = Transfer(tid, OUTGOING, to,
                             safe_filename(filename or os.path.basename(path)), size, OFFERED,
                             sha256=sha256.lower(), total_chunks=total_chunks(size),
                             source_path=path)
                self._transfers[tid] = t
                try:
                    t.stream_id = self.transport.allocate_stream(self.server_peer)
                    self._by_stream[t.stream_id] = t.transfer_id
                    offer = encode_json({"transfer_id": t.transfer_id, "to": t.peer_id,
                                         "filename": t.filename, "size": t.size,
                                         "chunk_size": CHUNK_SIZE, "total_chunks": t.total_chunks,
                                         "sha256": t.sha256})
                    self._send(t, PacketType.FILE_OFFER, offer, "offer")
                except AppError as exc:
                    self._fail(t, exc.code)
                    raise
                t.deadline = self.clock() + self.accept_timeout
                self._set_status(t, OFFERED)
                return t.transfer_id
        finally:
            self._flush()

    def accept_transfer(self, transfer_id: str) -> None:
        try:
            with self._lock:
                t = self._incoming_offer(transfer_id)
                try:
                    os.makedirs(self.download_dir, exist_ok=True)
                    t.temp_path = os.path.join(self.download_dir, f".{t.transfer_id}.part")
                    t.fh = open(t.temp_path, "wb")
                except OSError as exc:
                    self._fail(t, IO_ERROR, notify="reject")
                    raise AppError(IO_ERROR, "Không tạo được tệp tạm") from exc
                t.hasher = hashlib.sha256()
                try:
                    self._send(t, PacketType.FILE_ACCEPT,
                               encode_json({"transfer_id": t.transfer_id}), "accept")
                except AppError as exc:
                    self._fail(t, exc.code)
                    raise
                t.deadline = self.clock() + self.idle_timeout
                self._set_status(t, ACCEPTED)
        finally:
            self._flush()

    def reject_transfer(self, transfer_id: str, reason: str = "Không nhận tệp") -> None:
        if not isinstance(reason, str):
            reason = ""
        try:
            with self._lock:
                t = self._incoming_offer(transfer_id)
                t.status = REJECTED
                self._event("file_status", self._status_data(t))
                payload = encode_json({"transfer_id": t.transfer_id,
                                       "reason": reason[:MAX_REASON_CHARS]})
                self._send_final(t, PacketType.FILE_REJECT, payload)
        finally:
            self._flush()

    def list_transfers(self) -> list[dict]:
        with self._lock:
            return [t.snapshot() for t in self._transfers.values()]

    def get_transfer(self, transfer_id: str) -> dict:
        with self._lock:
            return self._get(transfer_id).snapshot()

    def get_download_path(self, transfer_id: str) -> str:
        """Đường dẫn tệp đã nhận xong (GET /api/files/{id}/download)."""
        with self._lock:
            t = self._get(transfer_id)
            if t.direction != INCOMING or t.status != COMPLETED or not t.final_path:
                raise AppError(INVALID_STATE, "Tệp chưa nhận xong")
            return t.final_path

    # ----- Callback từ transport -----

    def handle_packet(self, peer_id: str, stream_id: int, packet_type: int, payload: bytes) -> bool:
        if peer_id != self.server_peer or not is_file_packet(stream_id, packet_type):
            return False
        try:
            with self._lock:
                self._on_packet(stream_id, PacketType(packet_type), payload)
        finally:
            self._flush()
        return True

    def handle_delivery(self, delivery_id: str) -> bool:
        try:
            with self._lock:
                return self._on_delivery(delivery_id)
        finally:
            self._flush()

    def handle_failure(self, delivery_id: str, error_code: str | None = None) -> bool:
        try:
            with self._lock:
                info = self._deliveries.pop(delivery_id, None)
                if info is None:
                    return False
                if info[1] == "final-orphan":
                    self._close_stream_id(info[2], error_code or DELIVERY_TIMEOUT)
                    return True
                t = self._transfers.get(info[0])
                if t is not None:
                    if info[1] == "final" or t.status in TERMINAL:
                        self._close_stream(t, error_code or DELIVERY_TIMEOUT)
                    else:
                        # Transport đã đóng luồng hỏng; không còn đường báo bên kia.
                        self._fail(t, error_code or DELIVERY_TIMEOUT)
                return True
        finally:
            self._flush()

    def handle_peer_closed(self, peer_id: str, reason: str | None = None) -> bool:
        """Mất phiên với server: mọi tệp dang dở thất bại, dọn tệp tạm."""
        if peer_id != self.server_peer:
            return False
        try:
            with self._lock:
                for t in list(self._transfers.values()):
                    self._fail(t, reason or "PEER_CLOSED")
                # Phiên mới cấp lại stream từ 3: bỏ ánh xạ cũ.
                self._by_stream.clear()
                self._deliveries.clear()
        finally:
            self._flush()
        return True

    # ----- Timer -----

    def tick(self) -> None:
        """Kiểm tra timeout và bơm tiếp chunk bị QUEUE_FULL. Gọi định kỳ."""
        now = self.clock()
        try:
            with self._lock:
                for t in list(self._transfers.values()):
                    if t.status in TERMINAL:
                        continue
                    if now >= t.deadline:
                        if t.direction == OUTGOING:
                            self._fail(t, TRANSFER_TIMEOUT, notify="error")
                        elif t.status == OFFERED:
                            self._fail(t, TRANSFER_TIMEOUT, notify="reject")
                        else:
                            self._fail(t, TRANSFER_TIMEOUT, notify="result")
                    elif t.direction == OUTGOING and t.status == TRANSFERRING:
                        self._pump(t)
        finally:
            self._flush()

    def start(self, interval: float = 0.25) -> None:
        if self._timer is not None:
            return
        self._stop.clear()

        def loop():
            while not self._stop.wait(interval):
                try:
                    self.tick()
                except Exception:
                    log.exception("File transfer tick failed")

        self._timer = threading.Thread(target=loop, daemon=True, name="cc-files")
        self._timer.start()

    def stop(self) -> None:
        self._stop.set()
        if self._timer is not None and self._timer is not threading.current_thread():
            self._timer.join(timeout=1)
        self._timer = None

    def close(self) -> None:
        """Client thoát/đăng xuất: dừng timer, hủy tệp dang dở, xóa tệp tạm."""
        self.stop()
        try:
            with self._lock:
                for t in list(self._transfers.values()):
                    self._fail(t, CLIENT_CLOSED)
        finally:
            self._flush()

    # ----- Xử lý gói (đang giữ lock) -----

    def _on_packet(self, stream_id: int, kind: PacketType, payload: bytes) -> None:
        if kind == PacketType.FILE_OFFER:
            self._on_offer(stream_id, payload)
            return
        t = self._transfers.get(self._by_stream.get(stream_id))
        if t is None or t.status in TERMINAL:
            return      # gói muộn của tệp đã xong
        if kind == PacketType.FILE_CHUNK:
            self._on_chunk(t, payload)
            return
        try:
            msg = decode_json(payload)
        except AppError:
            self._fail(t, INVALID_PACKET, notify="result" if t.direction == INCOMING else "error")
            return
        if kind == PacketType.ERROR:
            code = msg.get("code")
            self._fail(t, code if isinstance(code, str) and code else TRANSFER_FAILED)
        elif msg.get("transfer_id") != t.transfer_id:
            self._fail(t, INVALID_PACKET, notify="result" if t.direction == INCOMING else "error")
        elif t.direction == OUTGOING and kind == PacketType.FILE_ACCEPT:
            self._on_accept(t)
        elif t.direction == OUTGOING and kind == PacketType.FILE_REJECT:
            reason = msg.get("reason")
            if reason in _AUTO_REJECT_CODES:
                # Bên nhận tự từ chối (hết giờ, offer hỏng...), không phải người dùng.
                self._fail(t, reason)
                return
            t.status, t.error_code = REJECTED, TRANSFER_REJECTED
            self._cleanup_files(t, success=False)
            data = self._status_data(t)
            data["reason"] = reason[:MAX_REASON_CHARS] if isinstance(reason, str) else None
            self._event("file_status", data)
            self._close_stream(t, TRANSFER_REJECTED)
        elif t.direction == OUTGOING and kind == PacketType.FILE_RESULT:
            self._on_result(t, msg)
        elif t.direction == INCOMING and kind == PacketType.FILE_END:
            self._on_end(t)
        else:
            notify = "result" if t.direction == INCOMING else "error"
            self._fail(t, INVALID_PACKET, notify=notify)

    def _on_offer(self, stream_id: int, payload: bytes) -> None:
        if stream_id in self._by_stream:
            return
        try:
            raw = decode_json(payload)
        except AppError:
            raw = {}
        try:
            offer = validate_offer(raw, require_from=True)
        except AppError as exc:
            self._refuse_stream(stream_id, raw.get("transfer_id"), exc.code)
            return
        tid = offer["transfer_id"]
        if tid in self._transfers:
            self._refuse_stream(stream_id, tid, DUPLICATE_TRANSFER)
            return
        t = Transfer(tid, INCOMING, offer["from"], offer["filename"], offer["size"], OFFERED,
                     sha256=offer["sha256"], stream_id=stream_id,
                     total_chunks=total_chunks(offer["size"]),
                     deadline=self.clock() + self.accept_timeout)
        self._transfers[tid] = t
        self._by_stream[stream_id] = tid
        self._event("file_offer", {"transfer_id": tid, "from": t.peer_id,
                                   "filename": t.filename, "size": t.size})
        self._event("file_status", self._status_data(t))

    def _refuse_stream(self, stream_id: int, tid, code: str) -> None:
        """Offer hỏng: trả FILE_REJECT nếu có transfer_id hợp lệ, rồi đóng luồng."""
        if _is_uuid(tid):
            try:
                did = self.transport.send(self.server_peer, stream_id, PacketType.FILE_REJECT,
                                          encode_json({"transfer_id": tid, "reason": code}))
                # Chỉ để đóng luồng sau khi gói tới; không gắn transfer.
                self._deliveries[did] = ("", "final-orphan", stream_id)
                return
            except AppError:
                pass
        self._close_stream_id(stream_id, code)

    def _on_accept(self, t: Transfer) -> None:
        if t.status != OFFERED:
            self._fail(t, INVALID_PACKET, notify="error")
            return
        self._set_status(t, ACCEPTED)
        try:
            t.fh = open(t.source_path, "rb")
        except OSError:
            self._fail(t, IO_ERROR, notify="error")
            return
        t.deadline = self.clock() + self.idle_timeout
        self._set_status(t, TRANSFERRING)
        self._progress(t, force=True)
        self._pump(t)

    def _pump(self, t: Transfer) -> None:
        """Giữ tối đa max_inflight chunk chưa ACK; đủ ACK thì gửi FILE_END."""
        while t.inflight < self.max_inflight and t.next_chunk < t.total_chunks:
            n = chunk_length(t.next_chunk, t.size)
            try:
                data = t.fh.read(n)
            except OSError:
                data = b""
            if len(data) != n:
                self._fail(t, IO_ERROR, notify="error")     # tệp nguồn bị đổi/xóa
                return
            try:
                self._send(t, PacketType.FILE_CHUNK, encode_chunk(t.next_chunk, data), "chunk", n)
            except AppError as exc:
                if exc.code == QUEUE_FULL:
                    # Chunk đã đọc nhưng chưa gửi: lùi con trỏ, thử lại ở tick/ACK sau.
                    t.fh.seek(t.next_chunk * CHUNK_SIZE)
                    return
                self._fail(t, exc.code)
                return
            t.next_chunk += 1
            t.inflight += 1
        if t.next_chunk == t.total_chunks and t.inflight == 0 and not t.end_sent:
            try:
                self._send(t, PacketType.FILE_END, encode_json({"transfer_id": t.transfer_id}), "end")
            except AppError as exc:
                if exc.code != QUEUE_FULL:
                    self._fail(t, exc.code)
                return
            t.end_sent = True
            t.fh.close()
            t.fh = None
            t.deadline = self.clock() + self.idle_timeout
            self._set_status(t, VERIFYING)

    def _on_result(self, t: Transfer, msg: dict) -> None:
        if msg.get("status") == COMPLETED:
            if not t.end_sent or t.acked_chunks != t.total_chunks:
                self._fail(t, INVALID_PACKET)
                return
            t.status = COMPLETED
            self._cleanup_files(t, success=True)
            self._progress(t, force=True)
            self._event("file_status", self._status_data(t))
            self._event("file_completed", {"transfer_id": t.transfer_id, "direction": t.direction,
                                           "filename": t.filename, "size": t.size})
            self._close_stream(t, "TRANSFER_DONE")
        else:
            code = msg.get("error_code")
            self._fail(t, code if isinstance(code, str) and code else TRANSFER_FAILED)

    def _on_chunk(self, t: Transfer, payload: bytes) -> None:
        if t.direction != INCOMING or t.status not in (ACCEPTED, TRANSFERRING):
            self._fail(t, INVALID_PACKET, notify="result" if t.direction == INCOMING else "error")
            return
        try:
            index, data = decode_chunk(payload)
        except AppError:
            index, data = -1, b""
        # Transport giao đúng thứ tự, nên chunk phải là chunk kế tiếp.
        if (index != t.next_chunk or index >= t.total_chunks
                or len(data) != chunk_length(index, t.size)):
            self._fail(t, INVALID_PACKET, notify="result")
            return
        try:
            t.fh.write(data)
        except OSError:
            self._fail(t, IO_ERROR, notify="result")
            return
        t.hasher.update(data)
        t.next_chunk += 1
        t.bytes_done += len(data)
        t.deadline = self.clock() + self.idle_timeout
        if t.status == ACCEPTED:
            self._set_status(t, TRANSFERRING)
        self._progress(t, force=t.bytes_done == t.size)

    def _on_end(self, t: Transfer) -> None:
        if t.status not in (ACCEPTED, TRANSFERRING):
            self._fail(t, INVALID_PACKET, notify="result")
            return
        self._set_status(t, VERIFYING)
        if t.next_chunk != t.total_chunks or t.bytes_done != t.size:
            self._fail(t, INVALID_PACKET, notify="result")
            return
        if t.hasher.hexdigest() != t.sha256:
            self._fail(t, CHECKSUM_MISMATCH, notify="result")
            return
        final = None
        try:
            t.fh.close()
            t.fh = None
            final = unique_path(self.download_dir, t.filename)
            os.replace(t.temp_path, final)
        except (OSError, AppError):
            if final:
                _remove_quietly(final)
            self._fail(t, IO_ERROR, notify="result")
            return
        t.final_path, t.temp_path = final, None
        t.status = COMPLETED
        self._progress(t, force=True)
        self._event("file_status", self._status_data(t))
        self._event("file_completed", {"transfer_id": t.transfer_id, "direction": t.direction,
                                       "filename": os.path.basename(final), "size": t.size})
        self._send_final(t, PacketType.FILE_RESULT, encode_json(
            {"transfer_id": t.transfer_id, "status": COMPLETED, "error_code": None}))

    def _on_delivery(self, delivery_id: str) -> bool:
        info = self._deliveries.pop(delivery_id, None)
        if info is None:
            return False
        tid, kind, n = info
        if kind == "final-orphan":
            self._close_stream_id(n, "TRANSFER_DONE")
            return True
        t = self._transfers.get(tid)
        if t is None:
            return True
        if kind == "final":
            self._close_stream(t, "TRANSFER_DONE")
            return True
        if t.status in TERMINAL:
            return True
        if t.status != OFFERED:     # đang chờ chấp nhận: giữ hạn accept_timeout
            t.deadline = self.clock() + self.idle_timeout
        if kind == "chunk":
            t.inflight -= 1
            t.acked_chunks += 1
            t.bytes_done += n
            self._progress(t, force=t.bytes_done == t.size)
            if t.status == TRANSFERRING:
                self._pump(t)
        return True

    # ----- Nội bộ -----

    def _send(self, t: Transfer, kind: PacketType, payload: bytes, tag: str, nbytes: int = 0) -> str:
        did = self.transport.send(self.server_peer, t.stream_id, kind, payload)
        self._deliveries[did] = (t.transfer_id, tag, nbytes)
        return did

    def _send_final(self, t: Transfer, kind: PacketType, payload: bytes) -> None:
        """Gói cuối của luồng: đóng luồng khi gói đã tới (hoặc gửi thất bại)."""
        try:
            self._send(t, kind, payload, "final")
        except AppError:
            self._close_stream(t, TRANSFER_FAILED)

    def _fail(self, t: Transfer, code: str, notify: str | None = None) -> None:
        """Chuyển failed, dọn tệp; ``notify`` = error|result|reject để báo bên kia."""
        if t.status in TERMINAL:
            return
        t.status, t.error_code = FAILED, code
        self._cleanup_files(t, success=False)
        self._event("file_status", self._status_data(t))
        if not t.stream_id:
            return
        if notify == "error":
            self._send_final(t, PacketType.ERROR, encode_json(
                {"code": code, "message": "Truyền tệp thất bại", "reference_id": t.transfer_id}))
        elif notify == "result":
            self._send_final(t, PacketType.FILE_RESULT, encode_json(
                {"transfer_id": t.transfer_id, "status": FAILED, "error_code": code}))
        elif notify == "reject":
            self._send_final(t, PacketType.FILE_REJECT, encode_json(
                {"transfer_id": t.transfer_id, "reason": code}))
        else:
            self._close_stream(t, code)

    def _cleanup_files(self, t: Transfer, *, success: bool) -> None:
        if t.fh is not None:
            try:
                t.fh.close()
            except OSError:
                pass
            t.fh = None
        if t.direction == INCOMING and not success and t.temp_path:
            _remove_quietly(t.temp_path)
            t.temp_path = None

    def _close_stream(self, t: Transfer, reason: str) -> None:
        if t.stream_id and self._by_stream.get(t.stream_id) == t.transfer_id:
            self._close_stream_id(t.stream_id, reason)

    def _close_stream_id(self, stream_id: int, reason: str) -> None:
        self._by_stream.pop(stream_id, None)
        try:
            self.transport.close_stream(self.server_peer, stream_id, reason)
        except AppError:
            pass        # peer đã đóng

    def _set_status(self, t: Transfer, status: str) -> None:
        t.status = status
        self._event("file_status", self._status_data(t))

    def _progress(self, t: Transfer, *, force: bool = False) -> None:
        now = self.clock()
        if force or now - t.last_progress >= PROGRESS_INTERVAL:
            t.last_progress = now
            self._event("file_progress", {"transfer_id": t.transfer_id, "direction": t.direction,
                                          "bytes_done": t.bytes_done, "total_bytes": t.size,
                                          "progress": t.progress})

    @staticmethod
    def _status_data(t: Transfer) -> dict:
        return {"transfer_id": t.transfer_id, "direction": t.direction,
                "status": t.status, "error_code": t.error_code}

    def _get(self, transfer_id: str) -> Transfer:
        t = self._transfers.get(transfer_id)
        if t is None:
            raise AppError(TRANSFER_NOT_FOUND, "Không có transfer này")
        return t

    def _incoming_offer(self, transfer_id: str) -> Transfer:
        t = self._get(transfer_id)
        if t.direction != INCOMING or t.status != OFFERED:
            raise AppError(INVALID_STATE, "Chỉ chấp nhận/từ chối tệp đến đang chờ")
        return t

    def _event(self, kind: str, data: dict) -> None:
        self._outbox.append((kind, data))

    def _flush(self) -> None:
        """Phát event ngoài lock trạng thái, giữ đúng thứ tự giữa các thread."""
        with self._flush_lock:
            with self._lock:
                events, self._outbox = self._outbox, []
            if self._emit_cb is None:
                return
            for kind, data in events:
                try:
                    self._emit_cb(kind, data)
                except Exception:
                    log.exception("File event callback failed")


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
