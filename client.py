"""Facade phía client mà http_bridge gọi (1a_api.md §5).

Đăng nhập (1b_protocol_spec.md §2): TCP/TLS LOGIN → LOGIN_OK (khoá phiên) → đóng TCP
→ ReliableUDP, gửi UDP_BIND trên stream 1 → UDP_BIND_OK → connected.

Callback của ReliableUDP chạy trên luồng dispatcher của transport nên chỉ đẩy việc vào
hàng đợi; luồng worker của client xử lý tuần tự. Mọi thay đổi được ghi vào EventLog để
JavaScript lấy qua GET /api/events.
"""
from __future__ import annotations

import base64
import binascii
import itertools
import json
import logging
import os
import queue
import shutil
import socket
import ssl
import struct
import tempfile
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field

from messaging import Messenger
from protocol import FILE_TYPES, AppError, CryptoContext, PacketType, decode_json, encode_json
from reliable_udp import ReliableUDP

log = logging.getLogger(__name__)

API_VERSION = "1.0"
SERVER_PEER = "server"          # peer_id của server trong ReliableUDP phía client
SESSION_STREAM = 1

FRAME_HEADER = struct.Struct("!I")
MAX_FRAME = 65536
LOGIN_TIMEOUT = 10.0
BIND_TIMEOUT = 10.0
LOGOUT_TIMEOUT = 3.0

EVENT_LOG_SIZE = 10000
MAX_EVENTS_PER_POLL = 100
UPLOAD_OFFER_TTL = 60.0
MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_FILENAME_BYTES = 255
MAX_USERNAME_LEN = 64
MAX_USER_LIST_PARTS = 1024

DISCONNECTED = "disconnected"
CONNECTING = "connecting"
CONNECTED = "connected"
DISCONNECTING = "disconnecting"


# ============================================================================
# TCP framing: [length uint32 big-endian][JSON UTF-8]
# ============================================================================

def send_frame(sock: socket.socket, message: dict) -> None:
    raw = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if not 1 <= len(raw) <= MAX_FRAME:
        raise AppError("PAYLOAD_TOO_LARGE", "Khung TCP vượt quá 65536 byte")
    sock.sendall(FRAME_HEADER.pack(len(raw)) + raw)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Server đóng kết nối TCP giữa chừng")
        buf += chunk
    return bytes(buf)


def recv_frame(sock: socket.socket) -> dict:
    (length,) = FRAME_HEADER.unpack(_recv_exact(sock, FRAME_HEADER.size))
    if not 1 <= length <= MAX_FRAME:
        raise AppError("INVALID_PACKET", "Độ dài khung TCP không hợp lệ")
    return decode_json(_recv_exact(sock, length))


def _b64(value, size: int) -> bytes:
    raw = base64.b64decode(value, validate=True)
    if len(raw) != size:
        raise ValueError("Sai độ dài khoá")
    return raw


def parse_login_ok(reply: dict) -> dict:
    """Kiểm tra LOGIN_OK; ERROR từ server → AppError với mã của server."""
    kind = reply.get("type")
    if kind == "ERROR":
        raise AppError(str(reply.get("code") or "LOGIN_FAILED"),
                       str(reply.get("message") or "Đăng nhập thất bại"))
    if kind != "LOGIN_OK":
        raise AppError("INVALID_PACKET", "Phản hồi đăng nhập không hợp lệ")
    try:
        user_id, session_id, udp_port = reply["user_id"], reply["session_id"], reply["udp_port"]
        if not isinstance(user_id, str) or not 1 <= len(user_id) <= 32:
            raise ValueError("user_id")
        for value, hi in ((session_id, 2**64 - 1), (udp_port, 65535)):
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= hi:
                raise ValueError("session_id/udp_port")
        return {"user_id": user_id, "session_id": session_id, "udp_port": udp_port,
                "c2s_key": _b64(reply["c2s_key"], 32), "s2c_key": _b64(reply["s2c_key"], 32),
                "c2s_nonce_prefix": _b64(reply["c2s_nonce_prefix"], 4),
                "s2c_nonce_prefix": _b64(reply["s2c_nonce_prefix"], 4)}
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise AppError("INVALID_PACKET", "LOGIN_OK thiếu hoặc sai trường") from exc


def clean_filename(name) -> str:
    """Chỉ giữ basename; từ chối tên rỗng, có ký tự điều khiển hoặc quá 255 byte."""
    if not isinstance(name, str):
        raise AppError("INVALID_INPUT", "filename phải là chuỗi")
    name = os.path.basename(name.replace("\\", "/")).strip()
    if name in ("", ".", "..") or not name.isprintable():
        raise AppError("INVALID_INPUT", "Tên tệp không hợp lệ")
    if len(name.encode("utf-8", "surrogatepass")) > MAX_FILENAME_BYTES:
        raise AppError("INVALID_INPUT", "Tên tệp vượt quá 255 byte UTF-8")
    return name


# ============================================================================
# Hàng đợi sự kiện cho JavaScript
# ============================================================================

class CursorExpired(AppError):
    def __init__(self, current_cursor: int):
        super().__init__("EVENT_CURSOR_EXPIRED", "Cursor quá cũ, có thể đã mất sự kiện")
        self.current_cursor = current_cursor


class EventLog:
    """event_id tăng đơn điệu suốt vòng đời tiến trình, không reset khi logout/login."""

    def __init__(self, maxlen: int = EVENT_LOG_SIZE):
        self._events: deque = deque(maxlen=maxlen)
        self._last_id = 0
        self._cond = threading.Condition()

    def emit(self, type_: str, data: dict) -> int:
        with self._cond:
            self._last_id += 1
            self._events.append({"event_id": self._last_id, "type": type_, "data": data})
            self._cond.notify_all()
            return self._last_id

    def get(self, after: int, limit: int = MAX_EVENTS_PER_POLL, timeout: float = 0.0) -> dict:
        """Sự kiện có event_id > after. timeout > 0 thì chờ (long-poll) tới khi có sự kiện."""
        deadline = time.monotonic() + timeout
        with self._cond:
            while True:
                oldest = self._events[0]["event_id"] if self._events else self._last_id + 1
                # after lớn hơn id cuối: bridge đã khởi động lại; nhỏ hơn oldest-1: đã mất sự kiện.
                if after > self._last_id or after < oldest - 1:
                    raise CursorExpired(self._last_id)
                remaining = deadline - time.monotonic()
                if after < self._last_id or remaining <= 0:
                    break
                self._cond.wait(remaining)
            start = after + 1 - oldest   # event_id liên tiếp nên tính thẳng vị trí
            events = list(itertools.islice(self._events, start, start + limit))
        return {"events": events, "next_cursor": events[-1]["event_id"] if events else after}


# ============================================================================
# Client
# ============================================================================

@dataclass
class _Session:
    gen: int
    user: dict
    transport: ReliableUDP
    bound: threading.Event = field(default_factory=threading.Event)
    bind_error: str | None = None


@dataclass
class _Upload:
    """Offer gửi tệp đang chờ trình duyệt upload nội dung (chưa ra mạng)."""
    transfer_id: str
    to: str
    filename: str
    size: int
    created: float
    uploading: bool = False

    def to_dict(self) -> dict:
        return {"transfer_id": self.transfer_id, "direction": "outgoing", "peer_id": self.to,
                "filename": self.filename, "size": self.size, "status": "awaiting_upload",
                "bytes_done": 0, "progress": 0, "error_code": None}


class _Cancelled(Exception):
    pass


class ChatClient:
    def __init__(self, server_host: str, tcp_port: int = 9000, *, ca_file: str | None = None,
                 server_hostname: str | None = None):
        self.server_host = server_host
        self.tcp_port = tcp_port
        self.ca_file = ca_file                       # certs/ca.crt do tools/gen_cert.py sinh
        self.server_hostname = server_hostname or server_host

        self.events = EventLog()
        self.messaging = Messenger(self)
        self.files = None                            # FileTransferManager, gắn bằng attach_file_service

        self._lock = threading.RLock()
        self._state = DISCONNECTED
        self._user: dict | None = None
        self._last_error: dict | None = None
        self._session: _Session | None = None
        self._gen = 0                                # tăng mỗi phiên; sự kiện của phiên cũ bị bỏ
        self._cancel = threading.Event()
        self._tls_sock: socket.socket | None = None

        self._users_revision: int | None = None
        self._users: list[dict] = []
        self._parts_revision: int | None = None
        self._parts_count = 0
        self._parts: dict[int, list] = {}

        self._deliveries: dict[str, object] = {}     # delivery_id → callback(error_code | None)
        self._deliveries_lock = threading.Lock()

        self._uploads: dict[str, _Upload] = {}
        self._upload_dir = tempfile.mkdtemp(prefix="cc-upload-")

        self._inbox: queue.Queue = queue.Queue()
        threading.Thread(target=self._worker_loop, name="client-worker", daemon=True).start()

    # ---- facade: phiên ------------------------------------------------------

    def login(self, username: str, password: str) -> None:
        """Bắt đầu đăng nhập nền; kết quả báo qua sự kiện connection_changed / error."""
        if (not isinstance(username, str) or not 1 <= len(username) <= MAX_USERNAME_LEN
                or not username.isprintable()):
            raise AppError("INVALID_INPUT", "username không hợp lệ")
        if not isinstance(password, str) or not password:
            raise AppError("INVALID_INPUT", "password không hợp lệ")
        with self._lock:
            if self._state != DISCONNECTED:
                raise AppError("INVALID_STATE", "Đang đăng nhập hoặc đã kết nối")
            self._gen += 1
            gen = self._gen
            self._cancel.clear()
            self._last_error = None
            self._set_state(CONNECTING)
        threading.Thread(target=self._login_worker, args=(gen, username, password),
                         name="client-login", daemon=True).start()

    def logout(self) -> str:
        """Trả trạng thái sau khi gọi: 'disconnected' (đã ngắt sẵn) hoặc 'disconnecting'."""
        with self._lock:
            state = self._state
            if state in (DISCONNECTED, DISCONNECTING):
                return state
            gen, session = self._gen, self._session
            self._set_state(DISCONNECTING)
            if state == CONNECTING:
                # Luồng login thấy cờ huỷ sẽ tự dọn; đánh thức nó nếu đang chờ mạng.
                self._cancel.set()
                if self._tls_sock is not None:
                    try:
                        self._tls_sock.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                if session is not None:
                    session.bind_error = "CANCELLED"
                    session.bound.set()
                return DISCONNECTING
        threading.Thread(target=self._logout_worker, args=(gen, session),
                         name="client-logout", daemon=True).start()
        return DISCONNECTING

    def close(self) -> None:
        """Gọi khi tắt bridge."""
        if self.logout() == DISCONNECTING:
            deadline = time.monotonic() + LOGOUT_TIMEOUT + 1
            while self._state != DISCONNECTED and time.monotonic() < deadline:
                time.sleep(0.05)
        if self.files is not None:
            self.files.close()
        shutil.rmtree(self._upload_dir, ignore_errors=True)

    def get_status(self) -> dict:
        with self._lock:
            return {"state": self._state, "user": dict(self._user) if self._user else None,
                    "last_error": dict(self._last_error) if self._last_error else None}

    def list_users(self) -> dict:
        with self._lock:
            self.require_connected()
            return {"revision": self._users_revision, "users": [dict(u) for u in self._users]}

    def send_message(self, to: str | None, text: str) -> str:
        return self.messaging.send_message(to, text)

    def get_events(self, after_event_id: int, limit: int = MAX_EVENTS_PER_POLL,
                   timeout: float = 0.0) -> dict:
        return self.events.get(after_event_id, limit, timeout)

    # ---- facade: tệp ----------------------------------------------------------
    # Bản ghi awaiting_upload do client giữ; sau khi offer ra mạng thì file module quản lý.

    def attach_file_service(self, service) -> None:
        """Gắn FileTransferManager của file_transfer.py (người 4)."""
        self.files = service

    def create_upload(self, to: str, filename: str, size: int) -> str:
        user = self.require_connected()
        self._require_files()
        if not isinstance(to, str) or not to:
            raise AppError("INVALID_INPUT", "V1 chỉ gửi tệp riêng: cần 'to'")
        if to == user["user_id"]:
            raise AppError("INVALID_INPUT", "Không thể gửi tệp cho chính mình")
        if self.is_online(to) is False:
            raise AppError("USER_OFFLINE", "Người nhận không trực tuyến")
        name = clean_filename(filename)
        if isinstance(size, bool) or not isinstance(size, int) or size < 0:
            raise AppError("INVALID_INPUT", "size phải là số nguyên ≥ 0")
        if size > MAX_FILE_SIZE:
            raise AppError("FILE_TOO_LARGE", "Tệp vượt quá 100 MiB")
        transfer_id = str(uuid.uuid4())
        with self._lock:
            self._purge_expired_uploads()
            self._uploads[transfer_id] = _Upload(transfer_id, to, name, size, time.monotonic())
        return transfer_id

    def begin_upload(self, transfer_id: str, content_length: int) -> str:
        """Bridge gọi trước khi đọc body PUT; trả đường dẫn tệp tạm để ghi vào."""
        self._require_files()
        with self._lock:
            self._purge_expired_uploads()
            up = self._uploads.get(transfer_id)
            if up is None:
                raise AppError("TRANSFER_NOT_FOUND", "Không có offer này hoặc đã hết hạn")
            if up.uploading:
                raise AppError("INVALID_STATE", "Offer không còn ở trạng thái awaiting_upload")
            if content_length != up.size:
                raise AppError("INVALID_INPUT", "Content-Length khác size đã khai báo")
            up.uploading = True
        return os.path.join(self._upload_dir, transfer_id)

    def submit_uploaded_file(self, transfer_id: str, temp_path: str,
                             sha256: str | None = None) -> None:
        """Đã nhận đủ nội dung → giao cho file module gửi FILE_OFFER ra mạng."""
        with self._lock:
            up = self._uploads.get(transfer_id)
            if up is None or not up.uploading:
                raise AppError("INVALID_STATE", "Upload không hợp lệ")
        self.require_connected()
        # Tệp tạm đặt tên theo transfer_id nên phải truyền tên gốc; file module xoá
        # tệp tạm khi transfer kết thúc (delete_source).
        self._require_files().offer_file(up.to, temp_path, transfer_id, filename=up.filename,
                                         sha256=sha256, delete_source=True)
        with self._lock:
            self._uploads.pop(transfer_id, None)

    def abort_upload(self, transfer_id: str, error_code: str) -> None:
        """Upload lỗi: dọn tệp tạm, báo failed. Gọi nhiều lần không sao."""
        with self._lock:
            up = self._uploads.pop(transfer_id, None)
        if up is None:
            return
        try:
            os.remove(os.path.join(self._upload_dir, transfer_id))
        except OSError:
            pass
        self.emit("file_status", {"transfer_id": transfer_id, "direction": "outgoing",
                                  "status": "failed", "error_code": error_code})

    def accept_transfer(self, transfer_id: str) -> None:
        self.require_connected()
        self._require_files().accept_transfer(transfer_id)

    def reject_transfer(self, transfer_id: str, reason: str) -> None:
        self.require_connected()
        self._require_files().reject_transfer(transfer_id, reason)

    def list_transfers(self) -> list[dict]:
        with self._lock:
            self._purge_expired_uploads()
            local = [up.to_dict() for up in self._uploads.values()]
        return local + (list(self.files.list_transfers()) if self.files else [])

    def get_download_path(self, transfer_id: str) -> str:
        """Chưa nhận xong → AppError INVALID_STATE (409), không có → TRANSFER_NOT_FOUND (404)."""
        return self._require_files().get_download_path(transfer_id)

    # ---- dùng bởi messaging.py / file_transfer.py ---------------------------

    def require_connected(self) -> dict:
        with self._lock:
            if self._state != CONNECTED or self._user is None:
                raise AppError("NOT_AUTHENTICATED", "Chưa đăng nhập")
            return dict(self._user)

    def is_online(self, user_id: str) -> bool | None:
        """None nếu chưa có danh sách online."""
        with self._lock:
            if self._users_revision is None:
                return None
            return any(u["user_id"] == user_id for u in self._users)

    def send_reliable(self, stream_id: int, packet_type: int, payload: bytes,
                      on_result=None) -> str:
        """Gửi qua ReliableUDP; on_result(error_code | None) chạy trên luồng worker."""
        with self._lock:
            if self._state != CONNECTED or self._session is None:
                raise AppError("NOT_AUTHENTICATED", "Chưa đăng nhập")
            session = self._session
        return self._send(session, stream_id, packet_type, payload, on_result)

    def allocate_stream(self) -> int:
        with self._lock:
            if self._session is None:
                raise AppError("NOT_AUTHENTICATED", "Chưa đăng nhập")
            return self._session.transport.allocate_stream(SERVER_PEER)

    def close_stream(self, stream_id: int, reason: str) -> None:
        """Đóng luồng tệp đã xong; phiên đã đóng → AppError (file module tự bỏ qua)."""
        with self._lock:
            if self._session is None:
                raise AppError("NOT_AUTHENTICATED", "Chưa đăng nhập")
            transport = self._session.transport
        transport.close_stream(SERVER_PEER, stream_id, reason)

    def emit(self, type_: str, data: dict) -> None:
        self.events.emit(type_, data)

    # ---- đăng nhập / đăng xuất (luồng nền) ----------------------------------

    def _login_worker(self, gen: int, username: str, password: str) -> None:
        try:
            creds = parse_login_ok(self._tls_login(username, password))
            if self._cancel.is_set():
                raise _Cancelled
            self._open_udp(gen, username, creds)
            with self._lock:
                if self._cancel.is_set() or gen != self._gen or self._session is None:
                    raise _Cancelled
                self._user = dict(self._session.user)
                self._set_state(CONNECTED)
        except _Cancelled:
            self._finish(gen, None)
        except AppError as e:
            self._finish(gen, e.code, e.message)
        except OSError as e:   # gồm cả timeout, ssl.SSLError, lỗi chứng chỉ
            if self._cancel.is_set():
                self._finish(gen, None)
            else:
                self._finish(gen, "SERVER_UNAVAILABLE", f"Không kết nối được tới server: {e}")
        except Exception:
            log.exception("Lỗi khi đăng nhập")
            self._finish(gen, "INTERNAL", "Lỗi nội bộ khi đăng nhập")

    def _tls_login(self, username: str, password: str) -> dict:
        # Luôn xác minh chứng chỉ (spec cấm tắt); ca_file=None thì dùng CA hệ thống.
        if self.ca_file and not os.path.isfile(self.ca_file):
            raise AppError("CA_NOT_FOUND", f"Không có chứng chỉ CA {self.ca_file} "
                                           "(chạy python tools/gen_cert.py hoặc chép ca.crt từ máy server)")
        context = ssl.create_default_context(cafile=self.ca_file)
        raw = socket.create_connection((self.server_host, self.tcp_port), timeout=LOGIN_TIMEOUT)
        try:
            tls = context.wrap_socket(raw, server_hostname=self.server_hostname)
        except BaseException:
            raw.close()
            raise
        with tls:
            with self._lock:
                self._tls_sock = tls
            try:
                send_frame(tls, {"type": "LOGIN", "username": username, "password": password})
                return recv_frame(tls)
            finally:
                with self._lock:
                    self._tls_sock = None

    def _open_udp(self, gen: int, username: str, creds: dict) -> None:
        # Dùng IP đã phân giải: ReliableUDP so địa chỉ nguồn với đúng tuple này,
        # "localhost" sẽ không khớp ("127.0.0.1", port) của recvfrom.
        server_addr = socket.getaddrinfo(self.server_host, creds["udp_port"],
                                         socket.AF_INET, socket.SOCK_DGRAM)[0][4]
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            transport = ReliableUDP(sock, role="client")
        except BaseException:
            sock.close()
            raise
        session = _Session(gen, {"user_id": creds["user_id"], "username": username}, transport)
        try:
            transport.on_payload(lambda *a: self._inbox.put((gen, "payload", a)))
            transport.on_delivery(lambda *a: self._inbox.put((gen, "delivery", a)))
            transport.on_failure(lambda *a: self._inbox.put((gen, "failure", a)))
            transport.on_peer_closed(lambda *a: self._inbox.put((gen, "peer_closed", a)))
            transport.register_peer(SERVER_PEER, creds["session_id"], server_addr,
                                    CryptoContext(creds["c2s_key"], creds["c2s_nonce_prefix"]),
                                    CryptoContext(creds["s2c_key"], creds["s2c_nonce_prefix"]))
            with self._lock:
                if self._cancel.is_set() or gen != self._gen:
                    raise _Cancelled
                self._session = session          # từ đây _finish chịu trách nhiệm đóng
        except BaseException:
            transport.close()
            raise

        transport.start()
        self._send(session, SESSION_STREAM, PacketType.UDP_BIND, encode_json({}))
        if not session.bound.wait(BIND_TIMEOUT):
            raise AppError("SERVER_UNAVAILABLE", "Server không trả UDP_BIND_OK")
        if session.bind_error == "CANCELLED":
            raise _Cancelled
        if session.bind_error:
            raise AppError(session.bind_error, "Bind UDP thất bại")
        transport.activate_peer(SERVER_PEER)

    def _logout_worker(self, gen: int, session: _Session | None) -> None:
        if session is not None:
            done = threading.Event()
            try:
                self._send(session, SESSION_STREAM, PacketType.LOGOUT, encode_json({}),
                           lambda error: done.set())
                done.wait(LOGOUT_TIMEOUT)        # best effort
            except AppError:
                pass
        self._finish(gen, None)

    def _finish(self, gen: int, error_code: str | None, message: str | None = None) -> None:
        """Kết thúc phiên `gen`: về disconnected, dọn transport. Bỏ qua nếu phiên đã đổi."""
        with self._lock:
            if gen != self._gen or self._state == DISCONNECTED:
                return
            session, self._session = self._session, None
            self._gen += 1
            self._user = None
            self._users_revision, self._users = None, []
            self._parts_revision, self._parts = None, {}
            uploads, self._uploads = self._uploads, {}
            self._last_error = {"code": error_code, "message": message} if error_code else None
            self._set_state(DISCONNECTED, error_code)
        if error_code:
            self.emit("error", {"code": error_code, "message": message, "reference_id": None})

        with self._deliveries_lock:
            pending, self._deliveries = list(self._deliveries.values()), {}
        for callback in pending:
            self._run_callback(callback, error_code or "PEER_CLOSED")
        self.messaging.reset()
        if self.files is not None:
            try:
                self.files.handle_disconnect(error_code or "PEER_CLOSED")
            except Exception:
                log.exception("file_transfer.handle_disconnect lỗi")
        for transfer_id in uploads:
            try:
                os.remove(os.path.join(self._upload_dir, transfer_id))
            except OSError:
                pass
        if session is not None:
            session.transport.close()

    # ---- xử lý sự kiện transport (luồng worker) -----------------------------

    def _worker_loop(self) -> None:
        while True:
            gen, kind, args = self._inbox.get()
            try:
                if kind == "delivery":
                    self._resolve_delivery(args[0], None)
                elif kind == "failure":
                    self._resolve_delivery(args[0], args[1])
                else:
                    with self._lock:
                        session = self._session if self._session and self._session.gen == gen else None
                    if session is None:
                        continue                 # sự kiện của phiên đã đóng
                    if kind == "payload":
                        self._handle_payload(session, *args)
                    elif kind == "peer_closed":
                        self._on_peer_closed(session, args[1])
            except Exception:
                log.exception("Lỗi xử lý sự kiện transport %s", kind)

    def _handle_payload(self, session: _Session, peer_id: str, stream_id: int,
                        packet_type: int, payload: bytes) -> None:
        kind = PacketType(packet_type)
        # FILE_* và ERROR trên luồng tệp (>= 3) thuộc file module.
        if stream_id >= 3 and (kind in FILE_TYPES or kind == PacketType.ERROR):
            if self.files is not None:
                self.files.handle_packet(peer_id, stream_id, packet_type, payload)
            return
        try:
            data = decode_json(payload)
        except AppError:
            log.warning("Bỏ gói %s có JSON không hợp lệ", kind.name)
            return
        if kind == PacketType.UDP_BIND_OK:
            session.bound.set()
        elif kind == PacketType.USER_LIST:
            self._on_user_list(data)
        elif kind == PacketType.CHAT:
            self.messaging.handle_message(peer_id, data)
        elif kind == PacketType.CHAT_STATUS:
            self.messaging.handle_status(data)
        elif kind == PacketType.ERROR:
            self._on_error_packet(data)
        elif kind == PacketType.LOGOUT:
            self._finish(session.gen, "SESSION_CLOSED", "Server đã đóng phiên")
        else:
            log.debug("Bỏ qua gói %s", kind.name)

    def _on_peer_closed(self, session: _Session, reason: str) -> None:
        if not session.bound.is_set():
            session.bind_error = reason          # đang bind: để luồng login báo lỗi
            session.bound.set()
            return
        with self._lock:
            leaving = self._state == DISCONNECTING
        if leaving:
            self._finish(session.gen, None)
        else:
            self._finish(session.gen, reason, "Mất kết nối tới server")

    def _on_user_list(self, data: dict) -> None:
        """USER_LIST chia trang: chỉ thay danh sách khi đủ mọi phần cùng revision."""
        try:
            revision, index, count, users = (data["revision"], data["part_index"],
                                             data["part_count"], data["users"])
            if any(isinstance(v, bool) or not isinstance(v, int) for v in (revision, index, count)):
                raise ValueError
            if not 1 <= count <= MAX_USER_LIST_PARTS or not 0 <= index < count:
                raise ValueError
            if not isinstance(users, list):
                raise ValueError
        except (KeyError, ValueError):
            log.warning("Bỏ USER_LIST không hợp lệ")
            return
        with self._lock:
            if self._users_revision is not None and revision <= self._users_revision:
                return
            if self._parts_revision is not None and revision < self._parts_revision:
                return
            if revision != self._parts_revision:
                self._parts_revision, self._parts_count, self._parts = revision, count, {}
            if count != self._parts_count:
                return
            self._parts[index] = users
            if len(self._parts) < count:
                return
            merged = [{"user_id": u["user_id"], "username": u["username"]}
                      for i in range(count) for u in self._parts[i]
                      if isinstance(u, dict) and isinstance(u.get("user_id"), str)
                      and isinstance(u.get("username"), str)]
            self._users_revision, self._users = revision, merged
            self._parts_revision, self._parts = None, {}
        self.emit("users_updated", {"revision": revision, "users": [dict(u) for u in merged]})

    def _on_error_packet(self, data: dict) -> None:
        reference_id = data.get("reference_id")
        error = {"code": str(data.get("code") or "UNKNOWN"),
                 "message": str(data.get("message") or ""),
                 "reference_id": reference_id if isinstance(reference_id, str) else None}
        self.messaging.handle_error(error)
        self.emit("error", error)

    # ---- tiện ích -------------------------------------------------------------

    def _send(self, session: _Session, stream_id: int, packet_type: int, payload: bytes,
              on_result=None) -> str:
        # Giữ khoá suốt send + đăng ký để ACK đến rất nhanh vẫn tìm thấy callback.
        with self._deliveries_lock:
            delivery_id = session.transport.send(SERVER_PEER, stream_id, packet_type, payload)
            if on_result is not None:
                self._deliveries[delivery_id] = on_result
        return delivery_id

    def _resolve_delivery(self, delivery_id: str, error_code: str | None) -> None:
        with self._deliveries_lock:
            callback = self._deliveries.pop(delivery_id, None)
        if callback is not None:
            self._run_callback(callback, error_code)

    @staticmethod
    def _run_callback(callback, error_code) -> None:
        try:
            callback(error_code)
        except Exception:
            log.exception("Callback kết quả gửi lỗi")

    def _require_files(self):
        if self.files is None:
            raise AppError("NOT_IMPLEMENTED", "file_transfer.py chưa sẵn sàng")
        return self.files

    def _purge_expired_uploads(self) -> None:
        """Gọi khi đang giữ _lock. Offer chưa upload quá 60 giây thì xoá."""
        now = time.monotonic()
        for tid in [t for t, up in self._uploads.items()
                    if not up.uploading and now - up.created > UPLOAD_OFFER_TTL]:
            del self._uploads[tid]

    def _set_state(self, state: str, error_code: str | None = None) -> None:
        """Gọi khi đang giữ _lock."""
        self._state = state
        self.emit("connection_changed", {"state": state,
                                         "user": dict(self._user) if self._user else None,
                                         "error_code": error_code})
