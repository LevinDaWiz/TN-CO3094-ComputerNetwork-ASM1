"""Server cộng tác (Người 2): đăng nhập TCP/TLS cổng 9000 + phiên, chat, tệp qua UDP 9001.

Các phần chính (theo thứ tự trong file):

* ``CollabServer``          đăng nhập TCP/TLS (1b mục 2)
* ``build_user_list_parts`` USER_LIST phân trang (1b mục 8)
* ``ChatRouter``            kiểm tra và chọn người nhận chat (1b mục 6)
* ``FileRelay``             chuyển tiếp tệp giữa hai phiên (1b mục 7)
* ``UdpService``            nối tất cả với transport UDP (``server_udp.ServerUDP``)
* ``main``                  dòng lệnh: ``python server.py --help``
"""

import argparse
import base64
import collections
import dataclasses
import datetime
import json
import logging
import os
import socket
import ssl
import sys
import threading
import time
import uuid

from framing import (MAX_FRAME_LEN, INVALID_PACKET, PAYLOAD_TOO_LARGE,  # noqa: F401
                     ConnectionClosed, recv_frame, send_frame)
from protocol import (MAX_PLAINTEXT, AppError, CryptoContext, Flags, Header,  # của nhóm
                      PacketType, decode_json, decode_packet, encode_ack, encode_json,
                      encode_packet, peek_header)
from server_udp import ServerUDP
# Dùng chung luật kiểm tra offer với client truyền tệp (Người 4), chỉ import, không sửa.
from file_transfer import is_file_packet, validate_offer

log = logging.getLogger("server")

# ---------------------------------------------------------------------------
# Hằng số
# ---------------------------------------------------------------------------

DEFAULT_HOST = "0.0.0.0"
DEFAULT_TCP_PORT = 9000
DEFAULT_UDP_PORT = 9001

DEFAULT_LOGIN_TIMEOUT = 10.0         # giây; client treo không giữ thread mãi
DEFAULT_MAX_LOGIN_THREADS = 64       # số kết nối đăng nhập xử lý đồng thời

# Giới hạn trường trong LOGIN (tính theo byte UTF-8).
MAX_USERNAME_BYTES = 64
MAX_PASSWORD_BYTES = 1024

# Mã lỗi đăng nhập (xem 1b_protocol_spec.md mục 9); INVALID_PACKET và
# PAYLOAD_TOO_LARGE lấy từ framing.py.
INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
ALREADY_LOGGED_IN = "ALREADY_LOGGED_IN"


def error_message(code: str, message: str, reference_id=None) -> dict:
    """Frame ERROR trên TCP (dict, có ``type``), 1b mục 9. Bản UDP: ``error_payload``."""
    return {"type": "ERROR", "code": code, "message": message, "reference_id": reference_id}


def _b64(data: bytes) -> str:
    """Khóa/nonce prefix (bytes) -> chuỗi base64 cho LOGIN_OK."""
    return base64.b64encode(data).decode("ascii")


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class CollabServer:
    """Server đăng nhập TCP/TLS, mỗi kết nối một thread (1b mục 2).

    Mỗi kết nối chỉ dùng để đăng nhập: client gửi đúng một frame LOGIN (framing ở
    ``framing.py``), server trả LOGIN_OK hoặc ERROR rồi đóng TCP; phiên sau đó đi
    qua UDP (``UdpService``, chạy riêng, xem ``main``). Mọi lỗi mạng chỉ làm hỏng
    kết nối đó, không làm dừng server.

    ``session_backend`` là đối tượng (thường là ``sessions.SessionManager``) cung cấp:

    * ``authenticate(username, password) -> Session``; raise ``AppError``
      với ``INVALID_CREDENTIALS``/``ALREADY_LOGGED_IN`` khi thất bại.
      Session có các trường ``session_id, user_id, c2s_key, s2c_key,
      c2s_nonce_prefix, s2c_nonce_prefix`` (khóa dạng bytes).
    * ``remove_session(session_id)``: hủy phiên nếu gửi LOGIN_OK thất bại.

    ``ssl_context=None`` là không TLS (dùng trong test); ``main`` bật TLS mặc định.
    """

    def __init__(self, session_backend, host: str = DEFAULT_HOST,
                 tcp_port: int = DEFAULT_TCP_PORT, udp_port: int = DEFAULT_UDP_PORT,
                 ssl_context: ssl.SSLContext = None,
                 login_timeout: float = DEFAULT_LOGIN_TIMEOUT,
                 max_login_threads: int = DEFAULT_MAX_LOGIN_THREADS):
        self.sessions = session_backend
        self.host = host
        self.tcp_port = tcp_port
        self.udp_port = udp_port
        self.ssl_context = ssl_context
        self.login_timeout = login_timeout
        # Giới hạn số thread đăng nhập để kẻ xấu không mở vô hạn kết nối.
        self._login_slots = threading.BoundedSemaphore(max_login_threads)
        self._stop_event = threading.Event()
        self._listener = None
        self._accept_thread = None

    # ----- vòng đời --------------------------------------------------------

    def start(self) -> None:
        """Mở socket lắng nghe TCP và chạy thread accept ở nền."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if os.name != "nt":
            # Trên Windows SO_REUSEADDR cho phép tiến trình khác chiếm cổng,
            # nên chỉ bật trên Linux/macOS để khởi động lại nhanh.
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((self.host, self.tcp_port))
        listener.listen(128)
        # Timeout ngắn để vòng accept kiểm tra được cờ dừng định kỳ.
        listener.settimeout(0.5)
        self._listener = listener
        self.tcp_port = listener.getsockname()[1]   # cập nhật nếu dùng cổng 0
        self._stop_event.clear()
        self._accept_thread = threading.Thread(
            target=self._accept_loop, name="tcp-accept", daemon=True)
        self._accept_thread.start()
        log.info("TCP login đang lắng nghe %s:%d (TLS %s), UDP port công bố %d",
                 self.host, self.tcp_port, "bật" if self.ssl_context else "tắt",
                 self.udp_port)

    def stop(self) -> None:
        """Dừng nhận kết nối mới. Các thread đăng nhập đang chạy tự kết thúc."""
        self._stop_event.set()
        if self._accept_thread is not None:
            self._accept_thread.join(timeout=5)
        if self._listener is not None:
            self._listener.close()
            self._listener = None
        log.info("Server đã dừng")

    def serve_forever(self) -> None:
        """Chạy đến khi nhấn Ctrl+C."""
        self.start()
        try:
            while not self._stop_event.wait(1.0):
                pass
        except KeyboardInterrupt:
            log.info("Nhận Ctrl+C, đang dừng server...")
        finally:
            self.stop()

    # ----- accept ----------------------------------------------------------

    def _accept_loop(self) -> None:
        """Nhận kết nối và giao cho thread riêng; không bao giờ thoát vì lỗi."""
        while not self._stop_event.is_set():
            try:
                conn, addr = self._listener.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop_event.is_set():
                    break
                # Ví dụ hết file descriptor: ghi log, chờ một chút rồi thử lại.
                log.warning("Lỗi accept: %s", exc)
                time.sleep(0.1)
                continue

            if not self._login_slots.acquire(blocking=False):
                log.warning("Quá nhiều kết nối đăng nhập, từ chối %s:%d", *addr)
                self._close_quietly(conn)
                continue
            try:
                threading.Thread(target=self._handle_connection, args=(conn, addr),
                                 name=f"login-{addr[0]}:{addr[1]}", daemon=True).start()
            except RuntimeError as exc:   # không tạo được thread mới
                log.warning("Không tạo được thread cho %s:%d: %s", addr[0], addr[1], exc)
                self._login_slots.release()
                self._close_quietly(conn)

    # ----- xử lý một kết nối -----------------------------------------------

    def _handle_connection(self, conn: socket.socket, addr) -> None:
        """Thread xử lý một kết nối: (TLS handshake) → LOGIN → trả lời → đóng.

        Mọi ngoại lệ đều bị chặn ở đây để chỉ kết nối này hỏng.
        """
        peer = f"{addr[0]}:{addr[1]}"
        sock = conn
        try:
            conn.settimeout(self.login_timeout)
            if self.ssl_context is not None:
                # Handshake trong thread riêng để client chậm không chặn accept.
                sock = self.ssl_context.wrap_socket(
                    conn, server_side=True, do_handshake_on_connect=False)
                sock.do_handshake()
            self._process_login(sock, peer)
        except socket.timeout:
            log.info("[%s] Hết thời gian chờ đăng nhập", peer)
        except ConnectionClosed as exc:
            log.info("[%s] Client đóng kết nối giữa chừng (%s)", peer, exc)
        except ssl.SSLError as exc:
            log.info("[%s] Lỗi TLS: %s", peer, exc)
        except OSError as exc:   # ConnectionResetError, BrokenPipeError, ...
            log.info("[%s] Lỗi mạng: %s", peer, exc)
        except Exception:
            log.exception("[%s] Lỗi không mong đợi khi xử lý đăng nhập", peer)
        finally:
            self._close_gracefully(sock)
            self._login_slots.release()

    def _process_login(self, sock: socket.socket, peer: str) -> None:
        """Đọc frame LOGIN, xác thực và gửi LOGIN_OK hoặc ERROR.

        Log chỉ ghi username và mã lỗi; không ghi mật khẩu, khóa phiên hay nonce prefix.
        """
        try:
            msg = recv_frame(sock)
            username, password = self._parse_login(msg)
        except AppError as exc:
            log.info("[%s] Gói không hợp lệ: %s", peer, exc.code)
            send_frame(sock, error_message(exc.code, exc.message))
            return

        try:
            session = self.sessions.authenticate(username, password)
        except AppError as exc:
            log.info("[%s] Đăng nhập '%s' thất bại: %s", peer, username, exc.code)
            send_frame(sock, error_message(exc.code, exc.message))
            return

        reply = {
            "type": "LOGIN_OK",
            "user_id": session.user_id,
            "session_id": session.session_id,
            "udp_port": self.udp_port,
            "c2s_key": _b64(session.c2s_key),
            "s2c_key": _b64(session.s2c_key),
            "c2s_nonce_prefix": _b64(session.c2s_nonce_prefix),
            "s2c_nonce_prefix": _b64(session.s2c_nonce_prefix),
        }
        try:
            send_frame(sock, reply)
        except BaseException:
            # Client không nhận được khóa → hủy phiên ngay để có thể đăng nhập
            # lại, không phải chờ 15 giây hết hạn.
            self._remove_session_quietly(session.session_id)
            raise
        log.info("[%s] Đăng nhập thành công: %s (%s)", peer, username, session.user_id)

    @staticmethod
    def _parse_login(msg: dict):
        """Kiểm tra cấu trúc LOGIN; trả về (username, password).

        Sai type/thiếu trường -> ``INVALID_PACKET``; quá dài -> ``PAYLOAD_TOO_LARGE``.
        """
        if msg.get("type") != "LOGIN":
            raise AppError(INVALID_PACKET, "chỉ chấp nhận thông điệp LOGIN")
        username = msg.get("username")
        password = msg.get("password")
        if not isinstance(username, str) or not isinstance(password, str):
            raise AppError(INVALID_PACKET, "thiếu username/password dạng chuỗi")
        if (len(username.encode("utf-8")) > MAX_USERNAME_BYTES
                or len(password.encode("utf-8")) > MAX_PASSWORD_BYTES):
            raise AppError(PAYLOAD_TOO_LARGE, "username hoặc password quá dài")
        return username, password

    # ----- tiện ích đóng socket --------------------------------------------

    def _remove_session_quietly(self, session_id: int) -> None:
        """Hủy phiên khi gửi LOGIN_OK thất bại; lỗi chỉ ghi log."""
        try:
            self.sessions.remove_session(session_id)
        except Exception:
            log.exception("Không hủy được phiên sau khi gửi LOGIN_OK thất bại")

    @staticmethod
    def _close_gracefully(sock: socket.socket) -> None:
        """Đóng chiều gửi, bỏ dữ liệu client còn gửi dở rồi mới close.

        Nếu close khi bộ đệm nhận còn dữ liệu chưa đọc (ví dụ client gửi gộp
        nhiều frame hoặc gửi body quá dài), hệ điều hành gửi RST và client có
        thể mất luôn thông điệp ERROR vừa gửi. Vì vậy đọc bỏ một lượng giới hạn.
        """
        try:
            sock.shutdown(socket.SHUT_WR)
            sock.settimeout(1.0)
            drained = 0
            while drained < 4 * MAX_FRAME_LEN:
                chunk = sock.recv(8192)
                if not chunk:
                    break
                drained += len(chunk)
        except (OSError, ValueError):
            pass
        CollabServer._close_quietly(sock)

    @staticmethod
    def _close_quietly(sock: socket.socket) -> None:
        """Đóng socket, bỏ qua lỗi (socket có thể đã hỏng)."""
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Presence: USER_LIST phân trang (1b_protocol_spec.md mục 8)
# ---------------------------------------------------------------------------

def build_user_list_parts(revision: int, users: list, *,
                          max_bytes: int = MAX_PLAINTEXT) -> list:
    """Chia danh sách online thành các payload USER_LIST, mỗi phần <= ``max_bytes``.

    Mỗi phần là JSON ``{revision, part_index, part_count, users}`` đã serialize
    (bytes, sẵn sàng cho ``transport.send``). Giới hạn tính theo byte UTF-8 sau
    serialize, không theo số ký tự. Danh sách rỗng vẫn trả 1 phần ``users: []``
    để client biết không còn ai online.

    ``users`` thường lấy từ ``SessionManager.online_snapshot()`` cùng ``revision``.
    """
    # Lúc chia chưa biết part_count, nên đo bằng số "giữ chỗ" có nhiều chữ số nhất
    # có thể (len(users)); số thật luôn ít chữ số hơn hoặc bằng nên chỉ nhỏ đi.
    placeholder = max(1, len(users))

    def size(chunk):
        # Đo bằng json.dumps cùng quy ước với protocol.encode_json (compact, UTF-8);
        # encode_json tự raise khi > 1149 byte nên không dùng để đo thử được.
        obj = {"revision": revision, "part_index": placeholder,
               "part_count": placeholder, "users": chunk}
        return len(json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))

    chunks, current = [], []
    for user in users:
        if current and size(current + [user]) > max_bytes:
            chunks.append(current)
            current = []
        current.append(user)
        if size(current) > max_bytes:
            raise AppError(PAYLOAD_TOO_LARGE, "một user vượt giới hạn USER_LIST")
    chunks.append(current)

    return [encode_json({"revision": revision, "part_index": i,
                         "part_count": len(chunks), "users": chunk})
            for i, chunk in enumerate(chunks)]


# ---------------------------------------------------------------------------
# Định tuyến chat (1b_protocol_spec.md mục 6)
# ---------------------------------------------------------------------------

MAX_CHAT_TEXT_BYTES = 800
MAX_USER_ID_LEN = 32
DEDUPE_PER_SESSION = 4096        # số message_id nhớ cho mỗi phiên người gửi

USER_OFFLINE = "USER_OFFLINE"
NO_RECIPIENTS = "NO_RECIPIENTS"

STATUS_ACCEPTED = "accepted"
STATUS_DELIVERED = "delivered"
STATUS_FAILED = "failed"


def utc_timestamp() -> str:
    """Thời điểm hiện tại dạng ISO 8601 UTC, ví dụ ``2026-10-10T16:00:00Z``."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def chat_status(message_id: str, recipient_id, status: str, error_code=None) -> bytes:
    """Payload CHAT_STATUS ``{message_id, recipient_id, status, error_code}``."""
    return encode_json({"message_id": message_id, "recipient_id": recipient_id,
                        "status": status, "error_code": error_code})


def error_payload(code: str, message: str, reference_id=None) -> bytes:
    """Payload gói UDP ERROR (loại 14) ``{code, message, reference_id}`` dạng bytes."""
    return encode_json({"code": code, "message": message, "reference_id": reference_id})


def _is_uuid(value) -> bool:
    """Chuỗi UUID dạng chuẩn 36 ký tự (8-4-4-4-12)."""
    if not isinstance(value, str) or len(value) != 36:
        return False
    try:
        uuid.UUID(value)
    except ValueError:
        return False
    return True


def _is_user_id(value) -> bool:
    """user_id hợp lệ: ASCII in được, không khoảng trắng, 1..32 ký tự (1b mục 6)."""
    return (isinstance(value, str) and 1 <= len(value) <= MAX_USER_ID_LEN
            and value.isascii() and value.isprintable() and " " not in value)


@dataclasses.dataclass
class ChatDelivery:
    """Một bản tin cần gửi tới một người nhận (CHAT trên stream 2)."""
    session_id: int
    user_id: str
    payload: bytes


@dataclasses.dataclass
class ChatRoute:
    """Kết quả xử lý một gói CHAT từ người gửi.

    * ``deliveries``: tin cần gửi tới từng người nhận. Gửi thành công vào hàng
      đợi transport thì báo người gửi ``chat_status(..., "accepted")`` cho người
      nhận đó; ``on_delivery`` sau này báo ``"delivered"``.
    * ``statuses``: CHAT_STATUS ``failed`` gửi ngay cho người gửi.
    * ``error``: payload ERROR gửi cho người gửi (gói hỏng tới mức không có
      message_id hợp lệ để báo CHAT_STATUS).
    * ``duplicate``: message_id đã xử lý trong phiên này; không làm gì thêm.
    """
    message_id: str = None
    deliveries: list = dataclasses.field(default_factory=list)
    statuses: list = dataclasses.field(default_factory=list)
    error: bytes = None
    duplicate: bool = False


class ChatRouter:
    """Kiểm tra và chọn người nhận cho tin chat. Không làm I/O; an toàn đa luồng.

    ``session_backend`` cần ``get_session_by_user(user_id)`` và
    ``list_bound_sessions()`` (``sessions.SessionManager`` có sẵn).
    ``clock`` trả chuỗi ``sent_at`` (thay được trong test).
    """

    def __init__(self, session_backend, *, clock=utc_timestamp,
                 dedupe_limit: int = DEDUPE_PER_SESSION):
        self.sessions = session_backend
        self._clock = clock
        self._dedupe_limit = dedupe_limit
        self._seen = {}               # sender session_id -> OrderedDict[message_id]
        self._lock = threading.Lock()

    def route(self, sender, payload) -> ChatRoute:
        """Xử lý payload CHAT ``{message_id, to, text}`` của phiên ``sender``.

        ``from`` lấy từ phiên người gửi, không tin trường client tự khai báo.
        """
        if not isinstance(payload, dict) or not _is_uuid(payload.get("message_id")):
            return ChatRoute(error=error_payload(INVALID_PACKET, "message_id phải là UUID"))
        message_id = payload["message_id"]
        result = ChatRoute(message_id=message_id)

        # Chống trùng theo người gửi trong phiên: tin đã xử lý thì bỏ qua.
        if not self._remember(sender.session_id, message_id):
            result.duplicate = True
            return result

        to, text = payload.get("to"), payload.get("text")
        if to is not None and not _is_user_id(to):
            result.statuses.append(chat_status(message_id, None, STATUS_FAILED, INVALID_PACKET))
            return result
        if not isinstance(text, str) or not text:
            result.statuses.append(chat_status(message_id, to, STATUS_FAILED, INVALID_PACKET))
            return result
        if len(text.encode("utf-8")) > MAX_CHAT_TEXT_BYTES:
            result.statuses.append(chat_status(message_id, to, STATUS_FAILED, PAYLOAD_TOO_LARGE))
            return result

        if to is None:
            # Chat chung: mọi người khác đang online tại thời điểm server chấp nhận.
            recipients = [s for s in self.sessions.list_bound_sessions()
                          if s.session_id != sender.session_id]
            if not recipients:
                result.statuses.append(chat_status(message_id, None, STATUS_FAILED, NO_RECIPIENTS))
                return result
        else:
            # Chat riêng; to == người gửi cũng hợp lệ (gửi cho chính mình, như "ghi chú").
            target = self.sessions.get_session_by_user(to)
            if target is None or not target.bound:
                # Không phân biệt "không tồn tại" với "offline" để không lộ tài khoản.
                result.statuses.append(chat_status(message_id, to, STATUS_FAILED, USER_OFFLINE))
                return result
            recipients = [target]

        try:
            body = encode_json({"message_id": message_id, "from": sender.user_id, "to": to,
                                "text": text, "sent_at": self._clock()})
        except AppError as exc:
            # Ví dụ text toàn ký tự cần escape: <=800 byte nhưng JSON > 1149 byte.
            result.statuses.append(chat_status(message_id, to, STATUS_FAILED, exc.code))
            return result
        result.deliveries = [ChatDelivery(s.session_id, s.user_id, body) for s in recipients]
        return result

    def forget_session(self, session_id: int) -> None:
        """Xóa bộ nhớ chống trùng của phiên đã kết thúc (gắn vào on_session_removed)."""
        with self._lock:
            self._seen.pop(session_id, None)

    def _remember(self, session_id: int, message_id: str) -> bool:
        """Ghi nhận message_id; trả False nếu đã thấy trong phiên này."""
        with self._lock:
            seen = self._seen.setdefault(session_id, collections.OrderedDict())
            if message_id in seen:
                return False
            seen[message_id] = None
            if len(seen) > self._dedupe_limit:
                seen.popitem(last=False)   # quên tin cũ nhất, bộ nhớ có giới hạn
            return True


# ---------------------------------------------------------------------------
# Chuyển tiếp tệp (1b_protocol_spec.md mục 7)
# ---------------------------------------------------------------------------

RELAY_QUEUE_LIMIT = 4096      # gói chờ gửi tối đa mỗi luồng (~4 MiB chunk), vượt thì hủy tệp

_SENDER_KINDS = frozenset((PacketType.FILE_CHUNK, PacketType.FILE_END, PacketType.ERROR))
_RECEIVER_KINDS = frozenset((PacketType.FILE_ACCEPT, PacketType.FILE_REJECT,
                             PacketType.FILE_RESULT, PacketType.ERROR))
_FINAL_KINDS = frozenset((PacketType.FILE_REJECT, PacketType.FILE_RESULT, PacketType.ERROR))


@dataclasses.dataclass
class _FileLink:
    """Một chặng của transfer: ``other`` là chặng bên kia ``(session_id, stream_id)``."""
    other: tuple
    transfer_id: object
    is_sender: bool            # chặng này thuộc người gửi tệp


class FileRelay:
    """Chuyển tiếp FILE_* giữa hai phiên, không giữ cả tệp trong RAM.

    Mỗi transfer gồm hai chặng: ``(phiên gửi, luồng lẻ client mở)`` và
    ``(phiên nhận, luồng chẵn server cấp)``; seq hai chặng độc lập.

    ``find_recipient(user_id) -> session_id | None`` trả phiên đã sẵn sàng nhận.
    ``self._lock`` bảo vệ mọi bảng; ``transport.send`` chỉ xếp hàng nên được gọi
    khi đang giữ lock (transport không gọi ngược vào đây khi đang giữ lock của nó).
    """

    def __init__(self, transport, find_recipient, *, queue_limit: int = RELAY_QUEUE_LIMIT):
        self.transport = transport
        self._find_recipient = find_recipient
        self._queue_limit = queue_limit
        self._lock = threading.Lock()
        self._links = {}           # (sid, stream) -> _FileLink
        self._queues = {}          # (sid, stream) -> deque[(kind, payload, final)]
        self._sent = {}            # delivery_id -> ((sid, stream), final)

    # ----- vào từ UdpService ----------------------------------------------

    def handle_packet(self, sender, stream_id: int, kind: int, payload: bytes) -> None:
        """Gói FILE_* hoặc ERROR trên luồng >= 3 từ phiên ``sender``.

        Gói được chuyển nguyên payload sang chặng bên kia. Chặng người gửi chỉ được
        gửi CHUNK/END/ERROR, chặng người nhận chỉ ACCEPT/REJECT/RESULT/ERROR.
        Gói cuối (REJECT/RESULT/ERROR): xóa ánh xạ, đóng ngay chặng vừa nhận,
        chặng kia đóng khi gói cuối đã được ACK (``handle_delivery``).
        """
        leg = (sender.session_id, stream_id)
        with self._lock:
            link = self._links.get(leg)
            if link is None:
                if kind == PacketType.FILE_OFFER:
                    self._open_locked(sender, leg, payload)
                return                         # gói muộn của tệp đã xong: bỏ
            allowed = _SENDER_KINDS if link.is_sender else _RECEIVER_KINDS
            if kind not in allowed:
                log.debug("Bỏ gói tệp loại %s sai chiều từ %s", kind, sender.user_id)
                return
            other = link.other
            final = kind in _FINAL_KINDS
            if final:
                self._links.pop(leg, None)
                self._links.pop(other, None)
                self._close_leg_locked(leg, "TRANSFER_DONE")
            self._enqueue_locked(other, kind, payload, final)

    def handle_delivery(self, delivery_id: str) -> bool:
        """Gói relay đã được ACK. Trả False nếu delivery_id không thuộc relay."""
        with self._lock:
            record = self._sent.pop(delivery_id, None)
            if record is None:
                return False
            leg, final = record
            if final:
                self._close_leg_locked(leg, "TRANSFER_DONE")
            self._flush_all_locked()             # có chỗ trống: gửi tiếp hàng đợi
        return True

    def handle_failure(self, delivery_id: str, error_code: str) -> bool:
        """Gói relay không tới được (hết lượt truyền lại, peer đóng...)."""
        with self._lock:
            record = self._sent.pop(delivery_id, None)
            if record is None:
                return False
            leg, final = record
            if final:
                self._close_leg_locked(leg, error_code)
            elif leg in self._links:
                code = "DELIVERY_TIMEOUT" if error_code == "DELIVERY_TIMEOUT" else USER_OFFLINE
                self._abort_locked(leg, code, leg_alive=False)
            self._flush_all_locked()
        return True

    def handle_session_removed(self, session_id: int) -> None:
        """Phiên mất: hủy mọi transfer có chặng thuộc phiên đó, báo bên còn lại."""
        with self._lock:
            for leg in [leg for leg in self._links if leg[0] == session_id]:
                if leg in self._links:
                    self._abort_locked(leg, USER_OFFLINE, leg_alive=False)
            for leg in [leg for leg in self._queues if leg[0] == session_id]:
                self._queues.pop(leg, None)

    def active_links(self) -> int:
        """Số chặng đang được ánh xạ (dùng cho test/giám sát)."""
        with self._lock:
            return len(self._links)

    # ----- nội bộ (đang giữ lock) -----------------------------------------------

    def _open_locked(self, sender, leg, payload: bytes) -> None:
        """FILE_OFFER mới: kiểm tra, mở luồng chẵn cho người nhận, thêm ``from`` rồi chuyển.

        Offer hỏng -> ``FILE_RESULT failed/<mã>``; người nhận không sẵn sàng ->
        ``FILE_RESULT failed/USER_OFFLINE`` (gửi lại cho người gửi trên chính luồng offer).
        """
        try:
            offer = decode_json(payload)
        except AppError:
            offer = {}
        transfer_id = offer.get("transfer_id")

        def refuse(code):
            body = encode_json({"transfer_id": transfer_id if _is_uuid(transfer_id) else None,
                                "status": "failed", "error_code": code})
            self._enqueue_locked(leg, PacketType.FILE_RESULT, body, True)

        try:
            validate_offer(offer, require_from=False)   # cùng luật với client (Người 4)
        except AppError as exc:
            refuse(exc.code)
            return
        to = offer.get("to")
        if not _is_user_id(to):
            refuse(INVALID_PACKET)
            return
        target = self._find_recipient(to)
        if target is None:
            # Không phân biệt "không tồn tại" với "offline", giống chat riêng.
            refuse(USER_OFFLINE)
            return
        try:
            out_stream = self.transport.allocate_stream(str(target))    # chẵn từ 4
        except AppError as exc:
            refuse(USER_OFFLINE if exc.code == "INVALID_SESSION" else exc.code)
            return
        offer["from"] = sender.user_id                  # lấy từ phiên, không tin client
        try:
            body = encode_json(offer)
        except AppError as exc:
            refuse(exc.code)
            return
        out = (target, out_stream)
        self._links[leg] = _FileLink(out, transfer_id, True)
        self._links[out] = _FileLink(leg, transfer_id, False)
        self._enqueue_locked(out, PacketType.FILE_OFFER, body, False)

    def _enqueue_locked(self, leg, kind, payload: bytes, final: bool) -> None:
        """Xếp gói vào hàng đợi riêng của chặng rồi gửi ngay nếu được.

        Backpressure: transport báo ``QUEUE_FULL`` thì gói nằm lại hàng đợi, gửi tiếp
        khi có ACK. Hàng đợi vượt ``queue_limit`` thì hủy tệp với ``DELIVERY_TIMEOUT``
        (transport ACK ngay khi nhận nên không ghìm được người gửi; giới hạn hàng đợi
        là cách để không tích lũy cả tệp trong RAM, 1b mục 7).
        """
        queue = self._queues.setdefault(leg, collections.deque())
        if len(queue) >= self._queue_limit:
            # Bên nhận quá chậm: không tích lũy thêm, hủy tệp và báo cả hai bên.
            queue.clear()
            if leg in self._links:
                self._abort_locked(leg, "DELIVERY_TIMEOUT", leg_alive=True)
            return
        queue.append((kind, payload, final))
        self._flush_leg_locked(leg)

    def _flush_leg_locked(self, leg) -> None:
        """Gửi hàng đợi của chặng tới khi rỗng hoặc ``QUEUE_FULL``; chặng chết thì hủy tệp."""
        queue = self._queues.get(leg)
        dead = False
        while queue:
            kind, payload, final = queue[0]
            try:
                delivery_id = self.transport.send(str(leg[0]), leg[1], kind, payload)
            except AppError as exc:
                if exc.code == "QUEUE_FULL":
                    return                        # chờ ACK (handle_delivery) rồi gửi tiếp
                queue.clear()                     # peer/luồng đã đóng
                dead = True
                break
            queue.popleft()
            self._sent[delivery_id] = (leg, final)
        self._queues.pop(leg, None)
        if dead and leg in self._links:
            self._abort_locked(leg, USER_OFFLINE, leg_alive=False)

    def _flush_all_locked(self) -> None:
        for leg in list(self._queues):
            self._flush_leg_locked(leg)

    def _abort_locked(self, leg, code: str, *, leg_alive: bool) -> None:
        """Hủy transfer chứa ``leg``; báo bên kia (và chính ``leg`` nếu còn sống).

        Bảng báo lỗi đã chốt với Người 4 (khớp ``tests/fake_file_server.py``):
        bên được báo là người gửi -> ``FILE_RESULT failed/<code>``; là người nhận ->
        ``ERROR <code>`` với ``reference_id`` = transfer_id. Mất kết nối dùng
        ``USER_OFFLINE``.
        """
        link = self._links.pop(leg, None)
        if link is None:
            return
        self._links.pop(link.other, None)
        targets = [(link.other, not link.is_sender)]
        if leg_alive:
            targets.append((leg, link.is_sender))
        else:
            self._close_leg_locked(leg, code)
        for target, target_is_sender in targets:
            self._queues.pop(target, None)        # bỏ dữ liệu chưa gửi, chỉ gửi gói báo lỗi
            if target_is_sender:
                kind = PacketType.FILE_RESULT
                body = encode_json({"transfer_id": link.transfer_id, "status": "failed",
                                    "error_code": code})
            else:
                kind = PacketType.ERROR
                body = error_payload(code, "Truyền tệp thất bại", link.transfer_id)
            self._enqueue_locked(target, kind, body, True)

    def _close_leg_locked(self, leg, reason: str) -> None:
        """Bỏ hàng đợi và đóng luồng của chặng trên transport."""
        self._queues.pop(leg, None)
        try:
            self.transport.close_stream(str(leg[0]), leg[1], reason)
        except AppError:
            pass                                   # peer đã đóng


# ---------------------------------------------------------------------------
# Dịch vụ UDP 9001: UDP_BIND, USER_LIST, chat, tệp, heartbeat, LOGOUT
# ---------------------------------------------------------------------------

LOGOUT_TOMBSTONE_SECONDS = 60.0     # 1b mục 8: ACK lại LOGOUT trùng trong 60 giây
STREAM_SESSION = 1                  # 1b mục 5: phiên/presence/error chung
STREAM_CHAT = 2                     # CHAT và CHAT_STATUS

# Lý do transport báo khi gói tới người nhận thất bại -> mã lỗi gửi người gửi.
_FAILURE_TO_CHAT_ERROR = {"DELIVERY_TIMEOUT": "DELIVERY_TIMEOUT"}


@dataclasses.dataclass
class _LogoutTombstone:
    """Trạng thái tối thiểu sau LOGOUT để ACK lại gói LOGOUT bị truyền lại."""
    expire_at: float
    address: tuple
    rx: CryptoContext = dataclasses.field(repr=False)
    tx: CryptoContext = dataclasses.field(repr=False)   # dùng tiếp counter cũ, không tạo mới
    ack_seq: int = 1


class UdpService:
    """Logic UDP phía server: nối ``ServerUDP`` với registry phiên, ``ChatRouter`` và ``FileRelay``.

    Mọi callback chạy ngoài lock của transport. ``self._lock`` chỉ bảo vệ các bảng
    nhỏ của lớp này; không gọi callback khi đang giữ nó.
    """

    def __init__(self, sessions, transport, *, router=None, clock=time.monotonic,
                 file_queue_limit: int = RELAY_QUEUE_LIMIT):
        self.sessions = sessions
        self.transport = transport
        self.router = router if router is not None else ChatRouter(sessions)
        self.files = FileRelay(transport, self._find_ready_session, queue_limit=file_queue_limit)
        self._clock = clock
        self._lock = threading.Lock()
        self._ready = set()          # session_id đã nhận UDP_BIND_OK
        self._crypto = {}            # session_id -> (tx, rx) đang dùng cho peer
        self._chat = {}              # delivery_id -> (sender_sid, message_id, recipient_id)
        self._tombstones = {}        # session_id -> _LogoutTombstone
        transport.on_unknown_datagram(self._on_unknown)
        transport.on_payload(self._on_payload)
        transport.on_delivery(self._on_delivery)
        transport.on_failure(self._on_failure)
        transport.on_peer_closed(self._on_peer_closed)
        sessions.on_session_removed(self._on_session_removed)

    # ----- gói của phiên chưa có peer -------------------------------------

    def _on_unknown(self, raw: bytes, address: tuple) -> None:
        """Gói của phiên chưa có peer (chạy trên thread nhận UDP).

        Phiên vừa LOGOUT -> xử lý LOGOUT trùng. Còn lại chỉ nhận UDP_BIND:
        1. tìm phiên theo ``session_id`` trong header; không có hoặc đã bind thì bỏ, không ACK;
        2. giải mã bằng khóa c2s của phiên; sai khóa/tag thì bỏ;
        3. ``bind_udp`` với địa chỉ nguồn thực tế, rồi ``register_peer``;
        4. đưa lại đúng gói này cho transport: lần này được ACK và giao lên ``_on_payload``.
        """
        try:
            session_id = peek_header(raw).session_id
        except AppError:
            return
        tomb = self._get_tombstone(session_id)
        if tomb is not None:
            self._ack_duplicate_logout(session_id, tomb, raw, address)
            return
        session = self.sessions.get_session(session_id)
        if session is None or session.bound:
            return                                    # không có phiên / đã bind: bỏ, không ACK
        rx = CryptoContext(session.c2s_key, session.c2s_nonce_prefix)
        try:
            packet = decode_packet(raw, rx)           # sai khóa hoặc tag -> AppError
        except AppError:
            return
        if (packet.header.packet_type != PacketType.UDP_BIND
                or packet.header.stream_id != STREAM_SESSION):
            return
        try:
            self.sessions.bind_udp(session_id, address)
        except AppError:
            return
        # Chỉ tạo MỘT context gửi (tx) cho mỗi phiên: tạo lại thì counter về 0,
        # dùng lại nonce và phá AES-GCM. Context nhận (rx) không có counter.
        tx = CryptoContext(session.s2c_key, session.s2c_nonce_prefix)
        try:
            self.transport.register_peer(str(session_id), session_id, address, tx, rx)
        except AppError as exc:
            log.warning("Không đăng ký được peer cho %s: %s", session.user_id, exc.code)
            self.sessions.remove_session(session_id)
            return
        with self._lock:
            self._crypto[session_id] = (tx, rx)
        self.transport.receive_datagram(raw, address)   # lần này: ACK + giao lên on_payload

    # ----- gói của peer đã đăng ký ------------------------------------------

    def _on_payload(self, peer_id: str, stream_id: int, kind: int, payload: bytes) -> None:
        """Gói đã giải mã, đúng thứ tự, của peer đã đăng ký (peer_id = str(session_id)).

        * UDP_BIND (stream 1): trả UDP_BIND_OK, ``activate_peer`` (heartbeat 5 s,
          hết hạn 15 s), đánh dấu sẵn sàng rồi gửi USER_LIST cho mọi người.
        * LOGOUT (stream 1) -> ``_logout``; CHAT (stream 2) -> ``_handle_chat``;
          gói tệp (stream >= 3) -> ``FileRelay``.
        """
        session = self.sessions.get_session(int(peer_id))
        if session is None:
            return                                    # đã logout/hết hạn: bỏ hoạt động mới
        if kind == PacketType.UDP_BIND and stream_id == STREAM_SESSION:
            self._send(peer_id, STREAM_SESSION, PacketType.UDP_BIND_OK, encode_json({}))
            self.transport.activate_peer(peer_id)
            with self._lock:
                self._ready.add(session.session_id)
            self.broadcast_user_list()
        elif kind == PacketType.LOGOUT and stream_id == STREAM_SESSION:
            self._logout(session)
        elif kind == PacketType.CHAT and stream_id == STREAM_CHAT:
            self._handle_chat(session, payload)
        elif is_file_packet(stream_id, kind):
            self.files.handle_packet(session, stream_id, kind, payload)
        else:
            log.debug("Bỏ qua gói loại %s trên stream %s từ %s", kind, stream_id, session.user_id)

    def _handle_chat(self, sender, payload: bytes) -> None:
        """CHAT trên stream 2: ``ChatRouter`` chọn người nhận rồi gửi đi.

        Báo người gửi CHAT_STATUS: ``accepted`` khi xếp được vào hàng đợi transport,
        ``delivered`` khi người nhận ACK (``_on_delivery``), ``failed`` khi lỗi.
        Lỗi gửi ``INVALID_SESSION`` -> ``USER_OFFLINE``, lỗi khác (vd ``QUEUE_FULL``,
        không có trong spec) -> ``DELIVERY_TIMEOUT``.
        """
        sender_peer = str(sender.session_id)
        try:
            message = decode_json(payload)
        except AppError:
            message = None
        route = self.router.route(sender, message)
        if route.error is not None:
            self._send(sender_peer, STREAM_CHAT, PacketType.ERROR, route.error)
        for status in route.statuses:
            self._send(sender_peer, STREAM_CHAT, PacketType.CHAT_STATUS, status)
        for d in route.deliveries:
            # Giữ lock qua send + ghi bảng + báo accepted: on_delivery (cần lock) không thể
            # chạy trước khi bảng có delivery_id, và "accepted" luôn được xếp trước "delivered".
            # transport.send chỉ xếp hàng, không block.
            with self._lock:
                try:
                    delivery_id = self.transport.send(str(d.session_id), STREAM_CHAT,
                                                      PacketType.CHAT, d.payload)
                except AppError as exc:
                    code = USER_OFFLINE if exc.code == "INVALID_SESSION" else "DELIVERY_TIMEOUT"
                    status = chat_status(route.message_id, d.user_id, STATUS_FAILED, code)
                else:
                    self._chat[delivery_id] = (sender.session_id, route.message_id, d.user_id)
                    status = chat_status(route.message_id, d.user_id, STATUS_ACCEPTED)
                self._send(sender_peer, STREAM_CHAT, PacketType.CHAT_STATUS, status)

    def _on_delivery(self, delivery_id: str) -> None:
        """Người nhận ACK: tin chat -> báo ``delivered``; còn lại là gói của ``FileRelay``."""
        with self._lock:
            record = self._chat.pop(delivery_id, None)
        if record is None:
            self.files.handle_delivery(delivery_id)
        else:
            sender_sid, message_id, recipient_id = record
            self._send(str(sender_sid), STREAM_CHAT, PacketType.CHAT_STATUS,
                       chat_status(message_id, recipient_id, STATUS_DELIVERED))

    def _on_failure(self, delivery_id: str, error_code: str) -> None:
        """Gửi thất bại: tin chat -> ``failed`` (DELIVERY_TIMEOUT giữ nguyên, lý do
        khác như peer đóng/hết hạn -> USER_OFFLINE); còn lại là gói của ``FileRelay``."""
        with self._lock:
            record = self._chat.pop(delivery_id, None)
        if record is None:
            self.files.handle_failure(delivery_id, error_code)
        else:
            sender_sid, message_id, recipient_id = record
            code = _FAILURE_TO_CHAT_ERROR.get(error_code, USER_OFFLINE)   # peer đóng/hết hạn
            self._send(str(sender_sid), STREAM_CHAT, PacketType.CHAT_STATUS,
                       chat_status(message_id, recipient_id, STATUS_FAILED, code))

    def _find_ready_session(self, user_id: str):
        """session_id của ``user_id`` nếu đã bind và nhận UDP_BIND_OK, không thì None."""
        session = self.sessions.get_session_by_user(user_id)
        if session is None:
            return None
        with self._lock:
            return session.session_id if session.session_id in self._ready else None

    # ----- presence ------------------------------------------------------------

    def broadcast_user_list(self) -> None:
        """Gửi snapshot USER_LIST (đủ các phần, cùng revision) cho mọi peer đã sẵn sàng.

        Chỉ gửi cho peer đã nhận UDP_BIND_OK, nên client luôn thấy UDP_BIND_OK trước
        USER_LIST. Gọi sau mỗi lần bind và mỗi khi một phiên đã bind bị xóa.
        """
        revision, users = self.sessions.online_snapshot()
        parts = build_user_list_parts(revision, users)
        with self._lock:
            ready = list(self._ready)
        for session_id in ready:
            for part in parts:
                self._send(str(session_id), STREAM_SESSION, PacketType.USER_LIST, part)

    # ----- đóng phiên ------------------------------------------------------------

    def _logout(self, session) -> None:
        """LOGOUT đã được transport ACK; giữ khóa 60 s để ACK lại gói trùng, rồi xóa phiên."""
        now = self._clock()
        with self._lock:
            crypto = self._crypto.pop(session.session_id, None)
            self._tombstones = {sid: t for sid, t in self._tombstones.items() if t.expire_at > now}
            if crypto is not None:
                tx, rx = crypto
                self._tombstones[session.session_id] = _LogoutTombstone(
                    now + LOGOUT_TOMBSTONE_SECONDS, session.udp_addr, rx, tx)
        log.info("%s đăng xuất", session.user_id)
        self.sessions.remove_session(session.session_id)

    def _get_tombstone(self, session_id: int):
        """Tombstone LOGOUT còn hạn của phiên, hoặc None (quá 60 s thì xóa luôn)."""
        with self._lock:
            tomb = self._tombstones.get(session_id)
            if tomb is not None and tomb.expire_at <= self._clock():
                del self._tombstones[session_id]
                return None
            return tomb

    def _ack_duplicate_logout(self, session_id: int, tomb, raw: bytes, address: tuple) -> None:
        """ACK lại LOGOUT bị truyền lại; mọi gói khác của phiên đã logout bị bỏ.

        Chỉ nhận đúng địa chỉ cũ, đúng khóa. ACK được mã hóa bằng chính ``tx`` cũ
        (counter chạy tiếp nên không trùng nonce) và gửi thô qua ``send_raw`` vì
        peer đã đóng.
        """
        if address != tomb.address:
            return
        try:
            packet = decode_packet(raw, tomb.rx)
        except AppError:
            return
        h = packet.header
        if h.packet_type != PacketType.LOGOUT or h.stream_id != STREAM_SESSION:
            return
        with self._lock:
            seq = tomb.ack_seq
            tomb.ack_seq += 1
            wire = encode_packet(Header(PacketType.ACK, session_id, 0, seq, int(Flags.ENCRYPTED)),
                                 encode_ack(h.stream_id, h.seq), tomb.tx)
        self.transport.send_raw(wire, address)

    def _on_peer_closed(self, peer_id: str, reason: str) -> None:
        """Transport đóng peer (hết hạn heartbeat 15 s, lỗi stream 1/2...)."""
        log.info("Peer %s đóng: %s", peer_id, reason)
        self.sessions.remove_session(int(peer_id))

    def _on_session_removed(self, session, reason: str) -> None:
        """Phiên bị xóa (logout, hết hạn, mất kết nối): dọn peer và cập nhật online.

        Chỗ dọn duy nhất: mọi đường xóa phiên (logout, sweeper, peer timeout, lỗi gửi
        LOGIN_OK) đều qua đây. ``remove_session``/``close_peer`` gọi lần hai không làm
        gì, nên ``_on_peer_closed`` và hàm này không gọi nhau vô hạn.
        """
        session_id = session.session_id
        with self._lock:
            self._ready.discard(session_id)
            self._crypto.pop(session_id, None)
        self.router.forget_session(session_id)
        self.files.handle_session_removed(session_id)     # báo bên kia của các tệp dang dở
        try:
            self.transport.close_peer(str(session_id), reason)
        except AppError:
            pass
        if session.bound:
            self.broadcast_user_list()

    # ----- tiện ích ------------------------------------------------------------

    def _send(self, peer_id: str, stream_id: int, kind: int, payload: bytes):
        """Gửi reliable; peer đã đóng hoặc hàng đợi đầy thì chỉ ghi log."""
        try:
            return self.transport.send(peer_id, stream_id, kind, payload)
        except AppError as exc:
            log.debug("Không gửi được gói %s tới %s: %s", kind, peer_id, exc.code)
            return None


# ---------------------------------------------------------------------------
# Dòng lệnh
# ---------------------------------------------------------------------------

def build_tls_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    """Tạo SSLContext phía server, tối thiểu TLS 1.2.

    TLS bật mặc định vì LOGIN_OK chứa khóa AES của phiên; ``--no-tls`` chỉ để debug
    (giảng viên chưa xác nhận TLS có bắt buộc hay không). Chứng chỉ sinh bằng
    ``tools/gen_cert.py``.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return ctx


def parse_args(argv=None):
    """Tham số dòng lệnh; host, cổng TCP/UDP và các timeout đều cấu hình được."""
    p = argparse.ArgumentParser(description="Server cộng tác CO3094 (đăng nhập TCP/TLS)")
    p.add_argument("--host", default=DEFAULT_HOST,
                   help="địa chỉ lắng nghe (mặc định %(default)s)")
    p.add_argument("--tcp-port", type=int, default=DEFAULT_TCP_PORT,
                   help="cổng TCP đăng nhập (mặc định %(default)s)")
    p.add_argument("--udp-port", type=int, default=DEFAULT_UDP_PORT,
                   help="cổng UDP trả về trong LOGIN_OK (mặc định %(default)s)")
    p.add_argument("--login-timeout", type=float, default=DEFAULT_LOGIN_TIMEOUT,
                   help="timeout socket đăng nhập, giây (mặc định %(default)s)")
    p.add_argument("--no-tls", action="store_true",
                   help="TẮT TLS (chỉ để debug: khóa phiên sẽ đi dạng rõ)")
    p.add_argument("--cert", default="certs/server.crt",
                   help="chứng chỉ server (mặc định %(default)s)")
    p.add_argument("--key", default="certs/server.key",
                   help="khóa riêng server (mặc định %(default)s)")
    p.add_argument("--unbound-timeout", type=float, default=15.0,
                   help="giây trước khi xóa phiên chưa bind UDP (mặc định %(default)s)")
    p.add_argument("--accounts", default=None,
                   help="file tài khoản demo (mặc định accounts.json cạnh sessions.py)")
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = p.parse_args(argv)
    if args.unbound_timeout <= 0 or args.login_timeout <= 0:
        p.error("--unbound-timeout và --login-timeout phải > 0")
    return args


def main(argv=None) -> int:
    """Khởi động server: TLS -> tài khoản + thread dọn phiên -> UDP 9001 -> TCP 9000.

    Trả 0 khi dừng bằng Ctrl+C, 1 khi thiếu chứng chỉ/tài khoản hoặc không mở được cổng.
    """
    args = parse_args(argv)
    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(levelname)s [%(threadName)s] %(message)s")

    ssl_context = None
    if args.no_tls:
        log.warning("TLS đang TẮT: khóa phiên trong LOGIN_OK đi dạng rõ, chỉ dùng để debug")
    else:
        try:
            ssl_context = build_tls_context(args.cert, args.key)
        except (OSError, ssl.SSLError) as exc:
            log.error("Không nạp được chứng chỉ TLS (%s, %s): %s. "
                      "Chạy 'python tools/gen_cert.py' để sinh, hoặc dùng --no-tls khi debug",
                      args.cert, args.key, exc)
            return 1

    import sessions
    accounts_path = args.accounts or sessions.ACCOUNTS_FILE
    try:
        # Nạp tài khoản và chạy thread dọn phiên chưa bind.
        manager = sessions.init(accounts_path, unbound_timeout=args.unbound_timeout)
    except (OSError, ValueError) as exc:
        log.error("Không nạp được tài khoản từ %s: %s. "
                  "Chạy 'python tools/make_accounts.py' để sinh file", accounts_path, exc)
        return 1
    log.info("Đã nạp %d tài khoản từ %s; phiên chưa bind hết hạn sau %.1f giây",
             len(manager.accounts), accounts_path, manager.unbound_timeout)

    try:
        udp_sock = open_udp_socket(args.host, args.udp_port)
    except OSError as exc:
        log.error("Không mở được cổng UDP %s:%d: %s", args.host, args.udp_port, exc)
        manager.stop()
        return 1
    transport = ServerUDP(udp_sock, role="server")
    UdpService(manager, transport)
    transport.start()
    log.info("UDP đang lắng nghe %s:%d", args.host, udp_sock.getsockname()[1])

    server = CollabServer(manager, host=args.host, tcp_port=args.tcp_port,
                          udp_port=args.udp_port, ssl_context=ssl_context,
                          login_timeout=args.login_timeout)
    try:
        server.serve_forever()
    except OSError as exc:
        log.error("Không mở được cổng %s:%d: %s", args.host, args.tcp_port, exc)
        return 1
    finally:
        transport.close()
        manager.stop()
    return 0


def open_udp_socket(host: str, port: int) -> socket.socket:
    """Mở socket UDP cho cổng 9001.

    Trên Windows, ``recvfrom`` báo ``ConnectionResetError`` mỗi khi trước đó gửi gói tới
    một cổng đã đóng (client vừa tắt). Tắt hành vi này để vòng nhận không bị nhiễu.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    if hasattr(socket, "SIO_UDP_CONNRESET"):
        try:
            sock.ioctl(socket.SIO_UDP_CONNRESET, False)
        except OSError:
            pass
    sock.bind((host, port))
    return sock


def _utf8_console():
    """Windows: console/pipe mặc định cp1252, in tiếng Việt sẽ lỗi -> ép UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


if __name__ == "__main__":
    _utf8_console()
    sys.exit(main())
