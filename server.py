"""Server cộng tác: đăng nhập qua TCP/TLS (cổng 9000) - Người 2.

Theo ``1b_protocol_spec.md`` mục 2:

* Mỗi kết nối TCP chỉ dùng để đăng nhập: client gửi đúng một frame LOGIN,
  server trả LOGIN_OK hoặc ERROR rồi đóng kết nối. Phiên sau đó được duy trì
  qua UDP (cổng 9001, sẽ gắn thêm ở bước sau).
* Framing ``[length: uint32 big-endian][JSON UTF-8]`` nằm trong ``framing.py``
  (dùng chung với client).
* Mỗi kết nối được xử lý trong một thread riêng. Mọi lỗi mạng chỉ làm hỏng
  kết nối đó, không làm dừng server.
* TLS bật mặc định vì LOGIN_OK chứa khóa AES của phiên; ``--no-tls`` chỉ dùng
  để debug (giảng viên chưa xác nhận TLS có bắt buộc hay không).

Ngoài ra có phần logic dùng cho UDP (chưa gắn socket, chờ transport):

* ``build_user_list_parts``: USER_LIST phân trang <= 1149 byte (1b mục 8).
* ``ChatRouter``: kiểm tra CHAT, chọn người nhận chat riêng/chung, chống trùng
  message_id, tạo payload có ``from``/``sent_at`` (1b mục 6).

Không ghi mật khẩu, khóa phiên hay nonce prefix vào log.
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
from protocol import MAX_PLAINTEXT, AppError, encode_json   # dùng chung của cả nhóm

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
    """Tạo thông điệp ERROR theo 1b_protocol_spec.md mục 9."""
    return {"type": "ERROR", "code": code, "message": message, "reference_id": reference_id}


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class CollabServer:
    """Server đăng nhập TCP/TLS, mỗi kết nối một thread.

    ``session_backend`` là đối tượng (thường là ``sessions.SessionManager``) cung cấp:

    * ``authenticate(username, password) -> Session``; raise ``AppError``
      với ``INVALID_CREDENTIALS``/``ALREADY_LOGGED_IN`` khi thất bại.
      Session có các trường ``session_id, user_id, c2s_key, s2c_key,
      c2s_nonce_prefix, s2c_nonce_prefix`` (khóa dạng bytes).
    * ``remove_session(session_id)``: hủy phiên nếu gửi LOGIN_OK thất bại.

    Phần UDP (cổng ``udp_port``) sẽ gắn vào ``start``/``stop`` ở bước sau.
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
        """Đọc frame LOGIN, xác thực và gửi LOGIN_OK hoặc ERROR."""
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
        """Kiểm tra cấu trúc LOGIN; trả về (username, password)."""
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
    """Payload ERROR (loại gói 14) ``{code, message, reference_id}``."""
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
# Dòng lệnh
# ---------------------------------------------------------------------------

def build_tls_context(cert_file: str, key_file: str) -> ssl.SSLContext:
    """Tạo SSLContext phía server, tối thiểu TLS 1.2."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    return ctx


def parse_args(argv=None):
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

    server = CollabServer(manager, host=args.host, tcp_port=args.tcp_port,
                          udp_port=args.udp_port, ssl_context=ssl_context,
                          login_timeout=args.login_timeout)
    try:
        server.serve_forever()
    except OSError as exc:
        log.error("Không mở được cổng %s:%d: %s", args.host, args.tcp_port, exc)
        return 1
    finally:
        manager.stop()
    return 0


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
