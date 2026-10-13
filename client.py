"""Phía client: kết nối, đăng nhập, quản lý trạng thái kết nối, phân phối packet.

ChatClient chỉ làm việc với packet dạng dict ({"type": "...", ...}). Việc đóng gói
bytes, mã hoá, ACK/retransmit nằm trong Transport (reliable_udp.py + protocol.py).
Xem docs/api.md §5 (máy trạng thái) và §6 (hợp đồng với các module khác).
"""

import logging
import re
import threading
import time
from enum import Enum

log = logging.getLogger("client")

PROTOCOL_VERSION = 1
CONNECT_TIMEOUT = 5.0      # giây chờ HELLO_ACK
AUTH_TIMEOUT = 5.0         # giây chờ AUTH_OK / AUTH_FAIL
HEARTBEAT_INTERVAL = 3.0   # giây giữa hai lần PING
DEAD_TIMEOUT = 10.0        # không nhận được gói nào trong khoảng này → coi như mất kết nối
RECONNECT_ATTEMPTS = 5
RECONNECT_DELAY = 2.0
RECV_POLL = 0.5            # timeout mỗi lần recv để luồng nhận kiểm tra cờ dừng

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")


class ConnState(str, Enum):
    DISCONNECTED = "DISCONNECTED"
    CONNECTING = "CONNECTING"
    CONNECTED = "CONNECTED"
    AUTHENTICATING = "AUTHENTICATING"
    ONLINE = "ONLINE"
    RECONNECTING = "RECONNECTING"
    LOGGING_OUT = "LOGGING_OUT"


class ClientError(Exception):
    """Lỗi có mã, http_bridge dùng `code` để chọn HTTP status (docs/api.md §2)."""
    code = "INTERNAL"


class NotOnlineError(ClientError):
    code = "NOT_ONLINE"


class AlreadyOnlineError(ClientError):
    code = "ALREADY_ONLINE"


class BusyError(ClientError):
    code = "BUSY"


class AuthError(ClientError):
    code = "AUTH_FAILED"


class ConnectError(ClientError):
    code = "SERVER_UNREACHABLE"


class Transport:
    """Interface đường truyền mà ChatClient cần (docs/api.md §6.1).

    ⏳ PENDING: bản thật do reliable_udp.py (+ mã hoá) cung cấp.
    """

    def connect(self, server_addr: tuple[str, int]) -> None:
        raise NotImplementedError

    def send(self, packet: dict) -> None:
        """Gửi một packet; lỗi đường truyền → raise OSError."""
        raise NotImplementedError

    def recv(self, timeout: float) -> dict | None:
        """Trả packet kế tiếp, None nếu hết timeout; đường truyền đã đóng → raise OSError."""
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError


def make_real_transport() -> Transport:
    # ⏳ PENDING: thay bằng transport thật khi reliable_udp.py xong, ví dụ:
    #   from reliable_udp import ReliableUDPTransport
    #   return ReliableUDPTransport(...)
    raise NotImplementedError("reliable_udp.py chưa có Transport — tạm chạy với --mock")


class _Waiter:
    """Chờ một packet có type thuộc `types` (dùng cho HELLO_ACK, AUTH_OK...)."""

    def __init__(self, types: set[str]):
        self.types = types
        self.packet: dict | None = None
        self._event = threading.Event()

    def resolve(self, packet: dict | None) -> None:
        self.packet = packet
        self._event.set()

    def wait(self, timeout: float) -> dict | None:
        self._event.wait(timeout)
        return self.packet


class ChatClient:
    def __init__(self, server_addr: tuple[str, int], transport_factory=make_real_transport,
                 on_event=None):
        self.server_addr = server_addr
        self._transport_factory = transport_factory
        self._on_event = on_event or (lambda type_, data: None)

        # _lock bảo vệ trạng thái/transport và chỉ giữ trong thời gian ngắn.
        # _op_lock tuần tự hoá các thao tác dài (connect/login/logout/reconnect).
        self._lock = threading.RLock()
        self._op_lock = threading.Lock()
        self._send_lock = threading.Lock()

        self._state = ConnState.DISCONNECTED
        self._transport: Transport | None = None
        self._session_stop = threading.Event()   # dừng luồng của phiên kết nối hiện tại
        self._last_rx = 0.0
        self.session_id = None

        self.username: str | None = None
        self._password: str | None = None
        self._want_online = False                 # True từ lúc login thành công tới lúc logout
        self._users: list[str] = []

        self._handlers: dict[str, list] = {}
        self._waiters: list[_Waiter] = []
        self._waiters_lock = threading.Lock()

        # ⏳ PENDING: đối tượng FileService từ file_transfer.py (docs/api.md §6.3).
        self.file_service = None

        self.register_handler("USER_LIST", lambda p: self._set_users(p.get("users")))
        self.register_handler("PING", lambda p: self._safe_send({"type": "PONG"}))
        self.register_handler("PONG", lambda p: None)  # chỉ cần cập nhật _last_rx

    # ---- API công khai ----------------------------------------------------

    @property
    def state(self) -> ConnState:
        return self._state

    @property
    def online_users(self) -> list[str]:
        with self._lock:
            return list(self._users)

    def status(self) -> dict:
        with self._lock:
            return {"state": self._state.value, "username": self.username,
                    "server": f"{self.server_addr[0]}:{self.server_addr[1]}"}

    def register_handler(self, packet_type: str, fn) -> None:
        """Đăng ký hàm xử lý packet; hàm chạy trên luồng nhận nên không được chặn lâu."""
        self._handlers.setdefault(packet_type, []).append(fn)

    def require_online(self) -> None:
        if self._state != ConnState.ONLINE:
            raise NotOnlineError("Chưa đăng nhập")

    def connect(self) -> None:
        """Kết nối + handshake. Không làm gì nếu đã kết nối."""
        with self._op_lock:
            if self._state == ConnState.DISCONNECTED:
                self._open()

    def login(self, username: str, password: str = "") -> list[str]:
        """Đăng nhập, tự kết nối nếu cần. Trả về danh sách người online."""
        if not isinstance(username, str) or not USERNAME_RE.match(username):
            raise ValueError("Tên đăng nhập 1–32 ký tự, chỉ gồm chữ, số, _ . -")
        if not isinstance(password, str):
            raise ValueError("Mật khẩu phải là chuỗi")

        with self._op_lock:
            if self._state == ConnState.ONLINE:
                raise AlreadyOnlineError(f"Đang đăng nhập với tên {self.username}")
            if self._state == ConnState.DISCONNECTED:
                self._open()
            if self._state != ConnState.CONNECTED:
                raise BusyError(f"Không thể đăng nhập khi đang {self._state.value}")
            self._authenticate(username, password)
            self._want_online = True
            return self.online_users

    def logout(self) -> None:
        """Đăng xuất và ngắt kết nối. Gọi nhiều lần không sao."""
        self._want_online = False  # đặt trước khi lấy _op_lock để vòng reconnect dừng sớm
        with self._op_lock:
            if self._state == ConnState.DISCONNECTED:
                return
            self._set_state(ConnState.LOGGING_OUT)
            if self.username:
                self._safe_send({"type": "LOGOUT"})
            self._teardown()
            with self._lock:
                self.username = None
                self._password = None
                self._users = []
            self._set_state(ConnState.DISCONNECTED)

    def send_packet(self, packet: dict) -> None:
        """Gửi packet qua transport hiện tại; chưa kết nối hoặc lỗi → OSError."""
        with self._lock:
            transport = self._transport
        if transport is None:
            raise OSError("Chưa kết nối tới server")
        with self._send_lock:
            transport.send(packet)

    # ---- kết nối / xác thực (gọi khi đang giữ _op_lock) ------------------

    # `fail_state`: trạng thái quay về khi thất bại — DISCONNECTED khi người dùng
    # đăng nhập, RECONNECTING khi đang tự kết nối lại (tránh UI nhấp nháy).

    def _open(self, fail_state: ConnState = ConnState.DISCONNECTED) -> None:
        self._set_state(ConnState.CONNECTING)
        try:
            transport = self._transport_factory()
            transport.connect(self.server_addr)
        except NotImplementedError:
            self._set_state(fail_state)
            raise
        except Exception as e:
            self._set_state(fail_state, reason=str(e))
            raise ConnectError(f"Không kết nối được tới server: {e}") from e

        stop = threading.Event()
        with self._lock:
            self._transport = transport
            self._session_stop = stop
            self._last_rx = time.monotonic()
        threading.Thread(target=self._recv_loop, args=(transport, stop),
                         name="client-recv", daemon=True).start()

        waiter = self._expect({"HELLO_ACK"})   # đăng ký trước khi gửi để không lỡ gói trả lời
        try:
            self.send_packet({"type": "HELLO", "version": PROTOCOL_VERSION})
            packet = waiter.wait(CONNECT_TIMEOUT)
        except OSError as e:
            packet = None
            log.warning("Gửi HELLO lỗi: %s", e)
        finally:
            self._drop_waiter(waiter)
        if packet is None:
            self._teardown()
            self._set_state(fail_state, reason="Server không phản hồi HELLO")
            raise ConnectError("Server không phản hồi")

        self.session_id = packet.get("session_id")
        self._set_state(ConnState.CONNECTED)
        threading.Thread(target=self._heartbeat_loop, args=(stop,),
                         name="client-heartbeat", daemon=True).start()

    def _authenticate(self, username: str, password: str,
                      fail_state: ConnState = ConnState.DISCONNECTED) -> None:
        self._set_state(ConnState.AUTHENTICATING)
        waiter = self._expect({"AUTH_OK", "AUTH_FAIL"})
        try:
            self.send_packet({"type": "AUTH", "username": username, "password": password})
            packet = waiter.wait(AUTH_TIMEOUT)
        except OSError as e:
            packet = None
            log.warning("Gửi AUTH lỗi: %s", e)
        finally:
            self._drop_waiter(waiter)

        if packet is None:
            self._teardown()
            self._set_state(fail_state, reason="Server không phản hồi AUTH")
            raise ConnectError("Server không phản hồi khi đăng nhập")
        if packet["type"] == "AUTH_FAIL":
            self._set_state(ConnState.CONNECTED)
            raise AuthError(packet.get("reason") or "Sai tên đăng nhập hoặc mật khẩu")

        with self._lock:
            self.username = username
            self._password = password
        self._set_users(packet.get("users") or [username])
        self._set_state(ConnState.ONLINE)

    def _teardown(self) -> None:
        """Dừng luồng của phiên hiện tại, đóng transport, đánh thức mọi waiter."""
        with self._lock:
            self._session_stop.set()
            transport, self._transport = self._transport, None
        if transport is not None:
            try:
                transport.close()
            except OSError:
                pass
        with self._waiters_lock:
            waiters, self._waiters = self._waiters, []
        for w in waiters:
            w.resolve(None)

    # ---- mất kết nối / kết nối lại ----------------------------------------

    def _on_connection_lost(self, stop: threading.Event, reason: str) -> None:
        with self._lock:
            if stop.is_set():          # phiên này đã bị đóng chủ động (logout, teardown)
                return
            was_online = self._state == ConnState.ONLINE
        log.warning("Mất kết nối: %s", reason)
        self._teardown()
        self._emit("error", {"code": "SERVER_LOST", "message": reason})
        if was_online and self._want_online:
            self._set_state(ConnState.RECONNECTING, reason=reason)
            threading.Thread(target=self._reconnect_loop, name="client-reconnect",
                             daemon=True).start()
        else:
            self._set_state(ConnState.DISCONNECTED, reason=reason)

    def _reconnect_loop(self) -> None:
        for attempt in range(1, RECONNECT_ATTEMPTS + 1):
            with self._op_lock:
                if not self._want_online or self._state != ConnState.RECONNECTING:
                    return
                username, password = self.username, self._password
                log.info("Kết nối lại lần %d/%d", attempt, RECONNECT_ATTEMPTS)
                try:
                    self._open(fail_state=ConnState.RECONNECTING)
                    self._authenticate(username, password, fail_state=ConnState.RECONNECTING)
                    return
                except AuthError as e:
                    self._teardown()
                    self._want_online = False
                    self._set_state(ConnState.DISCONNECTED, reason=str(e))
                    return
                except (ClientError, OSError) as e:
                    self._teardown()
                    self._set_state(ConnState.RECONNECTING,
                                    reason=f"Lần {attempt} thất bại: {e}")
            time.sleep(RECONNECT_DELAY)

        with self._op_lock:
            if self._state == ConnState.RECONNECTING:
                self._want_online = False
                self._set_state(ConnState.DISCONNECTED, reason="Hết số lần kết nối lại")

    # ---- các luồng nền ------------------------------------------------------

    def _recv_loop(self, transport: Transport, stop: threading.Event) -> None:
        while not stop.is_set():
            try:
                packet = transport.recv(RECV_POLL)
            except OSError as e:
                self._on_connection_lost(stop, f"Lỗi nhận: {e}")
                return
            if packet is None:
                continue
            if not isinstance(packet, dict) or not isinstance(packet.get("type"), str):
                log.warning("Bỏ qua packet không hợp lệ: %r", packet)
                continue
            self._last_rx = time.monotonic()
            if not self._resolve_waiter(packet):
                self._dispatch(packet)

    def _heartbeat_loop(self, stop: threading.Event) -> None:
        while not stop.wait(HEARTBEAT_INTERVAL):
            if time.monotonic() - self._last_rx > DEAD_TIMEOUT:
                self._on_connection_lost(stop, "Không nhận được heartbeat từ server")
                return
            try:
                self.send_packet({"type": "PING"})
            except OSError as e:
                self._on_connection_lost(stop, f"Lỗi gửi PING: {e}")
                return

    # ---- tiện ích nội bộ ----------------------------------------------------

    def _dispatch(self, packet: dict) -> None:
        handlers = self._handlers.get(packet["type"])
        if not handlers:
            log.debug("Không có handler cho %s", packet["type"])
            return
        for fn in handlers:
            try:
                fn(packet)
            except Exception:
                log.exception("Handler %s lỗi", packet["type"])

    def _expect(self, types: set[str]) -> _Waiter:
        waiter = _Waiter(types)
        with self._waiters_lock:
            self._waiters.append(waiter)
        return waiter

    def _drop_waiter(self, waiter: _Waiter) -> None:
        with self._waiters_lock:
            if waiter in self._waiters:
                self._waiters.remove(waiter)

    def _resolve_waiter(self, packet: dict) -> bool:
        with self._waiters_lock:
            for w in self._waiters:
                if packet["type"] in w.types:
                    self._waiters.remove(w)
                    break
            else:
                return False
        w.resolve(packet)
        return True

    def _safe_send(self, packet: dict) -> None:
        try:
            self.send_packet(packet)
        except OSError as e:
            log.debug("Gửi %s lỗi: %s", packet.get("type"), e)

    def _set_users(self, users) -> None:
        if not isinstance(users, list):
            return
        clean = sorted({u for u in users if isinstance(u, str)})
        with self._lock:
            if clean == self._users:
                return
            self._users = clean
        self._emit("users", {"users": clean})

    def _set_state(self, state: ConnState, reason: str | None = None) -> None:
        with self._lock:
            if self._state == state and reason is None:
                return
            self._state = state
        self._emit("connection", {"state": state.value, "reason": reason})

    def _emit(self, type_: str, data: dict) -> None:
        try:
            self._on_event(type_, data)
        except Exception:
            log.exception("on_event lỗi")
