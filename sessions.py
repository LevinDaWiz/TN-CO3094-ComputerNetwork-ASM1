"""Quản lý tài khoản và phiên đăng nhập phía server (Người 2).

1. Tài khoản demo: đọc từ ``accounts.json`` (sinh bằng ``tools/make_accounts.py``).
   Không có chức năng đăng ký. Mật khẩu chỉ lưu dạng hash PBKDF2-HMAC-SHA256
   với salt ngẫu nhiên riêng cho từng tài khoản, so sánh bằng
   ``hmac.compare_digest``. Không lưu, không log mật khẩu rõ.

2. Registry phiên (``SessionManager``), hợp đồng ``1a_api.md`` mục 5::

       authenticate(username: str, password: str) -> Session
       bind_udp(session_id: int, address: tuple) -> None
       list_online_users() -> list[dict]
       remove_session(session_id: int) -> None

   cùng ``get_session(session_id)``, ``get_session_by_user(user_id)``.
   Mỗi tài khoản một phiên; phiên chưa bind UDP hết hạn sau 15 giây.

Cách dùng phía server::

    import sessions
    sessions.init()                      # nạp accounts.json + chạy thread dọn phiên
    s = sessions.authenticate("user01", "pass01")
    sessions.bind_udp(s.session_id, ("192.168.1.5", 50000))

Các hàm cấp module dùng manager mặc định do ``init()`` tạo (lần gọi đầu sẽ tự
``init()``). Session trả ra là **bản sao**; muốn trạng thái mới thì gọi lại
``get_session``. Không ghi khóa/mật khẩu vào log; ``repr(Session)`` ẩn khóa.

``AppError`` dùng chung cả nhóm được định nghĩa trong ``protocol.py``; module này
import lại để nơi khác có thể viết ``from sessions import AppError`` mà vẫn là
cùng một lớp (``except AppError`` bắt được lỗi từ mọi module).
"""

import base64
import dataclasses
import hashlib
import hmac
import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, field

from protocol import AppError  # dùng lại, không định nghĩa lớp thứ hai

# ---------------------------------------------------------------------------
# Hằng số
# ---------------------------------------------------------------------------

ACCOUNTS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "accounts.json")
ACCOUNTS_FILE_VERSION = 1

HASH_SCHEME = "pbkdf2_sha256"
DEFAULT_ITERATIONS = 600_000   # mức OWASP khuyến nghị; ~120 ms/lần trên laptop
MIN_ITERATIONS = 1_000         # chỉ để test chạy nhanh; file thật dùng DEFAULT
SALT_BYTES = 16
HASH_BYTES = 32

MAX_USER_ID_LEN = 32           # 1b_protocol_spec.md mục 6: ASCII, tối đa 32 ký tự
MAX_USERNAME_BYTES = 64        # khớp giới hạn kiểm tra trong server.py
MAX_PASSWORD_BYTES = 1024

INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
ALREADY_LOGGED_IN = "ALREADY_LOGGED_IN"
INVALID_SESSION = "INVALID_SESSION"
INVALID_PACKET = "INVALID_PACKET"

UNBOUND_TIMEOUT = 15.0         # giây; 1b_protocol_spec.md mục 2
SWEEP_INTERVAL = 1.0           # giây giữa hai lần dọn phiên hết hạn
KEY_BYTES = 32                 # AES-256
NONCE_PREFIX_BYTES = 4

# Lý do xóa phiên, truyền cho callback on_session_removed.
REASON_UNBOUND_TIMEOUT = "UNBOUND_TIMEOUT"
REASON_REMOVED = "REMOVED"

log = logging.getLogger("sessions")

# Cùng một thông báo cho "sai username" và "sai mật khẩu" để không lộ
# tài khoản nào tồn tại.
_BAD_LOGIN_MESSAGE = "Sai tên đăng nhập hoặc mật khẩu"


# ---------------------------------------------------------------------------
# Hash mật khẩu
# ---------------------------------------------------------------------------

def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"), validate=True)


def hash_password(password: str, *, iterations: int = DEFAULT_ITERATIONS,
                  salt: bytes = None) -> str:
    """Băm mật khẩu, trả về chuỗi ``pbkdf2_sha256$<vòng>$<salt b64>$<hash b64>``.

    Mỗi lần gọi sinh salt ngẫu nhiên mới (trừ khi truyền ``salt``), nên cùng
    một mật khẩu cho ra hash khác nhau ở các tài khoản khác nhau.
    """
    if not isinstance(password, str):
        raise TypeError("password phải là str")
    if iterations < MIN_ITERATIONS:
        raise ValueError(f"iterations phải >= {MIN_ITERATIONS}")
    if salt is None:
        salt = secrets.token_bytes(SALT_BYTES)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                 iterations, dklen=HASH_BYTES)
    return f"{HASH_SCHEME}${iterations}${_b64e(salt)}${_b64e(digest)}"


def parse_password_hash(encoded: str):
    """Tách chuỗi hash thành ``(iterations, salt, digest)``.

    Raise ``ValueError`` nếu sai định dạng (dùng khi nạp ``accounts.json``).
    """
    try:
        scheme, iterations, salt_b64, digest_b64 = encoded.split("$")
        iterations = int(iterations)
        salt = _b64d(salt_b64)
        digest = _b64d(digest_b64)
    except (AttributeError, ValueError, UnicodeError) as exc:
        raise ValueError("password_hash sai định dạng") from exc
    if scheme != HASH_SCHEME:
        raise ValueError(f"chỉ hỗ trợ {HASH_SCHEME}")
    if iterations < MIN_ITERATIONS or len(salt) < 8 or len(digest) != HASH_BYTES:
        raise ValueError("password_hash có tham số không hợp lệ")
    return iterations, salt, digest


def verify_password(password: str, encoded: str) -> bool:
    """Kiểm tra mật khẩu với hash đã lưu (so sánh thời gian hằng)."""
    try:
        iterations, salt, expected = parse_password_hash(encoded)
    except ValueError:
        return False
    if not isinstance(password, str):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                 iterations, dklen=len(expected))
    return hmac.compare_digest(actual, expected)


# ---------------------------------------------------------------------------
# Tài khoản
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Account:
    """Một tài khoản demo. ``password_hash`` không hiện trong repr/log."""
    user_id: str
    username: str
    password_hash: str = field(repr=False)


def _validate_account(acc: Account) -> None:
    uid, name = acc.user_id, acc.username
    if not isinstance(uid, str) or not 1 <= len(uid) <= MAX_USER_ID_LEN \
            or not uid.isascii() or not uid.isprintable() or " " in uid:
        raise ValueError(f"user_id không hợp lệ: {uid!r} (ASCII, 1..{MAX_USER_ID_LEN} ký tự)")
    if not isinstance(name, str) or not name or name != name.strip() \
            or len(name.encode("utf-8")) > MAX_USERNAME_BYTES:
        raise ValueError(f"username không hợp lệ: {name!r}")
    parse_password_hash(acc.password_hash)


class AccountStore:
    """Danh sách tài khoản chỉ đọc; an toàn khi nhiều thread cùng gọi.

    Sau khi khởi tạo không còn thay đổi gì, nên không cần lock.
    """

    def __init__(self, accounts):
        by_name, by_id = {}, {}
        for acc in accounts:
            _validate_account(acc)
            if acc.username in by_name:
                raise ValueError(f"trùng username: {acc.username!r}")
            if acc.user_id in by_id:
                raise ValueError(f"trùng user_id: {acc.user_id!r}")
            by_name[acc.username] = acc
            by_id[acc.user_id] = acc
        self._by_name = by_name
        self._by_id = by_id
        # Hash giả cùng số vòng lớn nhất: dùng khi username không tồn tại để
        # thời gian phản hồi giống như sai mật khẩu (chống dò tài khoản).
        max_iter = max((parse_password_hash(a.password_hash)[0] for a in by_name.values()),
                       default=MIN_ITERATIONS)
        self._dummy_hash = hash_password(secrets.token_hex(16), iterations=max_iter)

    @classmethod
    def from_file(cls, path: str = ACCOUNTS_FILE) -> "AccountStore":
        """Nạp ``accounts.json``. Raise ``ValueError``/``OSError`` nếu file hỏng."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict) or data.get("version") != ACCOUNTS_FILE_VERSION:
            raise ValueError(f"{path}: cần version {ACCOUNTS_FILE_VERSION}")
        rows = data.get("accounts")
        if not isinstance(rows, list) or not rows:
            raise ValueError(f"{path}: danh sách accounts rỗng hoặc sai kiểu")
        accounts = []
        for row in rows:
            if not isinstance(row, dict):
                raise ValueError(f"{path}: mỗi tài khoản phải là object")
            accounts.append(Account(row.get("user_id"), row.get("username"),
                                    row.get("password_hash")))
        return cls(accounts)

    def verify(self, username: str, password: str) -> Account:
        """Trả về ``Account`` nếu đúng; sai thì raise ``AppError(INVALID_CREDENTIALS)``.

        Sai username và sai mật khẩu cho cùng mã lỗi, cùng thông báo và tốn
        thời gian tương đương.
        """
        if not isinstance(username, str) or not isinstance(password, str) \
                or len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
            raise AppError(INVALID_CREDENTIALS, _BAD_LOGIN_MESSAGE)
        acc = self._by_name.get(username)
        encoded = acc.password_hash if acc is not None else self._dummy_hash
        ok = verify_password(password, encoded)
        if acc is None or not ok:
            raise AppError(INVALID_CREDENTIALS, _BAD_LOGIN_MESSAGE)
        return acc

    def get_by_user_id(self, user_id: str):
        """Trả về ``Account`` theo ``user_id`` hoặc ``None``."""
        return self._by_id.get(user_id)

    def get_by_username(self, username: str):
        """Trả về ``Account`` theo ``username`` hoặc ``None``."""
        return self._by_name.get(username)

    def __len__(self) -> int:
        return len(self._by_name)


# Kho tài khoản mặc định của server, nạp lười từ ACCOUNTS_FILE.
_store = None
_store_lock = threading.Lock()


def load_accounts(path: str = ACCOUNTS_FILE) -> AccountStore:
    """Nạp (hoặc nạp lại) kho tài khoản mặc định từ ``path``."""
    global _store
    store = AccountStore.from_file(path)   # đọc file ngoài lock
    with _store_lock:
        _store = store
    return store


def get_account_store() -> AccountStore:
    """Trả về kho tài khoản mặc định, nạp ``accounts.json`` ở lần gọi đầu."""
    with _store_lock:
        store = _store
    return store if store is not None else load_accounts()


# ---------------------------------------------------------------------------
# Phiên
# ---------------------------------------------------------------------------

@dataclass
class Session:
    """Một phiên đăng nhập. Khóa và nonce prefix không hiện trong repr/log.

    Mốc thời gian (``created_at``, ``last_seen``) theo đồng hồ đơn điệu của
    manager (mặc định ``time.monotonic``), chỉ dùng để so sánh khoảng thời gian.
    """
    session_id: int
    user_id: str
    username: str
    c2s_key: bytes = field(repr=False)
    s2c_key: bytes = field(repr=False)
    c2s_nonce_prefix: bytes = field(repr=False)
    s2c_nonce_prefix: bytes = field(repr=False)
    udp_addr: tuple = None        # None khi chưa bind
    bound: bool = False
    created_at: float = 0.0
    last_seen: float = 0.0


def _validate_address(address) -> tuple:
    """Địa chỉ UDP phải là (host: str, port: int 1..65535); IPv6 có thể dài hơn."""
    if (not isinstance(address, tuple) or len(address) < 2
            or not isinstance(address[0], str) or not address[0]
            or not isinstance(address[1], int) or isinstance(address[1], bool)
            or not 1 <= address[1] <= 65535):
        raise AppError(INVALID_PACKET, "Địa chỉ UDP không hợp lệ")
    return tuple(address)


class SessionManager:
    """Registry phiên, an toàn khi nhiều thread cùng gọi.

    * ``_lock`` bảo vệ ``_by_id`` và ``_by_user``. Không giữ lock khi băm mật
      khẩu, làm I/O hay gọi callback.
    * Phiên chưa bind quá ``unbound_timeout`` giây bị xóa bởi thread dọn dẹp
      (``start()``) hoặc khi gọi ``expire_unbound()`` thủ công (dùng trong test).
    * Phiên đã bind không bị thread này xóa: việc phát hiện mất kết nối (15 giây
      không có gói hợp lệ) do lớp UDP đảm nhận rồi gọi ``remove_session``.
    """

    def __init__(self, accounts: AccountStore, *, unbound_timeout: float = UNBOUND_TIMEOUT,
                 sweep_interval: float = SWEEP_INTERVAL, clock=time.monotonic):
        if unbound_timeout <= 0 or sweep_interval <= 0:
            raise ValueError("unbound_timeout và sweep_interval phải > 0")
        self.accounts = accounts
        self.unbound_timeout = unbound_timeout
        self.sweep_interval = sweep_interval
        self._clock = clock
        self._lock = threading.Lock()
        self._by_id = {}            # session_id -> Session
        self._by_user = {}          # user_id -> session_id
        self._on_removed = None
        self._stop = threading.Event()
        self._thread = None

    # ----- callback ---------------------------------------------------------

    def on_session_removed(self, callback) -> None:
        """Đăng ký ``callback(session, reason)``, gọi ngoài lock mỗi khi xóa phiên.

        Phần UDP dùng để gỡ peer khỏi transport và gửi lại USER_LIST.
        Callback phải chạy nhanh; ngoại lệ trong callback chỉ được ghi log.
        """
        self._on_removed = callback

    def _notify_removed(self, removed) -> None:
        callback = self._on_removed
        for session, reason in removed:
            log.info("Xóa phiên của %s (%s)", session.user_id, reason)
            if callback is None:
                continue
            try:
                callback(session, reason)
            except Exception:
                log.exception("Callback on_session_removed lỗi")

    # ----- hợp đồng 1a_api.md mục 5 ----------------------------------------

    def authenticate(self, username: str, password: str) -> Session:
        """Xác thực và tạo phiên mới; trả bản sao ``Session``.

        Raise ``AppError(INVALID_CREDENTIALS)`` nếu sai tài khoản/mật khẩu,
        ``AppError(ALREADY_LOGGED_IN)`` nếu tài khoản đang có phiên.
        """
        # PBKDF2 tốn ~0,1 s: chạy NGOÀI lock để các đăng nhập khác không phải chờ.
        account = self.accounts.verify(username, password)
        keys = (secrets.token_bytes(KEY_BYTES), secrets.token_bytes(KEY_BYTES),
                secrets.token_bytes(NONCE_PREFIX_BYTES), secrets.token_bytes(NONCE_PREFIX_BYTES))
        with self._lock:
            if account.user_id in self._by_user:
                raise AppError(ALREADY_LOGGED_IN, "Tài khoản đang đăng nhập ở nơi khác")
            session_id = self._new_session_id_locked()
            now = self._clock()
            session = Session(session_id, account.user_id, account.username, *keys,
                              created_at=now, last_seen=now)
            self._by_id[session_id] = session
            self._by_user[account.user_id] = session_id
            snapshot = dataclasses.replace(session)
        log.info("Tạo phiên mới cho %s", account.user_id)
        return snapshot

    def bind_udp(self, session_id: int, address: tuple) -> None:
        """Ghi nhận địa chỉ UDP nguồn thực tế của phiên (sau khi UDP_BIND xác thực).

        Gọi lại với cùng địa chỉ (UDP_BIND bị truyền lại) là hợp lệ. Phiên
        không tồn tại/đã hết hạn hoặc đổi sang địa chỉ khác thì raise
        ``AppError(INVALID_SESSION)`` (1b mục 2: đổi địa chỉ phải đăng nhập lại).
        """
        address = _validate_address(address)
        with self._lock:
            session = self._by_id.get(session_id)
            if session is None:
                raise AppError(INVALID_SESSION, "Phiên không tồn tại hoặc đã hết hạn")
            if session.bound and session.udp_addr != address:
                raise AppError(INVALID_SESSION, "Không được đổi địa chỉ UDP trong phiên")
            first_bind = not session.bound
            session.udp_addr = address
            session.bound = True
            session.last_seen = self._clock()
            user_id = session.user_id
        if first_bind:
            log.info("Phiên của %s đã bind UDP %s:%d", user_id, address[0], address[1])

    def list_online_users(self) -> list:
        """Danh sách ``[{user_id, username}]`` của các phiên đã bind, sắp theo user_id."""
        with self._lock:
            users = [{"user_id": s.user_id, "username": s.username}
                     for s in self._by_id.values() if s.bound]
        return sorted(users, key=lambda u: u["user_id"])

    def remove_session(self, session_id: int) -> None:
        """Xóa phiên (logout, mất kết nối, lỗi gửi LOGIN_OK). Không lỗi nếu không có."""
        with self._lock:
            session = self._pop_locked(session_id)
        if session is not None:
            self._notify_removed([(session, REASON_REMOVED)])

    # ----- tiện ích cho các phần sau ---------------------------------------

    def get_session(self, session_id: int):
        """Bản sao ``Session`` theo ``session_id``, hoặc ``None``."""
        with self._lock:
            session = self._by_id.get(session_id)
            return dataclasses.replace(session) if session is not None else None

    def get_session_by_user(self, user_id: str):
        """Bản sao ``Session`` đang có của ``user_id``, hoặc ``None``."""
        with self._lock:
            session_id = self._by_user.get(user_id)
            session = self._by_id.get(session_id) if session_id is not None else None
            return dataclasses.replace(session) if session is not None else None

    def touch(self, session_id: int) -> None:
        """Cập nhật ``last_seen`` khi nhận gói UDP hợp lệ của phiên."""
        with self._lock:
            session = self._by_id.get(session_id)
            if session is not None:
                session.last_seen = self._clock()

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_id)

    # ----- hết hạn và thread dọn dẹp ----------------------------------------

    def expire_unbound(self) -> list:
        """Xóa các phiên chưa bind quá ``unbound_timeout`` giây; trả danh sách đã xóa."""
        now = self._clock()
        with self._lock:
            expired = [sid for sid, s in self._by_id.items()
                       if not s.bound and now - s.created_at >= self.unbound_timeout]
            removed = [self._pop_locked(sid) for sid in expired]
        self._notify_removed([(s, REASON_UNBOUND_TIMEOUT) for s in removed])
        return removed

    def start(self) -> None:
        """Chạy thread dọn phiên hết hạn ở nền (gọi nhiều lần không sao)."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(target=self._sweep_loop,
                                            name="session-sweeper", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        """Dừng thread dọn dẹp."""
        self._stop.set()
        thread = self._thread
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=5)

    def _sweep_loop(self) -> None:
        while not self._stop.wait(self.sweep_interval):
            try:
                self.expire_unbound()
            except Exception:
                # Thread dọn dẹp không được chết vì một lỗi bất ngờ.
                log.exception("Lỗi khi dọn phiên hết hạn")

    # ----- nội bộ (gọi khi đang giữ lock) -----------------------------------

    def _new_session_id_locked(self) -> int:
        """session_id 64-bit ngẫu nhiên, khác 0, không trùng phiên đang có."""
        while True:
            candidate = secrets.randbits(64)
            if candidate != 0 and candidate not in self._by_id:
                return candidate

    def _pop_locked(self, session_id):
        session = self._by_id.pop(session_id, None)
        if session is not None and self._by_user.get(session.user_id) == session_id:
            del self._by_user[session.user_id]
        return session


# ---------------------------------------------------------------------------
# Manager mặc định và các hàm cấp module (hợp đồng 1a_api.md mục 5)
# ---------------------------------------------------------------------------

_manager = None
_manager_lock = threading.Lock()


def init(accounts_path: str = None, *, unbound_timeout: float = UNBOUND_TIMEOUT,
         sweep_interval: float = SWEEP_INTERVAL, start: bool = True) -> SessionManager:
    """Tạo manager mặc định: nạp tài khoản và (mặc định) chạy thread dọn phiên.

    Gọi lại sẽ thay manager cũ (manager cũ bị dừng thread dọn dẹp).
    """
    global _manager
    store = load_accounts(accounts_path) if accounts_path else get_account_store()
    manager = SessionManager(store, unbound_timeout=unbound_timeout,
                             sweep_interval=sweep_interval)
    with _manager_lock:
        old, _manager = _manager, manager
    if old is not None:
        old.stop()
    if start:
        manager.start()
    return manager


def get_manager() -> SessionManager:
    """Manager mặc định; lần đầu gọi sẽ ``init()`` với cấu hình mặc định."""
    with _manager_lock:
        manager = _manager
    return manager if manager is not None else init()


def authenticate(username: str, password: str) -> Session:
    """Xem ``SessionManager.authenticate``."""
    return get_manager().authenticate(username, password)


def bind_udp(session_id: int, address: tuple) -> None:
    """Xem ``SessionManager.bind_udp``."""
    get_manager().bind_udp(session_id, address)


def list_online_users() -> list:
    """Xem ``SessionManager.list_online_users``."""
    return get_manager().list_online_users()


def remove_session(session_id: int) -> None:
    """Xem ``SessionManager.remove_session``."""
    get_manager().remove_session(session_id)


def get_session(session_id: int):
    """Xem ``SessionManager.get_session``."""
    return get_manager().get_session(session_id)


def get_session_by_user(user_id: str):
    """Xem ``SessionManager.get_session_by_user``."""
    return get_manager().get_session_by_user(user_id)


def on_session_removed(callback) -> None:
    """Xem ``SessionManager.on_session_removed``."""
    get_manager().on_session_removed(callback)
