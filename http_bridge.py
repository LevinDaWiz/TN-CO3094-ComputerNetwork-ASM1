"""HTTP server cục bộ viết bằng socket thô, làm cầu nối giữa giao diện web và client.

- Phục vụ tệp tĩnh trong web/ (giao diện của người 5).
- API JSON cho đăng nhập, gửi tin, danh sách online, tệp (docs/api.md §3).
- EventQueue + long-poll GET /api/events thay cho WebSocket (docs/api.md §4).

Chạy:  python3 http_bridge.py --mock            (server giả, không cần nhóm)
       python3 http_bridge.py --server 127.0.0.1:9000
"""

import argparse
import json
import logging
import mimetypes
import os
import socket
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass
from urllib.parse import parse_qs, quote, unquote, urlsplit

from client import ChatClient, ClientError, make_real_transport
from messaging import GLOBAL, Messenger

log = logging.getLogger("http_bridge")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_HEADER_BYTES = 16 * 1024
MAX_JSON_BODY = 64 * 1024
MAX_UPLOAD = 100 * 1024 * 1024
SOCKET_TIMEOUT = 15.0
DEFAULT_POLL_TIMEOUT = 25.0
MAX_POLL_TIMEOUT = 30.0
EVENT_QUEUE_SIZE = 1000
CHUNK = 64 * 1024

STATUS_TEXT = {200: "OK", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
               404: "Not Found", 415: "Unsupported Media Type",
               405: "Method Not Allowed", 409: "Conflict", 413: "Payload Too Large",
               500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway"}

# Mã lỗi của client.py → HTTP status (docs/api.md §2).
CLIENT_ERROR_STATUS = {"NOT_ONLINE": 409, "ALREADY_ONLINE": 409, "BUSY": 409,
                       "AUTH_FAILED": 401, "SERVER_UNREACHABLE": 502}


# ============================================================================
# Hàng đợi sự kiện
# ============================================================================

class EventQueue:
    """Sự kiện đánh số tăng dần; JS long-poll lấy các sự kiện có seq > since."""

    def __init__(self, maxlen: int = EVENT_QUEUE_SIZE):
        self._events: deque = deque(maxlen=maxlen)
        self._seq = 0
        self._cond = threading.Condition()

    @property
    def last_seq(self) -> int:
        with self._cond:
            return self._seq

    def push(self, type_: str, data: dict) -> int:
        """Thêm sự kiện; an toàn khi gọi từ bất kỳ luồng nào."""
        with self._cond:
            self._seq += 1
            self._events.append({"seq": self._seq, "type": type_, "ts": time.time(), "data": data})
            self._cond.notify_all()
            return self._seq

    def wait_since(self, since: int, timeout: float) -> tuple[list[dict], int, bool]:
        """Chờ tới khi có sự kiện mới hơn `since` hoặc hết timeout.

        Trả về (events, next, reset). reset=True khi `since` không còn khớp với hàng
        đợi (bridge khởi động lại, hoặc JS tụt quá xa nên đã mất sự kiện cũ).
        """
        deadline = time.monotonic() + timeout
        with self._cond:
            if since > self._seq:
                return [], self._seq, True
            while self._seq <= since:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return [], since, False
                self._cond.wait(remaining)
            reset = since < self._events[0]["seq"] - 1
            events = [e for e in self._events if e["seq"] > since]
            return events, self._seq, reset


# ============================================================================
# HTTP tối giản trên socket
# ============================================================================

class HttpError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


@dataclass
class FileResult:
    """Kết quả handler là một tệp cần gửi về (tệp tĩnh hoặc tải xuống)."""
    path: str
    content_type: str
    download_name: str | None = None


class Request:
    def __init__(self, conn: socket.socket, method: str, target: str, headers: dict,
                 leftover: bytes):
        self.conn = conn
        self.method = method
        self.headers = headers              # khoá viết thường
        split = urlsplit(target)
        self.path = unquote(split.path)
        self.query = {k: v[-1] for k, v in parse_qs(split.query).items()}
        self._leftover = leftover           # phần body đã đọc lẫn cùng header
        self._body_read = False

    @property
    def content_length(self) -> int:
        if "chunked" in self.headers.get("transfer-encoding", "").lower():
            raise HttpError(400, "BAD_REQUEST", "Không hỗ trợ Transfer-Encoding: chunked")
        raw = self.headers.get("content-length", "0")
        try:
            n = int(raw)
        except ValueError:
            raise HttpError(400, "BAD_REQUEST", "Content-Length không hợp lệ")
        if n < 0:
            raise HttpError(400, "BAD_REQUEST", "Content-Length không hợp lệ")
        return n

    def iter_body(self, limit: int):
        """Đọc body theo từng khúc, dừng đúng ở Content-Length."""
        if self._body_read:
            return
        self._body_read = True
        remaining = self.content_length
        if remaining > limit:
            raise HttpError(413, "TOO_LARGE", f"Body vượt quá {limit} byte")
        if self._leftover:
            chunk, self._leftover = self._leftover[:remaining], b""
            remaining -= len(chunk)
            yield chunk
        while remaining > 0:
            chunk = self.conn.recv(min(CHUNK, remaining))
            if not chunk:
                raise HttpError(400, "BAD_REQUEST", "Kết nối đóng khi chưa gửi đủ body")
            remaining -= len(chunk)
            yield chunk

    def drain(self, limit: int = MAX_UPLOAD) -> None:
        """Đọc bỏ body trước khi trả lỗi; nếu không, đóng socket khi còn dữ liệu chưa
        đọc sẽ gửi RST và trình duyệt có thể không nhận được response lỗi."""
        try:
            for _ in self.iter_body(limit):
                pass
        except (HttpError, OSError):
            pass

    def read_body(self, limit: int = MAX_JSON_BODY) -> bytes:
        return b"".join(self.iter_body(limit))

    def json(self) -> dict:
        # Bắt buộc application/json: form HTML của trang web khác không gửi được kiểu này
        # nếu không qua preflight CORS (mà bridge không hỗ trợ) → chặn CSRF.
        ctype = self.headers.get("content-type", "").split(";")[0].strip().lower()
        if self.content_length and ctype != "application/json":
            raise HttpError(415, "BAD_REQUEST", "Content-Type phải là application/json")
        body = self.read_body(MAX_JSON_BODY)
        if not body.strip():
            return {}
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HttpError(400, "BAD_REQUEST", "Body không phải JSON hợp lệ")
        if not isinstance(data, dict):
            raise HttpError(400, "BAD_REQUEST", "Body JSON phải là object")
        return data


def read_request(conn: socket.socket) -> Request | None:
    """Đọc request line + header. Trả None nếu client đóng kết nối trước khi gửi gì."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > MAX_HEADER_BYTES:
            raise HttpError(400, "BAD_REQUEST", "Header quá lớn")
        chunk = conn.recv(4096)
        if not chunk:
            if buf:
                raise HttpError(400, "BAD_REQUEST", "Request bị cắt ngang")
            return None
        buf += chunk
    head, leftover = buf.split(b"\r\n\r\n", 1)
    if len(head) > MAX_HEADER_BYTES:
        raise HttpError(400, "BAD_REQUEST", "Header quá lớn")

    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        raise HttpError(400, "BAD_REQUEST", "Request line không hợp lệ")
    method, target, _version = parts

    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            raise HttpError(400, "BAD_REQUEST", "Header không hợp lệ")
        headers[name.strip().lower()] = value.strip()
    return Request(conn, method.upper(), target, headers, leftover)


def _head_bytes(status: int, headers: list[tuple[str, str]]) -> bytes:
    lines = [f"HTTP/1.1 {status} {STATUS_TEXT.get(status, 'Unknown')}"]
    lines += [f"{k}: {v}" for k, v in headers]
    lines += ["Connection: close", "Cache-Control: no-store", "", ""]
    return "\r\n".join(lines).encode("iso-8859-1")


def send_bytes(conn: socket.socket, status: int, body: bytes, content_type: str) -> None:
    conn.sendall(_head_bytes(status, [("Content-Type", content_type),
                                      ("Content-Length", str(len(body)))]) + body)


def send_json(conn: socket.socket, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    send_bytes(conn, status, body, "application/json; charset=utf-8")


def send_file(conn: socket.socket, result: FileResult, f) -> None:
    size = os.fstat(f.fileno()).st_size
    headers = [("Content-Type", result.content_type), ("Content-Length", str(size))]
    if result.download_name:
        # RFC 6266/5987: tên tệp Unicode phải percent-encode trong header.
        headers.append(("Content-Disposition",
                        f"attachment; filename*=UTF-8''{quote(result.download_name)}"))
    conn.sendall(_head_bytes(200, headers))
    while chunk := f.read(CHUNK):
        conn.sendall(chunk)


def ok(data) -> tuple[int, dict]:
    return 200, {"ok": True, "data": data, "error": None}


def error_payload(code: str, message: str) -> dict:
    return {"ok": False, "data": None, "error": {"code": code, "message": message}}


def guess_type(path: str) -> str:
    ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
    if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
        ctype += "; charset=utf-8"
    return ctype


def safe_filename(name: str) -> str:
    """Bỏ đường dẫn và ký tự điều khiển khỏi tên tệp người dùng gửi lên."""
    name = os.path.basename(name.replace("\\", "/"))
    name = "".join(ch for ch in name if ch.isprintable()).strip().lstrip(".")
    return name[:200] or "file"


# ============================================================================
# Bridge
# ============================================================================

class HttpBridge:
    def __init__(self, client: ChatClient, messenger: Messenger, events: EventQueue,
                 host: str = "127.0.0.1", port: int = 8080,
                 static_dir: str = os.path.join(BASE_DIR, "web"),
                 upload_dir: str = os.path.join(BASE_DIR, "uploads")):
        self.client = client
        self.messenger = messenger
        self.events = events
        self.host, self.port = host, port
        self.static_dir = os.path.realpath(static_dir)
        self.upload_dir = upload_dir
        self._sock: socket.socket | None = None
        self._stopping = threading.Event()

        self.routes = {
            ("GET", "/api/status"): self.h_status,
            ("POST", "/api/login"): self.h_login,
            ("POST", "/api/logout"): self.h_logout,
            ("GET", "/api/users"): self.h_users,
            ("GET", "/api/messages"): self.h_get_messages,
            ("POST", "/api/messages"): self.h_send_message,
            ("GET", "/api/events"): self.h_events,
            ("POST", "/api/files"): self.h_upload,
        }

    # ---- vòng accept --------------------------------------------------------

    def serve_forever(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(64)
        self._sock.settimeout(1.0)   # để vòng lặp kiểm tra cờ dừng định kỳ
        log.info("HTTP bridge: http://%s:%d", self.host, self.port)
        try:
            while not self._stopping.is_set():
                try:
                    conn, _addr = self._sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    if self._stopping.is_set():
                        break
                    raise
                threading.Thread(target=self._handle_conn, args=(conn,),
                                 name="http-conn", daemon=True).start()
        finally:
            self._sock.close()

    def shutdown(self) -> None:
        self._stopping.set()

    # ---- xử lý một kết nối --------------------------------------------------

    def _handle_conn(self, conn: socket.socket) -> None:
        conn.settimeout(SOCKET_TIMEOUT)
        responded = False
        try:
            req = read_request(conn)
            if req is None:
                return
            self._check_origin(req)
            result = self._route(req)
            if isinstance(result, FileResult):
                try:
                    f = open(result.path, "rb")
                except OSError:
                    raise HttpError(404, "NOT_FOUND", "Không đọc được tệp")
                with f:
                    responded = True
                    send_file(conn, result, f)
            else:
                responded = True
                send_json(conn, *result)
        except HttpError as e:
            if not responded:
                self._try_send(conn, e.status, error_payload(e.code, e.message))
        except (socket.timeout, ConnectionError):
            pass  # trình duyệt đóng tab / mạng chậm: bỏ qua
        except Exception:
            log.exception("Lỗi xử lý request")
            if not responded:
                self._try_send(conn, 500, error_payload("INTERNAL", "Lỗi nội bộ"))
        finally:
            conn.close()

    def _check_origin(self, req: Request) -> None:
        """Chặn trang web lạ gọi API qua trình duyệt của người dùng.

        - Host phải là địa chỉ của bridge (chống DNS rebinding).
        - Request có Origin (trình duyệt gửi khi cross-site / POST) phải cùng origin.
        """
        allowed = {f"{h}:{self.port}" for h in ("127.0.0.1", "localhost", self.host)}
        host = req.headers.get("host", "").lower()
        if host not in allowed:
            raise HttpError(403, "FORBIDDEN", "Host không hợp lệ")
        origin = req.headers.get("origin")
        if origin is not None and urlsplit(origin).netloc.lower() != host:
            raise HttpError(403, "FORBIDDEN", "Origin không hợp lệ")

    @staticmethod
    def _try_send(conn, status, payload) -> None:
        try:
            send_json(conn, status, payload)
        except OSError:
            pass

    def _route(self, req: Request):
        if not req.path.startswith("/api/"):
            if req.method != "GET":
                raise HttpError(405, "METHOD_NOT_ALLOWED", "Chỉ hỗ trợ GET cho tệp tĩnh")
            return self._static(req.path)

        if req.path.startswith("/api/files/"):
            if req.method != "GET":
                raise HttpError(405, "METHOD_NOT_ALLOWED", "Chỉ hỗ trợ GET")
            handler = lambda r: self.h_download(r, r.path[len("/api/files/"):])  # noqa: E731
        else:
            handler = self.routes.get((req.method, req.path))
            if handler is None:
                if any(path == req.path for _, path in self.routes):
                    raise HttpError(405, "METHOD_NOT_ALLOWED", f"{req.method} không hỗ trợ")
                raise HttpError(404, "NOT_FOUND", "Không có endpoint này")

        try:
            return handler(req)
        except ClientError as e:
            raise HttpError(CLIENT_ERROR_STATUS.get(e.code, 500), e.code, str(e))
        except NotImplementedError as e:
            raise HttpError(501, "NOT_IMPLEMENTED", str(e) or "Tính năng chưa có")
        except ValueError as e:
            raise HttpError(400, "BAD_REQUEST", str(e))

    def _static(self, path: str) -> FileResult:
        rel = path.removeprefix("/static/").lstrip("/") or "index.html"
        full = os.path.realpath(os.path.join(self.static_dir, rel))
        # realpath gộp "../" và symlink, sau đó mới kiểm tra còn nằm trong web/ không.
        if not full.startswith(self.static_dir + os.sep) or not os.path.isfile(full):
            raise HttpError(404, "NOT_FOUND", "Không tìm thấy tệp")
        return FileResult(full, guess_type(full))

    # ---- endpoint -----------------------------------------------------------

    def h_status(self, req):
        return ok({**self.client.status(), "last_seq": self.events.last_seq})

    def h_login(self, req):
        body = req.json()
        username = body.get("username")
        password = body.get("password", "")
        if password is None:
            password = ""
        users = self.client.login(username, password)
        return ok({"username": self.client.username, "state": self.client.state.value,
                   "users": users})

    def h_logout(self, req):
        req.read_body()
        self.client.logout()
        self.messenger.reset()
        return ok({"state": self.client.state.value})

    def h_users(self, req):
        return ok({"users": self.client.online_users})

    def h_get_messages(self, req):
        peer = req.query.get("peer") or GLOBAL
        limit = _int_param(req.query, "limit", 50, 1, 500)
        return ok({"messages": [m.to_dict() for m in self.messenger.store.history(peer, limit)]})

    def h_send_message(self, req):
        body = req.json()
        to = body.get("to")
        text = body.get("text")
        if to is not None and not isinstance(to, str):
            raise ValueError("'to' phải là chuỗi hoặc null")
        if not isinstance(text, str):
            raise ValueError("Thiếu 'text'")
        if to and to == self.client.username:
            raise ValueError("Không thể nhắn riêng cho chính mình")
        msg = self.messenger.send(to or None, text)
        return ok({"message": msg.to_dict()})

    def h_events(self, req):
        since = _int_param(req.query, "since", 0, 0, None)
        timeout = _float_param(req.query, "timeout", DEFAULT_POLL_TIMEOUT, 0, MAX_POLL_TIMEOUT)
        events, next_seq, reset = self.events.wait_since(since, timeout)
        return ok({"events": events, "next": next_seq, "reset": reset})

    def h_upload(self, req):
        try:
            if self.client.file_service is None:
                raise NotImplementedError("file_transfer.py chưa sẵn sàng")
            self.client.require_online()
            if "x-filename" not in req.headers:
                raise ValueError("Thiếu header X-Filename")
            filename = safe_filename(unquote(req.headers["x-filename"]))
            to = unquote(req.headers.get("x-to", "")).strip() or None
            if to and to == self.client.username:
                raise ValueError("Không thể gửi tệp cho chính mình")
            if req.content_length > MAX_UPLOAD:
                raise HttpError(413, "TOO_LARGE",
                                f"Tệp vượt quá {MAX_UPLOAD // (1024 * 1024)} MB")
        except Exception:
            req.drain()
            raise

        os.makedirs(self.upload_dir, exist_ok=True)
        path = os.path.join(self.upload_dir, f"{uuid.uuid4().hex}_{filename}")
        size = 0
        try:
            with open(path, "wb") as f:
                for chunk in req.iter_body(MAX_UPLOAD):
                    f.write(chunk)
                    size += len(chunk)
        except BaseException:
            _remove_quietly(path)
            raise

        # ⏳ PENDING: file_transfer.py thật sẽ nhận (path, filename, to) và chạy nền.
        transfer_id = self.client.file_service.send_file(path, filename, to)
        return ok({"transfer_id": transfer_id, "filename": filename, "size": size})

    def h_download(self, req, transfer_id: str):
        if self.client.file_service is None:
            raise NotImplementedError("file_transfer.py chưa sẵn sàng")
        found = self.client.file_service.get_received(transfer_id)
        if not found or not os.path.isfile(found[0]):
            raise HttpError(404, "NOT_FOUND", "Không có tệp này hoặc chưa nhận xong")
        path, filename = found
        return FileResult(path, guess_type(filename), download_name=filename)


def _int_param(query: dict, name: str, default: int, lo: int, hi: int | None) -> int:
    raw = query.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ValueError(f"'{name}' phải là số nguyên")
    if value < lo:
        raise ValueError(f"'{name}' phải ≥ {lo}")
    return min(value, hi) if hi is not None else value


def _float_param(query: dict, name: str, default: float, lo: float, hi: float) -> float:
    raw = query.get(name)
    if raw is None or raw == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        raise ValueError(f"'{name}' phải là số")
    if not lo <= value <= hi:  # cũng loại NaN
        raise ValueError(f"'{name}' phải trong khoảng {lo}–{hi}")
    return value


def _remove_quietly(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


# ============================================================================
# main
# ============================================================================

def parse_addr(text: str) -> tuple[str, int]:
    host, sep, port = text.rpartition(":")
    if not sep or not host or not port.isdigit():
        raise argparse.ArgumentTypeError("Dạng host:port, ví dụ 127.0.0.1:9000")
    return host, int(port)


def main() -> None:
    ap = argparse.ArgumentParser(description="Client chat + HTTP bridge cho giao diện web")
    ap.add_argument("--server", type=parse_addr, default=("127.0.0.1", 9000),
                    help="địa chỉ server chat (mặc định 127.0.0.1:9000)")
    ap.add_argument("--http-host", default="127.0.0.1")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--web-dir", default=os.path.join(BASE_DIR, "web"))
    ap.add_argument("--upload-dir", default=os.path.join(BASE_DIR, "uploads"))
    ap.add_argument("--mock", action="store_true",
                    help="dùng server/file transfer giả trong dev_mock.py")
    ap.add_argument("--mock-fail-rate", type=float, default=0.0,
                    help="tỉ lệ bỏ MSG_ACK khi --mock, để thử trạng thái FAILED")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    events = EventQueue()
    if args.mock:
        try:
            from dev_mock import MockFileService, MockServerTransport
        except ImportError:
            ap.error("--mock cần dev_mock.py (file chỉ dùng khi dev, không có trong repo)")
        transport_factory = lambda: MockServerTransport(fail_rate=args.mock_fail_rate)  # noqa: E731
    else:
        transport_factory = make_real_transport

    client = ChatClient(args.server, transport_factory, on_event=events.push)
    messenger = Messenger(client, on_event=events.push)
    if args.mock:
        client.file_service = MockFileService(events.push,
                                              download_dir=os.path.join(BASE_DIR, "downloads"))
    # ⏳ PENDING: khi file_transfer.py xong → client.file_service = FileTransferService(...)

    bridge = HttpBridge(client, messenger, events, args.http_host, args.http_port,
                        static_dir=args.web_dir, upload_dir=args.upload_dir)
    try:
        bridge.serve_forever()
    except KeyboardInterrupt:
        log.info("Đang tắt...")
    finally:
        bridge.shutdown()
        client.logout()
        messenger.shutdown()


if __name__ == "__main__":
    main()
