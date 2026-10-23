"""HTTP server cục bộ viết bằng socket thô, phục vụ giao diện web (1a_api.md).

- Phục vụ HTML/CSS/JS trong web/ (giao diện của người 5) và API JSON cùng origin.
- Chỉ gọi facade ChatClient (client.py); không chạm tới TLS/UDP.
- Request thay đổi trạng thái phải có X-Local-Token lấy từ GET /api/bootstrap.

Chạy:  python3 http_bridge.py                     (server 127.0.0.1, CA certs/ca.crt)
       python3 http_bridge.py --server-host 192.168.1.10 --http-port 8081
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import mimetypes
import os
import re
import secrets
import socket
import threading
from dataclasses import dataclass
from urllib.parse import parse_qs, quote, unquote, urlsplit

from client import API_VERSION, MAX_FILE_SIZE, ChatClient, CursorExpired
from file_transfer import FileTransferManager
from protocol import AppError

log = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MAX_HEADER_BYTES = 16 * 1024
MAX_JSON_BODY = 64 * 1024
SOCKET_TIMEOUT = 15.0
MAX_POLL_TIMEOUT = 25.0
CHUNK = 64 * 1024

STATUS_TEXT = {200: "OK", 201: "Created", 202: "Accepted", 400: "Bad Request",
               401: "Unauthorized", 403: "Forbidden", 404: "Not Found",
               405: "Method Not Allowed", 409: "Conflict", 413: "Payload Too Large",
               500: "Internal Server Error", 501: "Not Implemented",
               503: "Service Unavailable"}

# AppError.code → HTTP status (1a_api.md §1). Mã không có trong bảng là lỗi đầu vào → 400.
ERROR_STATUS = {
    "NOT_AUTHENTICATED": 401,
    "FORBIDDEN": 403, "INVALID_LOCAL_TOKEN": 403,
    "NOT_FOUND": 404, "TRANSFER_NOT_FOUND": 404,
    "INVALID_STATE": 409, "USER_OFFLINE": 409, "EVENT_CURSOR_EXPIRED": 409,
    "TRANSFER_NOT_COMPLETED": 409,
    "PAYLOAD_TOO_LARGE": 413, "FILE_TOO_LARGE": 413,
    "NOT_IMPLEMENTED": 501,
    "SERVER_UNAVAILABLE": 503, "QUEUE_FULL": 503, "TRANSPORT_CLOSED": 503,
    # Từ ReliableUDP khi peer vừa bị đóng / hết bộ đếm, trước khi client kịp về disconnected.
    "INVALID_SESSION": 503, "STREAM_CLOSED": 503, "SESSION_EXHAUSTED": 503,
}

TRANSFER_ID = r"(?P<transfer_id>[A-Za-z0-9-]{1,64})"


# ============================================================================
# HTTP tối giản trên socket
# ============================================================================

class HttpError(Exception):
    def __init__(self, status: int, code: str, message: str, extra: dict | None = None):
        super().__init__(message)
        self.status, self.code, self.message, self.extra = status, code, message, extra or {}


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
        self.body_read = False

    @property
    def content_length(self) -> int:
        if "chunked" in self.headers.get("transfer-encoding", "").lower():
            raise HttpError(400, "INVALID_INPUT", "Không hỗ trợ Transfer-Encoding: chunked")
        raw = self.headers.get("content-length", "0")
        if not (raw.isascii() and raw.isdigit()):
            raise HttpError(400, "INVALID_INPUT", "Content-Length không hợp lệ")
        return int(raw)

    def iter_body(self, limit: int):
        """Đọc body theo từng khúc, dừng đúng ở Content-Length."""
        if self.body_read:
            return
        self.body_read = True
        remaining = self.content_length
        if remaining > limit:
            raise HttpError(413, "PAYLOAD_TOO_LARGE", f"Body vượt quá {limit} byte")
        if self._leftover:
            chunk, self._leftover = self._leftover[:remaining], b""
            remaining -= len(chunk)
            yield chunk
        while remaining > 0:
            chunk = self.conn.recv(min(CHUNK, remaining))
            if not chunk:
                raise HttpError(400, "INVALID_INPUT", "Kết nối đóng khi chưa gửi đủ body")
            remaining -= len(chunk)
            yield chunk

    def json(self) -> dict:
        body = b"".join(self.iter_body(MAX_JSON_BODY))
        if not body.strip():
            return {}
        try:
            data = json.loads(body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HttpError(400, "INVALID_INPUT", "Body không phải JSON hợp lệ")
        if not isinstance(data, dict):
            raise HttpError(400, "INVALID_INPUT", "Body JSON phải là object")
        return data

    def drain(self) -> None:
        """Đọc bỏ body còn lại trước khi trả lỗi; đóng socket khi còn dữ liệu chưa đọc
        sẽ gửi RST và trình duyệt có thể không nhận được response lỗi."""
        try:
            for _ in self.iter_body(MAX_FILE_SIZE):
                pass
        except (HttpError, OSError):
            pass


def read_request(conn: socket.socket) -> Request | None:
    """Đọc request line + header. Trả None nếu client đóng kết nối trước khi gửi gì."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > MAX_HEADER_BYTES:
            raise HttpError(400, "INVALID_INPUT", "Header quá lớn")
        chunk = conn.recv(4096)
        if not chunk:
            if buf:
                raise HttpError(400, "INVALID_INPUT", "Request bị cắt ngang")
            return None
        buf += chunk
    head, leftover = buf.split(b"\r\n\r\n", 1)
    if len(head) > MAX_HEADER_BYTES:
        raise HttpError(400, "INVALID_INPUT", "Header quá lớn")

    lines = head.decode("iso-8859-1").split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        raise HttpError(400, "INVALID_INPUT", "Request line không hợp lệ")
    method, target, _version = parts

    headers = {}
    for line in lines[1:]:
        name, sep, value = line.partition(":")
        if not sep:
            raise HttpError(400, "INVALID_INPUT", "Header không hợp lệ")
        headers[name.strip().lower()] = value.strip()
    return Request(conn, method.upper(), target, headers, leftover)


def _head_bytes(status: int, headers: list[tuple[str, str]]) -> bytes:
    lines = [f"HTTP/1.1 {status} {STATUS_TEXT.get(status, 'Unknown')}"]
    lines += [f"{k}: {v}" for k, v in headers]
    lines += ["Connection: close", "Cache-Control: no-store", "", ""]
    return "\r\n".join(lines).encode("iso-8859-1")


def send_json(conn: socket.socket, status: int, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    conn.sendall(_head_bytes(status, [("Content-Type", "application/json; charset=utf-8"),
                                      ("Content-Length", str(len(body)))]) + body)


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


def guess_type(path: str) -> str:
    ctype = mimetypes.guess_type(path)[0] or "application/octet-stream"
    if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
        ctype += "; charset=utf-8"
    return ctype


def _int_param(query: dict, name: str, default: int) -> int:
    raw = query.get(name, "")
    if raw == "":
        return default
    if not (raw.isascii() and raw.isdigit()):
        raise HttpError(400, "INVALID_INPUT", f"'{name}' phải là số nguyên ≥ 0")
    return int(raw)


def _float_param(query: dict, name: str, default: float, hi: float) -> float:
    raw = query.get(name, "")
    if raw == "":
        return default
    try:
        value = float(raw)
    except ValueError:
        value = -1.0
    if not 0 <= value <= hi:  # cũng loại NaN
        raise HttpError(400, "INVALID_INPUT", f"'{name}' phải trong khoảng 0–{hi:g}")
    return value


# ============================================================================
# Bridge
# ============================================================================

class HttpBridge:
    def __init__(self, client: ChatClient, host: str = "127.0.0.1", port: int = 8080,
                 static_dir: str = os.path.join(BASE_DIR, "web")):
        self.client = client
        self.host, self.port = host, port
        self.static_dir = os.path.realpath(static_dir)
        self.local_token = secrets.token_urlsafe(32)
        self._sock: socket.socket | None = None
        self._stopping = threading.Event()
        self.ready = threading.Event()        # set khi đã listen (port=0 → self.port là cổng thật)

        routes = [
            ("GET", "/api/bootstrap", self.h_bootstrap),
            ("POST", "/api/login", self.h_login),
            ("POST", "/api/logout", self.h_logout),
            ("GET", "/api/status", self.h_status),
            ("GET", "/api/users", self.h_users),
            ("POST", "/api/messages", self.h_send_message),
            ("GET", "/api/events", self.h_events),
            ("POST", "/api/files/offers", self.h_create_offer),
            ("GET", "/api/files", self.h_list_files),
            ("PUT", f"/api/files/{TRANSFER_ID}/content", self.h_upload_content),
            ("POST", f"/api/files/{TRANSFER_ID}/accept", self.h_accept),
            ("POST", f"/api/files/{TRANSFER_ID}/reject", self.h_reject),
            ("GET", f"/api/files/{TRANSFER_ID}/download", self.h_download),
        ]
        self.routes = [(method, re.compile(pattern), handler) for method, pattern, handler in routes]

    # ---- vòng accept --------------------------------------------------------

    def serve_forever(self) -> None:
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(64)
        self._sock.settimeout(1.0)   # để vòng lặp kiểm tra cờ dừng định kỳ
        self.port = self._sock.getsockname()[1]
        self.ready.set()
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
        req = None
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
                status, data = result
                responded = True
                send_json(conn, status, {"ok": True, "data": data})
        except HttpError as e:
            if not responded:
                if req is not None:
                    req.drain()
                self._send_error(conn, e)
        except (socket.timeout, ConnectionError):
            pass  # trình duyệt đóng tab / mạng chậm: bỏ qua
        except Exception:
            log.exception("Lỗi xử lý request")
            if not responded:
                self._send_error(conn, HttpError(500, "INTERNAL", "Lỗi nội bộ"))
        finally:
            conn.close()

    @staticmethod
    def _send_error(conn, e: HttpError) -> None:
        try:
            send_json(conn, e.status, {"ok": False, "error": {"code": e.code,
                                                              "message": e.message, **e.extra}})
        except OSError:
            pass

    def _check_origin(self, req: Request) -> None:
        """Host phải là địa chỉ của bridge (chống DNS rebinding); Origin nếu có phải cùng origin."""
        allowed = {f"{h}:{self.port}" for h in ("127.0.0.1", "localhost", self.host)}
        host = req.headers.get("host", "").lower()
        if host not in allowed:
            raise HttpError(403, "FORBIDDEN", "Host không hợp lệ")
        origin = req.headers.get("origin")
        if origin is not None and urlsplit(origin).netloc.lower() != host:
            raise HttpError(403, "FORBIDDEN", "Origin không hợp lệ")

    def _check_token(self, req: Request) -> None:
        token = req.headers.get("x-local-token", "")
        if not hmac.compare_digest(token.encode(), self.local_token.encode()):
            raise HttpError(403, "INVALID_LOCAL_TOKEN", "Local token sai hoặc thiếu")

    def _route(self, req: Request):
        if not req.path.startswith("/api/"):
            if req.method != "GET":
                raise HttpError(405, "METHOD_NOT_ALLOWED", "Chỉ hỗ trợ GET cho tệp tĩnh")
            return self._static(req.path)

        path_exists = False
        for method, pattern, handler in self.routes:
            match = pattern.fullmatch(req.path)
            if match is None:
                continue
            path_exists = True
            if method != req.method:
                continue
            if method != "GET":
                self._check_token(req)
            try:
                return handler(req, **match.groupdict())
            except CursorExpired as e:
                raise HttpError(409, e.code, e.message, {"current_cursor": e.current_cursor})
            except AppError as e:
                raise HttpError(ERROR_STATUS.get(e.code, 400), e.code, e.message)
        if path_exists:
            raise HttpError(405, "METHOD_NOT_ALLOWED", f"{req.method} không hỗ trợ")
        raise HttpError(404, "NOT_FOUND", "Không có endpoint này")

    def _static(self, path: str) -> FileResult:
        rel = path.removeprefix("/static/").lstrip("/") or "index.html"
        full = os.path.realpath(os.path.join(self.static_dir, rel))
        # realpath gộp "../" và symlink, sau đó mới kiểm tra còn nằm trong web/ không.
        if not full.startswith(self.static_dir + os.sep) or not os.path.isfile(full):
            raise HttpError(404, "NOT_FOUND", "Không tìm thấy tệp")
        return FileResult(full, guess_type(full))

    # ---- endpoint: phiên và tin nhắn ---------------------------------------

    def h_bootstrap(self, req):
        return 200, {"local_token": self.local_token, "api_version": API_VERSION}

    def h_login(self, req):
        body = req.json()
        self.client.login(body.get("username"), body.get("password"))
        return 202, {"status": "connecting"}

    def h_logout(self, req):
        req.json()
        state = self.client.logout()
        return (200 if state == "disconnected" else 202), {"status": state}

    def h_status(self, req):
        return 200, self.client.get_status()

    def h_users(self, req):
        return 200, self.client.list_users()

    def h_send_message(self, req):
        body = req.json()
        message_id = self.client.send_message(body.get("to"), body.get("text"))
        return 202, {"message_id": message_id, "status": "queued"}

    def h_events(self, req):
        # timeout là phần mở rộng (long-poll); mặc định 0 = polling thường như 1a_api.md.
        after = _int_param(req.query, "after", 0)
        timeout = _float_param(req.query, "timeout", 0.0, MAX_POLL_TIMEOUT)
        return 200, self.client.get_events(after, timeout=timeout)

    # ---- endpoint: tệp ---------------------------------------------------------

    def h_create_offer(self, req):
        body = req.json()
        transfer_id = self.client.create_upload(body.get("to"), body.get("filename"),
                                                body.get("size"))
        return 201, {"transfer_id": transfer_id, "status": "awaiting_upload"}

    def h_list_files(self, req):
        return 200, {"transfers": self.client.list_transfers()}

    def h_upload_content(self, req, transfer_id):
        if "content-length" not in req.headers:
            raise HttpError(400, "INVALID_INPUT", "Thiếu Content-Length")
        length = req.content_length
        if length > MAX_FILE_SIZE:
            raise HttpError(413, "FILE_TOO_LARGE", "Tệp vượt quá 100 MiB")
        path = self.client.begin_upload(transfer_id, length)

        # Ghi thẳng xuống tệp tạm và băm SHA-256 theo từng khúc, không nạp cả tệp vào RAM.
        digest = hashlib.sha256()
        try:
            with open(path, "wb") as f:
                for chunk in req.iter_body(MAX_FILE_SIZE):
                    f.write(chunk)
                    digest.update(chunk)
            self.client.submit_uploaded_file(transfer_id, path, digest.hexdigest())
        except BaseException as e:
            self.client.abort_upload(transfer_id, getattr(e, "code", "IO_ERROR"))
            raise
        return 202, {"transfer_id": transfer_id, "status": "offered"}

    def h_accept(self, req, transfer_id):
        req.json()
        self.client.accept_transfer(transfer_id)
        return 202, {"transfer_id": transfer_id, "status": "accepted"}

    def h_reject(self, req, transfer_id):
        reason = req.json().get("reason") or "Không nhận tệp"
        if not isinstance(reason, str):
            raise HttpError(400, "INVALID_INPUT", "'reason' phải là chuỗi")
        self.client.reject_transfer(transfer_id, reason)
        return 202, {"transfer_id": transfer_id, "status": "rejected"}

    def h_download(self, req, transfer_id):
        path = self.client.get_download_path(transfer_id)
        return FileResult(path, "application/octet-stream",
                          download_name=os.path.basename(path))


# ============================================================================
# main
# ============================================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="Python client + HTTP bridge cho giao diện web")
    ap.add_argument("--server-host", default="127.0.0.1", help="địa chỉ server chat")
    ap.add_argument("--tcp-port", type=int, default=9000, help="cổng TCP/TLS đăng nhập")
    ap.add_argument("--ca-file", default=os.path.join(BASE_DIR, "certs", "ca.crt"),
                    help="chứng chỉ CA để xác minh TLS của server (mặc định certs/ca.crt)")
    ap.add_argument("--server-name", help="tên trong chứng chỉ server (mặc định = --server-host)")
    ap.add_argument("--http-host", default="127.0.0.1")
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--web-dir", default=os.path.join(BASE_DIR, "web"))
    ap.add_argument("--download-dir", default=os.path.join(BASE_DIR, "downloads"),
                    help="nơi lưu tệp nhận được (mặc định downloads/)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    client = ChatClient(args.server_host, args.tcp_port, ca_file=args.ca_file,
                        server_hostname=args.server_name)
    client.attach_file_service(FileTransferManager(client, download_dir=args.download_dir))

    bridge = HttpBridge(client, args.http_host, args.http_port, static_dir=args.web_dir)
    try:
        bridge.serve_forever()
    except KeyboardInterrupt:
        log.info("Đang tắt...")
    finally:
        bridge.shutdown()
        client.close()


if __name__ == "__main__":
    main()
