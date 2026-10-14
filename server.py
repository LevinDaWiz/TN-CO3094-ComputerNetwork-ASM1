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

Không ghi mật khẩu, khóa phiên hay nonce prefix vào log.
"""

import argparse
import base64
import logging
import os
import socket
import ssl
import sys
import threading
import time

from framing import (MAX_FRAME_LEN, INVALID_PACKET, PAYLOAD_TOO_LARGE,  # noqa: F401
                     ConnectionClosed, recv_frame, send_frame)
from protocol import AppError   # lớp lỗi dùng chung của cả nhóm

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

    ``session_backend`` là đối tượng (thường là module ``sessions``) cung cấp:

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
    p.add_argument("--log-level", default="INFO",
                   choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=args.log_level,
                        format="%(asctime)s %(levelname)s [%(threadName)s] %(message)s")

    import sessions
    if not hasattr(sessions, "authenticate"):
        log.error("sessions.py chưa có authenticate(); chưa chạy được server thật")
        return 1

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

    server = CollabServer(sessions, host=args.host, tcp_port=args.tcp_port,
                          udp_port=args.udp_port, ssl_context=ssl_context,
                          login_timeout=args.login_timeout)
    try:
        server.serve_forever()
    except OSError as exc:
        log.error("Không mở được cổng %s:%d: %s", args.host, args.tcp_port, exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
