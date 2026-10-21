"""Transport UDP phía server: ``ReliableUDP`` (Người 1) + nhận gói của phiên chưa đăng ký."""

import logging

from protocol import AppError, peek_header
from reliable_udp import ReliableUDP

log = logging.getLogger("server_udp")


class ServerUDP(ReliableUDP):
    """``ReliableUDP`` + callback cho gói của phiên chưa đăng ký (dùng cho UDP_BIND).

    Vì sao cần: ``ReliableUDP.receive_datagram`` bỏ mọi gói của phiên chưa
    ``register_peer``, mà gói UDP_BIND đầu tiên luôn đến đúng lúc đó (server chỉ
    biết địa chỉ UDP của client SAU khi nhận UDP_BIND, 1b mục 2). Lớp con này
    chuyển các gói đó cho ``on_unknown_datagram``; mọi gói khác đi nguyên đường
    của ``ReliableUDP``. Không sửa file của Người 1.

    Khởi tạo y như ``ReliableUDP`` (thường ``ServerUDP(sock, role="server")``).
    Chỉ dùng thuộc tính công khai ``peers`` của lớp cha, không đụng lock/biến nội bộ.
    Luồng xử lý UDP_BIND dùng lớp này nằm ở ``server.UdpService._on_unknown``.
    """

    def __init__(self, sock=None, **kwargs):
        super().__init__(sock, **kwargs)
        self._on_unknown = None
        # Đường gửi riêng cho send_raw (cùng nguồn với lớp cha: socket hoặc send_datagram).
        send_datagram = kwargs.get("send_datagram")
        self._raw_send = send_datagram or (lambda wire, address: sock.sendto(wire, address))

    def send_raw(self, wire: bytes, address: tuple) -> None:
        """Gửi một datagram đã mã hóa sẵn, không qua hàng đợi reliable.

        Dùng khi peer đã đóng nhưng vẫn phải trả lời, ví dụ ACK lại LOGOUT bị
        truyền lại trong 60 giây (1b mục 8). Lỗi gửi chỉ ghi log.
        """
        try:
            self._raw_send(wire, address)
        except OSError:
            log.debug("Gửi UDP thô thất bại", exc_info=True)

    def on_unknown_datagram(self, callback) -> None:
        """Đăng ký ``callback(raw, address)`` cho gói của phiên chưa ``register_peer``.

        Chỉ gọi khi header hợp lệ (``peek_header``). Transport không giải mã, không
        lưu, không ACK gói đó. Callback chạy trên thread nhận (ngoài lock của lớp cha)
        nên phải nhanh; lỗi trong callback chỉ được ghi log.
        """
        self._on_unknown = callback

    def receive_datagram(self, raw: bytes, address: tuple) -> bool:
        """Như ``ReliableUDP.receive_datagram``; gói của phiên lạ -> ``on_unknown_datagram``."""
        callback = self._on_unknown
        if callback is not None and self._is_unknown_session(raw):
            try:
                callback(raw, address)
            except Exception:
                log.exception("Callback on_unknown_datagram lỗi")
            return False
        return super().receive_datagram(raw, address)

    def close(self) -> None:
        """Gỡ callback trước, để sau khi đóng không còn gói nào được chuyển lên."""
        self._on_unknown = None
        super().close()

    def _is_unknown_session(self, raw) -> bool:
        """True nếu header hợp lệ nhưng ``session_id`` chưa có peer nào.

        Đọc ``peers`` không khóa: nếu đúng lúc đó phiên vừa được đăng ký thì callback
        chỉ thấy phiên đã bind và bỏ gói (client sẽ truyền lại); nếu phiên vừa bị
        đóng thì lớp cha tự bỏ gói. Cả hai trường hợp đều an toàn.
        """
        try:
            session_id = peek_header(raw).session_id
        except AppError:
            return False          # gói rác: để lớp cha bỏ như bình thường
        return all(peer.session_id != session_id for peer in list(self.peers.values()))
