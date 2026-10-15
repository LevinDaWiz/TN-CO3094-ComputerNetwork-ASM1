"""Transport UDP phía server (Người 2), mở rộng ``reliable_udp.ReliableUDP``.

Vấn đề: ``ReliableUDP.receive_datagram`` bỏ mọi gói của phiên chưa
``register_peer``. Nhưng gói UDP_BIND đầu tiên luôn đến đúng lúc đó, vì server
chỉ biết địa chỉ UDP của client SAU khi nhận UDP_BIND (1b_protocol_spec.md mục 2).

Giải pháp, không sửa file của Người 1: lớp con ``ServerUDP`` thêm
``on_unknown_datagram(callback)``. Gói có header hợp lệ nhưng phiên chưa đăng ký
được chuyển cho callback; mọi gói khác đi nguyên đường của ``ReliableUDP``.

Luồng UDP_BIND phía server::

    def on_unknown(raw, address):
        session = sessions.get_session(peek_header(raw).session_id)
        if session is None or session.bound:
            return                                   # bỏ, không ACK
        rx = CryptoContext(session.c2s_key, session.c2s_nonce_prefix)
        packet = decode_packet(raw, rx)              # sai khóa/tag -> AppError: bỏ
        if packet.header.packet_type != PacketType.UDP_BIND or packet.header.stream_id != 1:
            return
        sessions.bind_udp(session.session_id, address)          # địa chỉ nguồn thực tế
        transport.register_peer(str(session.session_id), session.session_id, address,
                                CryptoContext(session.s2c_key, session.s2c_nonce_prefix), rx)
        transport.receive_datagram(raw, address)     # lần này được ACK + giao lên on_payload

Lưu ý: mỗi phiên chỉ tạo MỘT CryptoContext gửi (tx) cho mỗi chiều; tạo lại sẽ dùng
lại nonce từ 0 và phá AES-GCM.
"""

import logging

from protocol import AppError, peek_header
from reliable_udp import ReliableUDP

log = logging.getLogger("server_udp")


class ServerUDP(ReliableUDP):
    """``ReliableUDP`` + callback cho gói của phiên chưa đăng ký (dùng cho UDP_BIND).

    Khởi tạo y như ``ReliableUDP`` (thường ``ServerUDP(sock, role="server")``).
    Chỉ dùng thuộc tính công khai ``peers`` của lớp cha, không đụng lock/biến nội bộ.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._on_unknown = None

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
