"""Quản lý tài khoản và phiên đăng nhập phía server (Người 2).

Trạng thái hiện tại: chưa có logic phiên. Phần tài khoản demo và registry phiên
sẽ được bổ sung ở bước tiếp theo theo hợp đồng trong ``1a_api.md`` mục 5::

    authenticate(username: str, password: str) -> Session
    bind_udp(session_id: int, address: tuple) -> None
    list_online_users() -> list[dict]
    remove_session(session_id: int) -> None

``AppError`` dùng chung cả nhóm được định nghĩa trong ``protocol.py``; module này
import lại để nơi khác có thể viết ``from sessions import AppError`` mà vẫn là
cùng một lớp (``except AppError`` bắt được lỗi từ mọi module).
"""

from protocol import AppError  # noqa: F401  (dùng lại, không định nghĩa lớp thứ hai)
