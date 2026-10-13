"""Gửi/nhận tin nhắn chung (broadcast) và riêng (unicast), theo dõi trạng thái gửi.

Lớp xử lý dữ liệu: không đụng tới socket. Gửi packet qua ChatClient, nhận packet
qua handler mà ChatClient gọi từ luồng nhận. Mọi thay đổi được báo lên giao diện
qua callback on_event(type, data) — xem docs/api.md §4.
"""

import threading
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum

GLOBAL = "global"          # khoá hội thoại cho kênh chung
MAX_TEXT_LEN = 4000
ACK_TIMEOUT = 10.0         # giây chờ MSG_ACK từ server trước khi coi là FAILED
HISTORY_LIMIT = 500        # số tin giữ lại cho mỗi hội thoại


class MessageStatus(str, Enum):
    PENDING = "PENDING"    # vừa tạo, chưa giao cho transport
    SENT = "SENT"          # transport đã nhận, đang chờ server xác nhận
    ACKED = "ACKED"        # server đã nhận và chuyển tiếp
    FAILED = "FAILED"      # transport lỗi, server từ chối hoặc quá ACK_TIMEOUT


@dataclass
class Message:
    sender: str
    to: str | None         # None = tin chung
    text: str
    msg_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ts: float = field(default_factory=time.time)
    status: MessageStatus = MessageStatus.PENDING
    direction: str = "out"  # "out" = mình gửi, "in" = nhận

    def peer(self, me: str) -> str:
        """Khoá hội thoại nhìn từ phía `me`: 'global' hoặc tên người bên kia."""
        if self.to is None:
            return GLOBAL
        return self.to if self.sender == me else self.sender

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


class MessageStore:
    """Lịch sử tin nhắn trong RAM, an toàn khi dùng từ nhiều luồng."""

    def __init__(self, limit: int = HISTORY_LIMIT):
        self._limit = limit
        self._lock = threading.Lock()
        self._by_peer: dict[str, list[Message]] = {}
        self._by_id: dict[str, Message] = {}

    def add(self, msg: Message, me: str) -> None:
        with self._lock:
            conv = self._by_peer.setdefault(msg.peer(me), [])
            conv.append(msg)
            self._by_id[msg.msg_id] = msg
            if len(conv) > self._limit:
                dropped = conv.pop(0)
                self._by_id.pop(dropped.msg_id, None)

    def get(self, msg_id: str) -> Message | None:
        with self._lock:
            return self._by_id.get(msg_id)

    def set_status(self, msg_id: str, status: MessageStatus) -> Message | None:
        """Đổi trạng thái tin gửi đi. Trả về tin nếu có thay đổi, None nếu không.

        Không cho lùi trạng thái: tin đã ACKED/FAILED thì giữ nguyên (ví dụ MSG_ACK
        đến muộn sau khi đã timeout).
        """
        with self._lock:
            msg = self._by_id.get(msg_id)
            if msg is None or msg.status in (MessageStatus.ACKED, MessageStatus.FAILED):
                return None
            msg.status = status
            return msg

    def history(self, peer: str = GLOBAL, limit: int = 50) -> list[Message]:
        with self._lock:
            return list(self._by_peer.get(peer, [])[-limit:])

    def clear(self) -> None:
        with self._lock:
            self._by_peer.clear()
            self._by_id.clear()


class Messenger:
    """Cầu nối giữa ChatClient (packet) và giao diện (Message + sự kiện)."""

    def __init__(self, client, on_event=None, ack_timeout: float = ACK_TIMEOUT):
        self.client = client
        self.store = MessageStore()
        self._on_event = on_event or (lambda type_, data: None)
        self._ack_timeout = ack_timeout
        self._timers: dict[str, threading.Timer] = {}
        self._timers_lock = threading.Lock()

        client.register_handler("MSG", self._on_msg)
        client.register_handler("MSG_ACK", self._on_msg_ack)
        client.register_handler("MSG_FAIL", self._on_msg_fail)

    # ---- gửi -------------------------------------------------------------

    def send_global(self, text: str) -> Message:
        return self.send(None, text)

    def send_private(self, to: str, text: str) -> Message:
        if not to:
            raise ValueError("Thiếu người nhận")
        return self.send(to, text)

    def send(self, to: str | None, text: str) -> Message:
        """Gửi tin; trả về ngay sau khi giao cho transport (status SENT hoặc FAILED).

        Raise ValueError nếu nội dung không hợp lệ, NotOnlineError nếu chưa đăng nhập.
        """
        text = (text or "").strip()
        if not text:
            raise ValueError("Tin nhắn rỗng")
        if len(text) > MAX_TEXT_LEN:
            raise ValueError(f"Tin nhắn dài quá {MAX_TEXT_LEN} ký tự")
        self.client.require_online()

        me = self.client.username
        msg = Message(sender=me, to=to or None, text=text)
        self.store.add(msg, me)

        packet = {"type": "MSG", "msg_id": msg.msg_id, "to": msg.to,
                  "text": msg.text, "ts": msg.ts}
        try:
            self.client.send_packet(packet)
        except OSError as e:
            self._update(msg.msg_id, MessageStatus.FAILED, reason=str(e))
            return msg

        # Đặt timer trước khi chuyển SENT để MSG_ACK đến rất nhanh vẫn huỷ được timer.
        self._start_timer(msg.msg_id)
        self.store.set_status(msg.msg_id, MessageStatus.SENT)
        return msg

    # ---- nhận (gọi từ luồng nhận của ChatClient) --------------------------

    def _on_msg(self, packet: dict) -> None:
        try:
            msg = Message(sender=str(packet["sender"]), to=packet.get("to") or None,
                          text=str(packet["text"]),
                          msg_id=str(packet.get("msg_id") or uuid.uuid4().hex),
                          ts=float(packet.get("ts") or time.time()),
                          status=MessageStatus.ACKED, direction="in")
        except (KeyError, TypeError, ValueError):
            self._on_event("error", {"code": "BAD_PACKET", "message": "Gói MSG không hợp lệ"})
            return
        if self.store.get(msg.msg_id) is not None:
            return  # trùng (server gửi lại) → bỏ qua
        self.store.add(msg, self.client.username)
        self._on_event("message", msg.to_dict())

    def _on_msg_ack(self, packet: dict) -> None:
        self._update(packet.get("msg_id"), MessageStatus.ACKED)

    def _on_msg_fail(self, packet: dict) -> None:
        self._update(packet.get("msg_id"), MessageStatus.FAILED, reason=packet.get("reason"))

    # ---- nội bộ ----------------------------------------------------------

    def _update(self, msg_id, status: MessageStatus, reason=None) -> None:
        if not msg_id:
            return
        self._cancel_timer(msg_id)
        if self.store.set_status(msg_id, status) is not None:
            data = {"msg_id": msg_id, "status": status.value}
            if reason:
                data["reason"] = reason
            self._on_event("message_status", data)

    def _start_timer(self, msg_id: str) -> None:
        t = threading.Timer(self._ack_timeout, self._update,
                            args=(msg_id, MessageStatus.FAILED, "Hết thời gian chờ xác nhận"))
        t.daemon = True
        with self._timers_lock:
            self._timers[msg_id] = t
        t.start()

    def _cancel_timer(self, msg_id: str) -> None:
        with self._timers_lock:
            t = self._timers.pop(msg_id, None)
        if t:
            t.cancel()

    def reset(self) -> None:
        """Gọi khi đăng xuất: huỷ timer và xoá lịch sử để người dùng sau không thấy."""
        self.shutdown()
        self.store.clear()

    def shutdown(self) -> None:
        with self._timers_lock:
            timers, self._timers = list(self._timers.values()), {}
        for t in timers:
            t.cancel()
