"""Tin nhắn chung/riêng trên stream 2 (1b_protocol_spec.md §6).

Không đụng tới socket: gửi qua ChatClient.send_reliable(), nhận CHAT / CHAT_STATUS /
ERROR do luồng worker của ChatClient chuyển tới, báo giao diện qua ChatClient.emit().

Trạng thái tin gửi đi: queued (cục bộ) → accepted (server nhận) → delivered (client
đích ACK), hoặc failed. Tin global có trạng thái riêng cho từng recipient_id.
"""
from __future__ import annotations

import logging
import threading
import uuid
from collections import OrderedDict, deque

from protocol import AppError, PacketType, encode_json

log = logging.getLogger(__name__)

CHAT_STREAM = 2
MAX_TEXT_BYTES = 800
MAX_ID_LEN = 64
TRACK_LIMIT = 10000             # số tin gửi đi / tin nhận được nhớ để theo dõi và chống trùng

SERVER_STATUSES = ("accepted", "delivered", "failed")
FINAL_STATUSES = ("delivered", "failed")


def _is_id(value) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= MAX_ID_LEN


class Messenger:
    def __init__(self, client):
        self.client = client
        self._lock = threading.Lock()
        # message_id → {recipient_id (None = cả tin): status}
        self._outgoing: OrderedDict[str, dict] = OrderedDict()
        self._seen: set[tuple[str, str]] = set()
        self._seen_order: deque = deque()

    # ---- gửi --------------------------------------------------------------------

    def send_message(self, to: str | None, text: str) -> str:
        """Xếp tin vào hàng gửi, trả message_id ngay (không chờ ACK)."""
        me = self.client.require_connected()
        if to is not None:
            if not _is_id(to):
                raise AppError("INVALID_INPUT", "'to' phải là user_id hoặc null")
            if to == me["user_id"]:
                raise AppError("INVALID_INPUT", "Không thể nhắn riêng cho chính mình")
            if self.client.is_online(to) is False:
                raise AppError("USER_OFFLINE", "Người nhận không trực tuyến")
        if not isinstance(text, str) or not text.strip():
            raise AppError("INVALID_INPUT", "Tin nhắn rỗng")
        try:
            size = len(text.encode("utf-8"))
        except UnicodeEncodeError:
            raise AppError("INVALID_INPUT", "Tin nhắn chứa ký tự không hợp lệ") from None
        if size > MAX_TEXT_BYTES:
            raise AppError("PAYLOAD_TOO_LARGE", f"Tin nhắn vượt quá {MAX_TEXT_BYTES} byte UTF-8")

        message_id = str(uuid.uuid4())
        payload = encode_json({"message_id": message_id, "to": to, "text": text})
        with self._lock:
            self._outgoing[message_id] = {}
            while len(self._outgoing) > TRACK_LIMIT:
                self._outgoing.popitem(last=False)
        try:
            self.client.send_reliable(CHAT_STREAM, PacketType.CHAT, payload,
                                      on_result=lambda error: self._on_hop_result(message_id, error))
        except AppError:
            with self._lock:
                self._outgoing.pop(message_id, None)
            raise
        return message_id

    def _on_hop_result(self, message_id: str, error_code: str | None) -> None:
        # ACK chặng client→server không có nghĩa accepted; accepted đến qua CHAT_STATUS.
        if error_code is not None:
            self._set_status(message_id, None, "failed", error_code)

    # ---- nhận (luồng worker của ChatClient) --------------------------------------

    def handle_message(self, peer_id: str, payload: dict) -> None:
        """Gói CHAT từ server: {message_id, from, to, text, sent_at}."""
        message_id, sender, to = payload.get("message_id"), payload.get("from"), payload.get("to")
        text, sent_at = payload.get("text"), payload.get("sent_at")
        if (not _is_id(message_id) or not _is_id(sender) or not (to is None or _is_id(to))
                or not isinstance(text, str) or not isinstance(sent_at, str)):
            log.warning("Bỏ CHAT thiếu hoặc sai trường")
            return
        key = (sender, message_id)
        with self._lock:
            if key in self._seen:
                return                           # trùng: dedupe theo người gửi trong phiên
            self._seen.add(key)
            self._seen_order.append(key)
            if len(self._seen_order) > TRACK_LIMIT:
                self._seen.discard(self._seen_order.popleft())
        self.client.emit("message_received", {"message_id": message_id, "from": sender,
                                              "to": to, "text": text, "sent_at": sent_at})

    def handle_status(self, payload: dict) -> None:
        """Gói CHAT_STATUS: {message_id, recipient_id, status, error_code}."""
        message_id, recipient = payload.get("message_id"), payload.get("recipient_id")
        status, error_code = payload.get("status"), payload.get("error_code")
        if (not _is_id(message_id) or not (recipient is None or _is_id(recipient))
                or status not in SERVER_STATUSES
                or not (error_code is None or isinstance(error_code, str))):
            log.warning("Bỏ CHAT_STATUS thiếu hoặc sai trường")
            return
        self._set_status(message_id, recipient, status, error_code)

    def handle_error(self, error: dict) -> None:
        """ERROR có reference_id là tin của mình → tin đó failed."""
        reference_id = error.get("reference_id")
        if reference_id:
            self._set_status(reference_id, None, "failed", error.get("code"))

    def reset(self) -> None:
        """Gọi khi kết thúc phiên."""
        with self._lock:
            self._outgoing.clear()
            self._seen.clear()
            self._seen_order.clear()

    # ---- nội bộ -------------------------------------------------------------------

    def _set_status(self, message_id: str, recipient: str | None, status: str,
                    error_code: str | None) -> None:
        with self._lock:
            recipients = self._outgoing.get(message_id)
            if recipients is None:
                return                           # không phải tin của mình / đã quên
            old = recipients.get(recipient, "queued")
            # Không lùi trạng thái: delivered/failed là cuối, accepted không lặp lại.
            if old in FINAL_STATUSES or old == status:
                return
            recipients[recipient] = status
        self.client.emit("message_status", {"message_id": message_id, "recipient_id": recipient,
                                            "status": status, "error_code": error_code})
