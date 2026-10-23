"""Server giả lập CHỈ dùng cho test/demo của ``file_transfer.py``.

KHÔNG phải server.py và không thay phần chuyển tiếp tệp của Người 2. Chỉ làm
tối thiểu những gì 1b_protocol_spec.md §7 mô tả để client có bên kia mà trao
đổi: thêm ``from``, mở luồng mới về người nhận, chuyển gói qua lại, báo lỗi
khi một bên rời đi. Không kiểm tra offer, không giới hạn bộ đệm, không timeout.
"""
import os
import sys
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_transfer import is_file_packet  # noqa: E402
from protocol import AppError, PacketType, decode_json, encode_json  # noqa: E402

_FINAL = (PacketType.FILE_REJECT, PacketType.FILE_RESULT, PacketType.ERROR)


class FakeFileServer:
    def __init__(self, transport, users: dict):
        self.transport = transport
        self.users = dict(users)          # peer_id -> user_id đang online
        self.links = {}                   # (peer, stream) -> ((peer, stream) bên kia, transfer_id, bên kia là người gửi?)
        self.outbox = deque()             # (leg, kind, payload, đóng luồng sau khi tới?)
        self.close_after = {}             # delivery_id -> leg

    def handle_packet(self, peer, stream, kind, payload) -> bool:
        if not is_file_packet(stream, kind):
            return False
        link = self.links.get((peer, stream))
        if link is None:
            if kind == PacketType.FILE_OFFER:
                self._open(peer, stream, decode_json(payload))
            return True
        other, _, _ = link
        final = kind in _FINAL
        if final:
            self._unlink((peer, stream))
        self._send(other, kind, payload, final)
        return True

    def handle_delivery(self, delivery_id) -> bool:
        leg = self.close_after.pop(delivery_id, None)
        if leg is not None:
            self._close(leg)
        self.flush()
        return leg is not None

    def handle_failure(self, delivery_id, _code=None) -> bool:
        return self.handle_delivery(delivery_id)

    def handle_peer_closed(self, peer, _reason=None) -> bool:
        self.users.pop(peer, None)
        for leg, (other, tid, other_is_sender) in list(self.links.items()):
            if leg[0] != peer or leg not in self.links:
                continue
            self._unlink(leg)
            if other_is_sender:
                body = {"transfer_id": tid, "status": "failed", "error_code": "USER_OFFLINE"}
                self._send(other, PacketType.FILE_RESULT, encode_json(body), True)
            else:
                body = {"code": "USER_OFFLINE", "message": "offline", "reference_id": tid}
                self._send(other, PacketType.ERROR, encode_json(body), True)
        return True

    def flush(self):
        while self.outbox:
            leg, kind, payload, final = self.outbox[0]
            try:
                did = self.transport.send(leg[0], leg[1], kind, payload)
            except AppError as exc:
                if exc.code == "QUEUE_FULL":
                    return
                did = None                # peer/luồng đã đóng: bỏ gói
            self.outbox.popleft()
            if did is not None and final:
                self.close_after[did] = leg

    def _open(self, peer, stream, offer):
        target = next((p for p, u in self.users.items() if u == offer.get("to")), None)
        if target is None:
            body = {"transfer_id": offer.get("transfer_id"), "status": "failed",
                    "error_code": "USER_OFFLINE"}
            self._send((peer, stream), PacketType.FILE_RESULT, encode_json(body), True)
            return
        out = (target, self.transport.allocate_stream(target))
        tid = offer.get("transfer_id")
        self.links[(peer, stream)] = (out, tid, False)
        self.links[out] = ((peer, stream), tid, True)
        offer["from"] = self.users[peer]
        self._send(out, PacketType.FILE_OFFER, encode_json(offer), False)

    def _send(self, leg, kind, payload, final):
        self.outbox.append((leg, kind, payload, final))
        self.flush()

    def _unlink(self, leg):
        """Bỏ cả hai chiều ánh xạ, đóng luồng này; luồng kia đóng sau gói cuối."""
        link = self.links.pop(leg, None)
        if link is not None:
            self.links.pop(link[0], None)
        self._close(leg)

    def _close(self, leg):
        try:
            self.transport.close_stream(leg[0], leg[1], "TRANSFER_DONE")
        except AppError:
            pass
