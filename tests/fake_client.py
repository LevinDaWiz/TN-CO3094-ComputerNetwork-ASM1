"""Client giả lập CHỈ dùng cho test/demo của ``file_transfer.py``.

Không phải client.py. Mô phỏng đúng phần ``ChatClient`` (Người 3) mà module tệp
dùng: ``send_reliable(stream, type, payload, on_result)``, ``allocate_stream()``,
``emit()``, ``close_stream()``; chuyển FILE_* và ERROR trên luồng >=3 vào
``files.handle_packet`` và gọi ``files.handle_disconnect`` khi mất phiên.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from file_transfer import FileTransferManager, is_file_packet  # noqa: E402
from protocol import AppError, PacketType, decode_json  # noqa: E402

SERVER_PEER = "server"


class FakeClient:
    def __init__(self, transport, *, on_event=None, on_chat=None, **file_options):
        self.transport = transport
        self.on_event = on_event or (lambda kind, data: None)
        self.on_chat = on_chat or (lambda data: None)
        self.chats = []
        self._callbacks = {}            # delivery_id -> on_result(error | None)
        self.files = FileTransferManager(self, **file_options)
        transport.on_payload(self._on_payload)
        transport.on_delivery(lambda did: self._resolve(did, None))
        transport.on_failure(self._resolve)
        transport.on_peer_closed(lambda peer, reason: self.files.handle_disconnect(reason))

    # ----- phần module tệp dùng -----

    def send_reliable(self, stream_id, packet_type, payload, on_result=None):
        delivery_id = self.transport.send(SERVER_PEER, stream_id, packet_type, payload)
        if on_result is not None:
            self._callbacks[delivery_id] = on_result
        return delivery_id

    def allocate_stream(self):
        return self.transport.allocate_stream(SERVER_PEER)

    def close_stream(self, stream_id, reason="STREAM_CLOSED"):
        try:
            self.transport.close_stream(SERVER_PEER, stream_id, reason)
        except AppError:
            pass

    def emit(self, kind, data):
        self.on_event(kind, data)

    # ----- callback của transport -----

    def _on_payload(self, peer, stream_id, packet_type, payload):
        if is_file_packet(stream_id, packet_type):
            self.files.handle_packet(peer, stream_id, packet_type, payload)
        elif packet_type == PacketType.CHAT:
            self.chats.append(decode_json(payload))
            self.on_chat(self.chats[-1])

    def _resolve(self, delivery_id, error):
        callback = self._callbacks.pop(delivery_id, None)
        if callback is not None:
            callback(error)
