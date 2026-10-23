"""Selective Repeat over UDP with independent ordered streams.

Manual mode: receive_datagram(), tick(), dispatch_events() for deterministic tests.
Socket mode: start() runs an I/O worker and a separate callback worker. Callbacks
must hand work to application queues quickly. No application callback runs locked.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
import logging
import socket
import threading
import time
import uuid
from typing import Callable

from protocol import (AppError, CryptoProvider, Flags, Header, Packet, PacketType,
                      UNRELIABLE_TYPES, UINT32_MAX, decode_ack, decode_packet,
                      encode_ack, encode_json, encode_packet, peek_header)

log = logging.getLogger(__name__)


class FixedWindow:
    """Flow control only; this is NOT a congestion-control algorithm."""
    def __init__(self, window: int = 16):
        self.cwnd = float(window)
    def on_ack(self):
        pass
    def on_timeout(self):
        pass


class AIMD:
    """Optional basic peer-wide congestion control, not BBR or CUBIC.

    Packet-count window: slow start, additive increase, multiplicative decrease.
    Retransmissions are timed separately. Plug in the confirmed controller later.
    """
    def __init__(self, window: int = 16):
        self.maximum = window
        self.cwnd = min(4.0, float(window))
        self.ssthresh = float(window)
    def on_ack(self):
        increment = 1.0 if self.cwnd < self.ssthresh else 1.0 / self.cwnd
        self.cwnd = min(float(self.maximum), self.cwnd + increment)
    def on_timeout(self):
        self.ssthresh = max(2.0, self.cwnd / 2)
        self.cwnd = 1.0


@dataclass
class Pending:
    delivery_id: str
    wire: bytes
    deadline: float | None = None
    rto: float = 0.5
    retries: int = 0


@dataclass
class Stream:
    next_seq: int = 1
    send_base: int = 1
    pending: dict[int, Pending] = field(default_factory=dict)
    acked: set[int] = field(default_factory=set)
    recv_base: int = 1
    received: dict[int, Packet] = field(default_factory=dict)
    closed: bool = False


@dataclass
class Peer:
    session_id: int
    address: tuple
    tx_crypto: CryptoProvider
    rx_crypto: CryptoProvider
    controller: object
    streams: dict[int, Stream] = field(default_factory=dict)
    control_seq: int = 1
    next_file_stream: int = 3
    last_seen: float = 0.0
    next_heartbeat: float | None = None
    rr_cursor: int = 0


class ReliableUDP:
    def __init__(self, sock: socket.socket | None = None, *,
                 send_datagram: Callable[[bytes, tuple], None] | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 role: str = "client", window: int = 16, initial_rto: float = 0.5,
                 max_rto: float = 4.0, max_retries: int = 8,
                 max_queue_per_stream: int = 256, max_pending: int = 4096,
                 max_events: int = 4096, max_streams_per_peer: int = 128,
                 max_peers: int = 64, max_batch: int = 64,
                 congestion_factory: Callable[[int], object] = AIMD,
                 heartbeat_interval: float = 5.0, peer_timeout: float = 15.0):
        if role not in ("client", "server") or not 1 <= window <= 16:
            raise ValueError("Invalid role/window")
        if not 0 < initial_rto <= max_rto or max_retries < 0:
            raise ValueError("Invalid retry settings")
        if min(max_queue_per_stream, max_pending, max_events,
               max_streams_per_peer, max_peers, max_batch) < 1:
            raise ValueError("Queue limits must be positive")
        if heartbeat_interval <= 0 or peer_timeout <= heartbeat_interval:
            raise ValueError("Invalid heartbeat timing")
        if sock is None and send_datagram is None:
            raise ValueError("Supply a UDP socket or send_datagram")
        self.sock = sock
        self._send_wire = send_datagram or (lambda wire, addr: sock.sendto(wire, addr))
        self.clock, self.role, self.window = clock, role, window
        self.initial_rto, self.max_rto, self.max_retries = initial_rto, max_rto, max_retries
        self.max_queue_per_stream, self.max_pending = max_queue_per_stream, max_pending
        self.max_events, self.max_streams = max_events, max_streams_per_peer
        self.max_peers, self.max_batch = max_peers, max_batch
        self.congestion_factory = congestion_factory
        self.heartbeat_interval, self.peer_timeout = heartbeat_interval, peer_timeout
        self.peers: dict[str, Peer] = {}
        self._sessions: dict[int, str] = {}
        self._events = deque()
        # Each outstanding send reserves one notification slot. Notifications
        # remain part of max_pending until dispatch, bounding a slow consumer.
        self._notifications: dict[str, str | None] = {}
        self._peer_notifications = deque()
        self._unreliable = deque()
        self._lock = threading.RLock()
        self._callbacks = {"payload": None, "delivery": None, "failure": None, "peer_closed": None}
        self._stop = threading.Event()
        self._threads = []
        self._closed = False

    def on_payload(self, callback):
        with self._lock:
            self._callbacks["payload"] = callback

    def on_delivery(self, callback):
        with self._lock:
            self._callbacks["delivery"] = callback

    def on_failure(self, callback):
        with self._lock:
            self._callbacks["failure"] = callback

    def on_peer_closed(self, callback):
        """Optional callback(peer_id, reason), including idle heartbeat expiry."""
        with self._lock:
            self._callbacks["peer_closed"] = callback

    def register_peer(self, peer_id: str, session_id: int, address: tuple,
                      tx_crypto: CryptoProvider, rx_crypto: CryptoProvider) -> None:
        """Keys come from session/security module. Address must already be trusted.

        For UDP_BIND, server session setup supplies the expected source address;
        authenticated dynamic initial binding belongs to sessions.py, not here.
        Never replace keys inside a live peer; use a new peer/session instead.
        """
        if not isinstance(session_id, int) or not 1 <= session_id < 2**64:
            raise AppError("INVALID_SESSION", "Invalid session id")
        with self._lock:
            self._ensure_open()
            if peer_id in self.peers or session_id in self._sessions:
                raise AppError("INVALID_SESSION", "Peer/session already registered")
            if len(self.peers) + len(self._peer_notifications) >= self.max_peers:
                raise AppError("QUEUE_FULL", "Peer registry full")
            self.peers[peer_id] = Peer(session_id, address, tx_crypto, rx_crypto,
                                       self.congestion_factory(self.window),
                                       next_file_stream=3 if self.role == "client" else 4,
                                       last_seen=self.clock())
            self._sessions[session_id] = peer_id

    def activate_peer(self, peer_id: str) -> None:
        """Enable heartbeat/expiry only AFTER UDP_BIND_OK."""
        with self._lock:
            peer = self._peer(peer_id)
            peer.last_seen = self.clock()
            peer.next_heartbeat = peer.last_seen + self.heartbeat_interval

    def allocate_stream(self, peer_id: str) -> int:
        with self._lock:
            peer = self._peer(peer_id)
            stream_id = peer.next_file_stream
            while stream_id in peer.streams:
                stream_id += 2
            if stream_id > UINT32_MAX:
                raise AppError("SESSION_EXHAUSTED", "File stream id exhausted")
            self._stream(peer, stream_id)
            peer.next_file_stream = stream_id + 2
            return stream_id

    def send(self, peer_id: str, stream_id: int, packet_type: int, payload: bytes) -> str:
        """Enqueue only. QUEUE_FULL means retry later; no sequence is consumed."""
        with self._lock:
            self._ensure_open()
            peer = self._peer(peer_id)
            try:
                kind = PacketType(packet_type)
            except (ValueError, TypeError) as exc:
                raise AppError("INVALID_PACKET", "Unknown packet type") from exc
            delivery_id = str(uuid.uuid4())
            if kind == PacketType.ACK:
                raise AppError("INVALID_PACKET", "ACK is generated by transport")
            if kind in UNRELIABLE_TYPES:
                if stream_id != 0:
                    raise AppError("INVALID_PACKET", "Unreliable packet requires stream 0")
                if len(self._unreliable) >= self.max_events:
                    raise AppError("QUEUE_FULL", "Control queue full")
                wire = self._control_wire(peer, kind, payload)
                self._unreliable.append((wire, peer.address))
                return delivery_id
            # Validate type/stream/payload before creating stream state.
            h = Header(kind, peer.session_id, stream_id, 1)
            from protocol import validate_header, validate_payload, MAX_PLAINTEXT
            validate_header(h)
            if not isinstance(payload, bytes) or len(payload) > MAX_PLAINTEXT:
                raise AppError("PAYLOAD_TOO_LARGE", "Payload must be bytes <=1149")
            validate_payload(kind, payload)
            stream = self._stream(peer, stream_id)
            if stream.closed:
                raise AppError("STREAM_CLOSED", "Never reuse a closed stream id")
            if len(stream.pending) >= self.max_queue_per_stream or self._outstanding() >= self.max_pending:
                raise AppError("QUEUE_FULL", "Reliable send queue full")
            if stream.next_seq > UINT32_MAX:
                raise AppError("SESSION_EXHAUSTED", "Sequence exhausted; reconnect")
            seq = stream.next_seq
            wire = encode_packet(Header(kind, peer.session_id, stream_id, seq), payload, peer.tx_crypto)
            stream.pending[seq] = Pending(delivery_id, wire, rto=self.initial_rto)
            stream.next_seq += 1
            return delivery_id

    def receive_datagram(self, raw: bytes, address: tuple) -> bool:
        """Returns False for invalid/unaccepted input; such data is never ACKed."""
        ack_wire = None
        with self._lock:
            if self._closed:
                return False
            try:
                h = peek_header(raw)
                peer_id = self._sessions.get(h.session_id)
                peer = self.peers.get(peer_id)
                if peer is None or address != peer.address:
                    return False
                packet = decode_packet(raw, peer.rx_crypto)
            except AppError:
                return False
            peer.last_seen = self.clock()
            kind = PacketType(h.packet_type)
            if kind == PacketType.ACK:
                stream_id, seq = decode_ack(packet.payload)
                stream = peer.streams.get(stream_id)
                pending = stream.pending.get(seq) if stream else None
                if pending is not None and pending.deadline is not None:
                    del stream.pending[seq]
                    stream.acked.add(seq)
                    self._notifications[pending.delivery_id] = None
                    peer.controller.on_ack()
                    while stream.send_base in stream.acked:
                        stream.acked.remove(stream.send_base)
                        stream.send_base += 1
                return True
            if kind == PacketType.HEARTBEAT:
                # Liveness handled internally; avoid replay flooding event queue.
                return True
            stream = peer.streams.get(h.stream_id)
            if stream is None:
                # New remote file streams must have the other endpoint's parity.
                if h.stream_id >= 3 and h.stream_id % 2 == (1 if self.role == "client" else 0):
                    return False
                try:
                    stream = self._stream(peer, h.stream_id)
                except AppError:
                    return False
            if stream.closed:
                return False
            if h.seq < stream.recv_base:
                ack_wire = self._control_wire(peer, PacketType.ACK, encode_ack(h.stream_id, h.seq))
            elif h.seq >= stream.recv_base + self.window:
                return False
            else:
                # Reserve storage before ACK. Duplicate bytes are never delivered twice.
                if h.seq not in stream.received:
                    stream.received[h.seq] = packet
                ack_wire = self._control_wire(peer, PacketType.ACK, encode_ack(h.stream_id, h.seq))
                self._drain_receive(peer_id, h.stream_id, stream)
        if ack_wire is not None:
            self._emit(ack_wire, address)  # immediate high-priority ACK, outside lock
        return True

    def tick(self) -> None:
        """Bounded work per peer; round robin files, reserve control/chat turns."""
        outgoing = []
        now = self.clock()
        with self._lock:
            if self._closed:
                return
            while self._unreliable and len(outgoing) < self.max_batch:
                outgoing.append(self._unreliable.popleft())
            for peer_id, peer in list(self.peers.items()):
                if peer.next_heartbeat is not None:
                    if now - peer.last_seen >= self.peer_timeout:
                        self._close_peer_locked(peer_id, "PEER_TIMEOUT")
                        continue
                    if now >= peer.next_heartbeat:
                        outgoing.append((self._control_wire(peer, PacketType.HEARTBEAT, encode_json({})), peer.address))
                        peer.next_heartbeat = now + self.heartbeat_interval
                for sid, stream in peer.streams.items():
                    self._drain_receive(peer_id, sid, stream)
                inflight = sum(p.deadline is not None for s in peer.streams.values() for p in s.pending.values())
                files = [sid for sid, s in peer.streams.items() if sid >= 3 and not s.closed]
                if files:
                    offset = peer.rr_cursor % len(files)
                    files = files[offset:] + files[:offset]
                    peer.rr_cursor = (peer.rr_cursor + 1) % len(files)
                order = [sid for sid in (1, 2) if sid in peer.streams] + files
                used = 0
                # Detect exhaustion first: don't send more packets on a doomed stream.
                for sid in order:
                    stream = peer.streams[sid]
                    if any(p.deadline is not None and now >= p.deadline and p.retries >= self.max_retries
                           for p in stream.pending.values()):
                        self._close_stream_locked(peer_id, sid, "DELIVERY_TIMEOUT")
                if peer_id not in self.peers:
                    continue
                inflight = sum(p.deadline is not None for s in peer.streams.values() for p in s.pending.values())
                # At most one loss reduction per peer per tick.
                reduced = False
                while used < self.max_batch:
                    progress = False
                    for sid in order:
                        stream = peer.streams[sid]
                        if stream.closed:
                            continue
                        candidate = None
                        for seq, p in stream.pending.items():
                            if seq >= stream.send_base + self.window:
                                continue
                            if p.deadline is not None and now >= p.deadline:
                                candidate = p
                                if not reduced:
                                    peer.controller.on_timeout()
                                    reduced = True
                                p.retries += 1
                                p.rto = min(self.max_rto, p.rto * 2)
                                break
                            if p.deadline is None:
                                # Reserve two peer-wide slots for session/chat when
                                # cwnd >=3. Files still have progress at cwnd 1/2.
                                cap = max(1, int(peer.controller.cwnd))
                                if sid >= 3 and cap >= 3:
                                    cap -= 2
                                if inflight < cap:
                                    candidate = p
                                    inflight += 1
                                    break
                        if candidate is not None:
                            candidate.deadline = now + candidate.rto
                            outgoing.append((candidate.wire, peer.address))
                            used += 1
                            progress = True
                            if used >= self.max_batch:
                                break
                    if not progress:
                        break
        for wire, address in outgoing:
            self._emit(wire, address)

    def dispatch_events(self, limit: int = 100) -> int:
        """Run callbacks outside all locks. Use one dispatcher per transport."""
        count = 0
        while count < limit:
            with self._lock:
                if self._events:
                    args = self._events.popleft()
                    callback = self._callbacks["payload"]
                elif self._notifications:
                    delivery_id = next(iter(self._notifications))
                    error = self._notifications.pop(delivery_id)
                    callback = self._callbacks["delivery" if error is None else "failure"]
                    args = (delivery_id,) if error is None else (delivery_id, error)
                elif self._peer_notifications:
                    args = self._peer_notifications.popleft()
                    callback = self._callbacks["peer_closed"]
                else:
                    break
            if callback is not None:
                try:
                    callback(*args)
                except Exception:
                    log.exception("Transport callback failed; application must handle its own work")
            count += 1
        return count

    def close_stream(self, peer_id: str, stream_id: int, reason: str = "STREAM_CLOSED") -> None:
        if not isinstance(stream_id, int) or not 1 <= stream_id <= UINT32_MAX:
            raise AppError("INVALID_PACKET", "Invalid reliable stream id")
        with self._lock:
            self._peer(peer_id)
            self._close_stream_locked(peer_id, stream_id, reason)

    def close_peer(self, peer_id: str, reason: str = "PEER_CLOSED") -> None:
        with self._lock:
            self._close_peer_locked(peer_id, reason)

    def start(self) -> None:
        if self.sock is None:
            raise ValueError("start() requires a UDP socket")
        with self._lock:
            self._ensure_open()
            if self._threads:
                return
            self.sock.settimeout(0.01)
            self._threads = [threading.Thread(target=self._io_loop, daemon=True, name="cc-udp"),
                             threading.Thread(target=self._dispatch_loop, daemon=True, name="cc-events")]
            for thread in self._threads:
                thread.start()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            for peer_id in list(self.peers):
                self._close_peer_locked(peer_id, "TRANSPORT_CLOSED")
            self._closed = True
            self._unreliable.clear()
            self._stop.set()
        if self.sock is not None:
            self.sock.close()
        for thread in self._threads:
            if thread is not threading.current_thread():
                thread.join(timeout=1)
        # If invoked inside a callback, dispatcher will finish its current batch.
        if not self._threads or threading.current_thread() not in self._threads:
            self.dispatch_events(self.max_events + self.max_pending + self.max_peers)

    def _peer(self, peer_id):
        peer = self.peers.get(peer_id)
        if peer is None:
            raise AppError("INVALID_SESSION", "Unknown peer")
        return peer

    def _stream(self, peer, stream_id):
        if stream_id not in peer.streams:
            if len(peer.streams) >= self.max_streams:
                raise AppError("QUEUE_FULL", "Stream registry full; reconnect to reclaim ids")
            peer.streams[stream_id] = Stream()
        return peer.streams[stream_id]

    def _ensure_open(self):
        if self._closed:
            raise AppError("TRANSPORT_CLOSED", "Transport closed")

    def _outstanding(self):
        return len(self._notifications) + sum(len(s.pending) for p in self.peers.values() for s in p.streams.values())

    def _control_wire(self, peer, kind, payload):
        if peer.control_seq > UINT32_MAX:
            raise AppError("SESSION_EXHAUSTED", "Control sequence exhausted; reconnect")
        wire = encode_packet(Header(kind, peer.session_id, 0, peer.control_seq,
                                    int(Flags.ENCRYPTED)), payload, peer.tx_crypto)
        peer.control_seq += 1
        return wire

    def _drain_receive(self, peer_id, sid, stream):
        while not stream.closed and stream.recv_base in stream.received and len(self._events) < self.max_events:
            packet = stream.received.pop(stream.recv_base)
            self._events.append((peer_id, sid, packet.header.packet_type, packet.payload))
            stream.recv_base += 1

    def _close_stream_locked(self, peer_id, sid, reason):
        peer = self.peers.get(peer_id)
        if peer is None:
            return
        stream = self._stream(peer, sid)
        stream.closed = True
        stream.received.clear()
        stream.acked.clear()
        for p in stream.pending.values():
            self._notifications[p.delivery_id] = reason
        stream.pending.clear()
        if sid in (1, 2):
            self._close_peer_locked(peer_id, "RECONNECT_REQUIRED")

    def _close_peer_locked(self, peer_id, reason):
        peer = self.peers.pop(peer_id, None)
        if peer is None:
            return
        self._sessions.pop(peer.session_id, None)
        self._peer_notifications.append((peer_id, reason))
        for stream in peer.streams.values():
            for p in stream.pending.values():
                self._notifications[p.delivery_id] = reason
            stream.pending.clear()
            stream.received.clear()
        # Payloads already ACKed remain dispatchable after graceful peer closure.

    def _emit(self, wire, address):
        try:
            self._send_wire(wire, address)
        except OSError:
            # Reliable timers retry the same encrypted bytes. Best-effort controls
            # may drop; never let a transient send failure kill the I/O worker.
            log.debug("UDP send failed", exc_info=True)

    def _io_loop(self):
        while not self._stop.is_set():
            try:
                raw, address = self.sock.recvfrom(1201)
                self.receive_datagram(raw, address)
            except socket.timeout:
                pass
            except OSError:
                if not self._stop.is_set():
                    log.debug("UDP receive failed", exc_info=True)
            except AppError:
                log.debug("Session counter exhausted", exc_info=True)
            try:
                self.tick()
            except AppError:
                log.debug("Session counter exhausted", exc_info=True)

    def _dispatch_loop(self):
        while not self._stop.is_set():
            if self.dispatch_events() == 0:
                self._stop.wait(0.005)
        self.dispatch_events(self.max_events + self.max_pending + self.max_peers)
