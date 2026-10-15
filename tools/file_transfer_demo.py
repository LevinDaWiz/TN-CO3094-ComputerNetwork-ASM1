"""Demo truyền tệp A -> server -> B qua UDP socket thật trên localhost.

Không cần đăng nhập TLS: script tự đăng ký khóa phiên cho ba transport, chỉ
để kiểm tra file_transfer.py + reliable_udp.py chạy đa luồng thật. Server ở
đây là server/client giả lập tối giản (tests/fake_*.py), không phải
server.py/client.py. Trong lúc
truyền, A gửi một tin chat để chứng minh luồng tệp không chặn chat.

    python tools/file_transfer_demo.py                  # tệp ngẫu nhiên 5 MiB
    python tools/file_transfer_demo.py --size-mib 100   # tối đa theo đặc tả
    python tools/file_transfer_demo.py --file report.pdf
"""
import argparse
import os
import socket
import sys
import tempfile
import threading
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "tests"))

from fake_client import FakeClient  # noqa: E402
from fake_file_server import FakeFileServer  # noqa: E402
from file_transfer import sha256_file  # noqa: E402
from protocol import CryptoContext, PacketType, encode_json  # noqa: E402
from reliable_udp import ReliableUDP  # noqa: E402


def _udp_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("127.0.0.1", 0))
    return s


def run_demo(source: str, download_dir: str, *, timeout: float = 300.0, log=print) -> dict:
    """Truyền ``source`` từ A sang B; trả số liệu để in hoặc kiểm thử."""
    ss, sa, sb = _udp_socket(), _udp_socket(), _udp_socket()
    server = ReliableUDP(ss, role="server")
    clients = {"A": ReliableUDP(sa), "B": ReliableUDP(sb)}
    for (name, transport), sock, session_id in zip(clients.items(), (sa, sb), (11, 22)):
        c2s, s2c, pc, ps = os.urandom(32), os.urandom(32), os.urandom(4), os.urandom(4)
        transport.register_peer("server", session_id, ss.getsockname(),
                                CryptoContext(c2s, pc), CryptoContext(s2c, ps))
        server.register_peer(name, session_id, sock.getsockname(),
                             CryptoContext(s2c, ps), CryptoContext(c2s, pc))

    fake_server = FakeFileServer(server, {"A": "u01", "B": "u02"})

    def server_payload(peer, stream, kind, payload):
        if not fake_server.handle_packet(peer, stream, kind, payload) and kind == PacketType.CHAT:
            server.send("B" if peer == "A" else "A", 2, PacketType.CHAT, payload)
    server.on_payload(server_payload)
    server.on_delivery(fake_server.handle_delivery)
    server.on_failure(fake_server.handle_failure)
    server.on_peer_closed(fake_server.handle_peer_closed)

    offered, finished = threading.Event(), threading.Event()
    chat_at = []
    last_shown = [-1]

    def on_event(kind, data):
        if kind == "file_offer":
            offered.set()
        elif kind == "file_progress" and data["direction"] == "incoming":
            step = int(data["progress"] // 10)
            if step != last_shown[0]:
                last_shown[0] = step
                log(f"  B nhận {data['progress']:5.1f}% ({data['bytes_done']}/{data['total_bytes']} byte)")
        elif kind == "file_status" and data["status"] in ("completed", "failed", "rejected"):
            if data["direction"] == "outgoing":
                finished.set()

    managers = {
        name: FakeClient(transport, download_dir=os.path.join(download_dir, name),
                         on_event=on_event,
                         on_chat=lambda data: chat_at.append((time.monotonic(), data["text"]))).files
        for name, transport in clients.items()
    }
    for transport in (server, *clients.values()):
        transport.start()

    try:
        start = time.monotonic()
        tid = managers["A"].offer_file("u02", source)
        if not offered.wait(5):
            raise RuntimeError("B không nhận được FILE_OFFER")
        managers["B"].accept_transfer(tid)
        time.sleep(0.2)
        clients["A"].send("server", 2, PacketType.CHAT, encode_json(
            {"message_id": "00000000-0000-4000-8000-000000000001", "to": "u02",
             "text": "Chat trong lúc đang truyền tệp"}))
        finished.wait(timeout)
        elapsed = time.monotonic() - start
        sent = managers["A"].get_transfer(tid)
        received = managers["B"].get_transfer(tid)
        result = {"sender": sent["status"], "receiver": received["status"],
                  "error": sent["error_code"] or received["error_code"],
                  "size": sent["size"], "seconds": elapsed, "hash_ok": False,
                  "chat_before_done": bool(chat_at) and chat_at[0][0] < start + elapsed,
                  "chat_latency": chat_at[0][0] - start if chat_at else None, "path": None}
        if received["status"] == "completed":
            path = managers["B"].get_download_path(tid)
            result["path"] = path
            result["hash_ok"] = sha256_file(path) == sha256_file(source)
        return result
    finally:
        for files in managers.values():
            files.close()
        for transport in (*clients.values(), server):
            transport.close()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--size-mib", type=float, default=5, help="kích thước tệp ngẫu nhiên")
    parser.add_argument("--file", help="gửi tệp có sẵn thay vì tệp ngẫu nhiên")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass

    workdir = tempfile.mkdtemp(prefix="cc_files_")
    source = args.file
    if source is None:
        source = os.path.join(workdir, "random.bin")
        with open(source, "wb") as f:
            remaining = int(args.size_mib * 1024 * 1024)
            while remaining:
                block = os.urandom(min(remaining, 1 << 20))
                f.write(block)
                remaining -= len(block)
    print(f"Gửi {source} ({os.path.getsize(source)} byte) từ A sang B qua server...")
    r = run_demo(source, workdir)
    mib = r["size"] / 1048576
    print(f"Người gửi: {r['sender']}, người nhận: {r['receiver']}, lỗi: {r['error']}")
    print(f"SHA-256 khớp: {r['hash_ok']}  | lưu tại: {r['path']}")
    if r["seconds"] > 0:
        print(f"{mib:.2f} MiB trong {r['seconds']:.1f}s = {mib / r['seconds']:.2f} MiB/s")
    if r["chat_latency"] is not None:
        print(f"Chat tới B sau {r['chat_latency']:.2f}s, trước khi tệp xong: {r['chat_before_done']}")
    return 0 if r["hash_ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
