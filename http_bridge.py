from urllib.parse import urlparse, parse_qs
import json, secrets, threading, time, uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

STORE = {
    "local_token": secrets.token_hex(16),
    "state": "disconnected",
    "user": None,
    "last_error": None,
    "users": [{"user_id": "u01", "username": "Hen"}],
    "revision": 1,
    "events": [],
    "next_id": 1,
    "transfers": {},
}
LOCK = threading.Lock()

def push_event(etype, data):
    with LOCK:
        eid = STORE["next_id"]; STORE["next_id"] += 1
        STORE["events"].append({"event_id": eid, "type": etype, "data": data})
        del STORE["events"][:-10000]
        return eid
    
def find_or_add_user(username):
    with LOCK:
        for u in STORE["users"]:
            if u["username"]==username:
                return u
        uid = f"u{len(STORE['users'])+1:02d}"
        user = {"user_id": uid, "username": username}
        STORE["users"].append(user)
        STORE["revision"] += 1
        return user

def make_transfer(to, filename, size):
    tid = str(uuid.uuid4())
    with LOCK:
        STORE["transfers"][tid] = {
            "transfer_id": tid, "direction": "outgoing", 
            "peer_id": to, "filename": filename, "size": size,
             "status": "awaiting_upload", "bytes_done": 0,
             "progress": 0, "error_code": None, "content":b"",}
    return tid

def ok(data):
    return {"ok": True, "data": data}

def err(code,msg):
    return {"ok": False, "error": {"code": code, "message": msg}}

class Handler(BaseHTTPRequestHandler):
    server_version = "CCBridge/1.0"

    def log_message(self, *args):
        pass
    
    def send_json(self, code, obj):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def read_json_body(self):
        length = self.headers.get("Content-Length")
        if length is None:
            return None, (400, err("MISSING_LENGTH", "Thiếu Content-Length"))
        try:
            n = int(length)
        except ValueError:
            return None, (400, err("INVALID_LENGTH", "Content-Length sai"))
        if n > 64 * 1024:
            return None, (413, err("TOO_LARGE", "Body JSON quá lớn"))
        raw = self.rfile.read(n) if n>0 else b""
        if not raw:
            return {}, None
        try:
            text = raw.decode("utf-8").strip()
            # curl.exe trên Windows không bóc nháy đơn như Linux,
            # body tới nơi kèm cặp nháy ngoài: '{"a":1}' -> bóc giúp.
            if len(text) >= 2 and text[0] == "'" and text[-1] == "'":
                text = text[1:-1]
            return json.loads(text), None
        except (UnicodeError, ValueError):
            return None, (400, err("INVALID_JSON", "Body không phải JSON"))

    def check_token(self):
        return self.headers.get("X-Local-Token") == STORE["local_token"]
    
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/bootstrap":
            self.send_json(200,ok({"local_token": STORE["local_token"], "api_version": "1.0"}))
            return
        if path == "/api/status":
            with LOCK:
                self.send_json(200,ok({"state": STORE["state"], "user": STORE["user"], "last_error": STORE["last_error"],}))
            return
        if path == "/api/events":
            qs = parse_qs(parsed.query)
            try:
                after = int(qs.get("after", [0])[0])
            except ValueError:
                self.send_json(400, err("INVALID_CURSOR", "after phải là số nguyên"))
                return
            with LOCK:
                events = STORE["events"]
                if events and after < events[0]["event_id"] - 1:
                    self.send_json(409, err("EVENT_CURSOR_EXPIRED", "Cursor quá cũ, tại lại trạng thái"))
                    return
                fresh = [e for e in events if e["event_id"] > after][:100]
                cursor = fresh[-1]["event_id"] if fresh else after
            self.send_json(200, ok({"events": fresh, "next_cursor": cursor}))
            return
        if path == "/api/users":
            with LOCK:
                if STORE["state"] != "connected":
                    self.send_json(401, err("NOT_LOGGED_IN", "Chưa đăng nhập"))
                    return
                self.send_json(200, ok({"revision": STORE["revision"], "users": STORE["users"],}))
            return
        if path =="/api/files":
            with LOCK:
                items = [{k: v for k, v in t.items()if k !="content"} for t in STORE["transfers"].values()]
            self.send_json(200, ok({"transfers": items}))
            return
        if path.startswith("/api/files/") and path.endswith("/download"):
            tid = path.split("/")[3]
            with LOCK:
                t = STORE["transfers"].get(tid)
                if t is None or t["status"] not in ("offered", "accepted"):
                    self.send_json(409, err("NOT_COMPLETED", "Chưa hoàn tất"))
                    return
                body = t["content"]
                filename = t["filename"]
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_json(404, err("NOT_FOUND", "Không tìm thấy"))

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/api/login":
            body, error = self.read_json_body()
            if error:
                self.send_json(error[0], error[1])
                return
            if not self.check_token():
                self.send_json(403, err("FORBIDDEN", "Sai local token"))
                return
            username = (body.get("username") or "").strip()
            password = (body.get("password") or "")
            if not username or not password:
                self.send_json(400, err("INVALID_INPUT", "Thiếu username/password"))
                return
            with LOCK:
                if STORE["state"] in ("connecting", "connected"):
                    self.send_json(409, err("ALREADY_CONNECTED", "Đang kết nối hoặc đã kết nối"))
                    return
            STORE["state"] = "connecting"
            STORE["last_error"] = None
            threading.Thread(target=fake_connect, args=(username,), daemon=True).start()
            self.send_json(200, ok({"message": "Đang kết nối..."}))
            return

        if path == "/api/logout":
            if not self.check_token():
                self.send_json(403, err("FORBIDDEN", "Sai local token"))
                return
            self.read_json_body()
            with LOCK:
                if STORE["state"]== "disconnected":
                    self.send_json(200, ok({"status": "disconnected"}))
                    return
                STORE["state"] = "disconnected"
                STORE["user"] = None
            push_event("connection_changed", {"state": "disconnected", "user": None, "error_code": None})
            self.send_json(200, ok({"status": "disconnected"}))
            return
        if path =="/api/messages":
            if not self.check_token():
                self.send_json(403, err("FORBIDDEN", "Sai local token"))
                return
            body, error = self.read_json_body()
            if error:
                self.send_json(error[0], error[1])
                return
            import uuid as uuid_mod
            with LOCK:
                if STORE["state"] != "connected":
                    self.send_json(401, err("NOT_LOGGED_IN", "Chưa đăng nhập"))
                    return
            to = body.get("to")
            text = body.get("text") or ""
            if not isinstance(text, str) or not text.strip() or len(text.encode("utf-8"))>800:
                self.send_json(400, err("INVALID_INPUT", "text rỗng hoặc vượt 800 byte UTF-8"))
                return
            mid = str(uuid_mod.uuid4())
            push_event("message_status", {"message_id":mid, "recipient_id": to, "status": "delivered", "error_code": None,})
            self.send_json(202, ok({"message_id": mid, "status": "queued"}))
            return
        if path == "/api/files/offers":
            if not self.check_token():
                self.send_json(403, err("FORBIDDEN", "Sai local token"))
                return
            body, error = self.read_json_body()
            if error:
                self.send_json(error[0], error[1])
                return
            with LOCK:
                if STORE["state"] != "connected":
                    self.send_json(401, err("NOT_LOGGED_IN", "Chưa đăng nhập"))
                    return
            to = body.get("to")
            filename = (body.get("filename") or "").strip()
            size = body.get("size")
            if not to or not filename or not isinstance(size, int) or size < 0 or size > 100*1024*1024:
                self.send_json(400, err("INVALID_INPUT", "to/filename/size sai"))
                return
            tid = make_transfer(to, filename, size)
            self.send_json(201, ok({"transfer_id": tid, "status": "awaiting_upload"}))
            return
        if path.startswith("/api/files/") and (path.endswith("/accept") or path.endswith("/reject")):
            if not self.check_token():
                self.send_json(403, err("FORBIDDEN", "Sai local token"))
                return
            tid=path.split("/")[3]
            with LOCK:
                t = STORE["transfers"].get(tid)
                if t is None:
                    self.send_json(404, err("NOT_FOUND", "Không có transfer"))
                    return
            status = "accepted" if path.endswith("/accept") else "rejected"
            with LOCK:
                t["status"] = status
            push_event("file_status", {"transfer_id": tid, "direction": t["direction"], "status": status, "error_code": None})
            self.send_json(200, ok({"transfer_id": tid, "status": status}))
            return
        self.send_json(404, err("NOT_FOUND", "Không tìm thấy"))

    def do_PUT(self):
        parsed =urlparse(self.path)
        parts = parsed.path.strip("/").split("/")
        if len(parts) != 4 or parts[0] != "api" or parts[1] != "files" or parts[3] != "content":
            self.send_json(404, err("NOT_FOUND", "Không tìm thấy"))
            return
        if not self.check_token():
            self.send_json(403, err("FORBIDDEN", "Sai local token"))
            return
        tid = parts[2]
        length =self.headers.get("Content-Length")
        if length is None:
            self.send_json(400, err("MISSING_LENGTH", "Thiếu Content-Length"))
            return
        n = int(length)
        raw = self.rfile.read(n) if n>0 else b""
        with LOCK:
            t = STORE["transfers"].get(tid)
            if t is None:
                self.send_json(404, err("NOT_FOUND", "Không tìm thấy transfer_id"))
                return
            if t["status"] != "awaiting_upload":
                self.send_json(409, err("INVALID_STATE", "Transfer không ở trạng thái upload"))
                return
            if len(raw) != t["size"]:
                t["status"] = "failed"
                t["error_code"] = "INVALID_INPUT"
                self.send_json(409, err("SIZE_MISMATCH", "Kích thước body khác metadata"))
                return
            t["content"] = raw
            t["status"] = "offered"
            t["bytes_done"] = len(raw)
            t["progress"] = 100 if raw else 0
        push_event("file_offer", {"transfer_id": tid, "from": "u01", "filename": t["filename"], "size": t["size"]})
        push_event("file_progress", {"transfer_id": tid, "direction": "outgoing", "bytes_done": t["bytes_done"], "total_bytes": t["size"], "progress": t["progress"]})
        self.send_json(202, ok({"transfer_id": tid, "status": "offered"}))

def fake_connect(username):
    user = find_or_add_user(username)
    time.sleep(1.0)
    with LOCK:
        if STORE["state"] != "connecting":
            return
        STORE["state"] = "connected"
        STORE["user"] = user
        STORE["last_error"] = None
    push_event("connection_changed", {"state": "connected", "user": user, "error_code": None})
    push_event("users_updated", {"revision": STORE["revision"], "users": STORE["users"]})

if __name__ == "__main__":
    push_event("connection_changed", {"state": "disconnected", "user":None, "error_code": None})
    server = ThreadingHTTPServer(("127.0.0.1", 8080), Handler)
    print("Stub bridge: http://127.0.0.1:8080 token=", STORE["local_token"])
    server.serve_forever()

    
