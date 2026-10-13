# API của HTTP Bridge (client ↔ giao diện web)

> Phiên bản: **v0.1 (draft)** — cần người 5 xác nhận trước **12/10**.
> Phụ trách: client.py / messaging.py / http_bridge.py.

Ký hiệu trạng thái:

| Ký hiệu | Ý nghĩa |
|---|---|
| ✅ READY | Đã code, chạy được khi dev với server giả (`--mock`) |
| ⏳ PENDING | Đã chốt hình dạng request/response, nhưng phần xử lý thật chờ module khác |

---

## 1. Kiến trúc

```
 Trình duyệt (HTML + JS, người 5)
        │  HTTP/1.1 + JSON, chỉ 127.0.0.1
        ▼
 http_bridge.py  ── HTTP server viết bằng socket thô + EventQueue
        │ gọi hàm                       ▲ on_event(type, data)
        ▼                               │
 messaging.py (Messenger)  ─────────────┤
        │                               │
 client.py (ChatClient: trạng thái, luồng nhận, heartbeat)
        │  packet dạng dict
        ▼
 Transport  ⏳ reliable_udp.py + mã hoá + protocol.py (đóng gói bytes)
        │  UDP
        ▼
 server.py / sessions.py
```

- Giao diện **không bao giờ** nói chuyện trực tiếp với server; mọi thứ đi qua bridge.
- Bridge chỉ bind `127.0.0.1` — mỗi người dùng chạy 1 client + 1 bridge trên máy mình.
- Không dùng WebSocket (đề cấm) → JS lấy dữ liệu mới bằng **long-polling** `GET /api/events`.

## 2. Quy ước chung

- Base URL: `http://127.0.0.1:<http_port>` (mặc định `8080`, đổi bằng `--http-port`).
- Request có body: **bắt buộc** `Content-Type: application/json` (trừ upload tệp). Đây là cách
  chống CSRF; vì thế JS phải gọi API từ chính trang do bridge phục vụ (cùng origin), không mở
  `index.html` trực tiếp từ đĩa (`file://`).
- Mọi response API đều có dạng **envelope**:

```json
{ "ok": true,  "data": { ... }, "error": null }
{ "ok": false, "data": null,    "error": { "code": "NOT_ONLINE", "message": "Chưa đăng nhập" } }
```

- JS nên kiểm tra `ok` thay vì chỉ dựa vào HTTP status.
- Thời gian (`ts`) là **Unix time tính bằng giây, kiểu float** (`Date(ts * 1000)` trong JS).

### Mã lỗi

| HTTP | `error.code` | Khi nào |
|---|---|---|
| 400 | `BAD_REQUEST` | JSON hỏng, thiếu trường, trường sai kiểu |
| 401 | `AUTH_FAILED` | Server từ chối đăng nhập |
| 403 | `FORBIDDEN` | Header `Host`/`Origin` không phải của bridge (chặn trang web lạ gọi API) |
| 404 | `NOT_FOUND` | Sai đường dẫn / không có tài nguyên |
| 405 | `METHOD_NOT_ALLOWED` | Sai method |
| 409 | `NOT_ONLINE` | Gọi API cần đăng nhập khi chưa ONLINE |
| 409 | `ALREADY_ONLINE` | Login khi đang ONLINE |
| 409 | `BUSY` | Login khi client đang CONNECTING / RECONNECTING… |
| 413 | `TOO_LARGE` | Body vượt giới hạn |
| 415 | `BAD_REQUEST` | Request có body JSON nhưng thiếu `Content-Type: application/json` |
| 501 | `NOT_IMPLEMENTED` | Tính năng ⏳ PENDING, module phụ thuộc chưa có |
| 502 | `SERVER_UNREACHABLE` | Không kết nối/handshake được tới server chat |
| 500 | `INTERNAL` | Lỗi không lường trước |

## 3. Endpoint

### 3.1 `GET /`, `GET /<path>`, `GET /static/<path>` ✅

Phục vụ `web/index.html` và các tệp trong `web/` (`/app.js` và `/static/app.js` đều trỏ tới
`web/app.js`). Chặn `../`. Người 5 đặt `index.html`, `app.js`, `style.css`… vào thư mục `web/`.
Thư mục `web/` hiện chưa có trong repo — người 5 tạo khi thêm giao diện.

### 3.2 `POST /api/login` ✅ (mock) / ⏳ (server thật)

Nếu chưa kết nối, bridge tự kết nối + handshake rồi mới gửi AUTH.

Request:
```json
{ "username": "alice", "password": "123456" }
```
- `username`: 1–32 ký tự `[A-Za-z0-9_.-]`.
- `password`: chuỗi, có thể rỗng (tuỳ server — ⏳ chờ `sessions.py` chốt cách xác thực).

Response 200:
```json
{ "ok": true, "data": { "username": "alice", "state": "ONLINE", "users": ["alice", "bob"] }, "error": null }
```
Lỗi: 400, 401 `AUTH_FAILED`, 409 `ALREADY_ONLINE`/`BUSY`, 501 (transport thật chưa có), 502 `SERVER_UNREACHABLE`.

### 3.3 `POST /api/logout` ✅

Body rỗng hoặc `{}`. Response: `{ "ok": true, "data": { "state": "DISCONNECTED" } }`.
Gọi khi chưa đăng nhập vẫn trả `ok: true` (idempotent).

### 3.4 `GET /api/status` ✅

```json
{ "ok": true, "data": {
    "state": "ONLINE",
    "username": "alice",
    "server": "127.0.0.1:9000",
    "last_seq": 42
} }
```
`state` ∈ `DISCONNECTED | CONNECTING | CONNECTED | AUTHENTICATING | ONLINE | RECONNECTING | LOGGING_OUT` (xem §5).
Dùng khi mở/tải lại trang để biết đã đăng nhập chưa; `last_seq` dùng làm `since` cho long-poll.

### 3.5 `GET /api/users` ✅

```json
{ "ok": true, "data": { "users": ["alice", "bob", "carol"] } }
```
Danh sách do server đẩy về (gói `USER_LIST`); bridge chỉ trả bản mới nhất. Cập nhật realtime qua sự kiện `users`.

### 3.6 `POST /api/messages` ✅

Request:
```json
{ "to": null,  "text": "Chào cả nhóm" }   // tin chung (broadcast)
{ "to": "bob", "text": "Chào Bob" }       // tin riêng (unicast)
```
- `text`: 1–4000 ký tự.

Response 200 (tin đã vào hàng gửi, **chưa chắc đã tới**):
```json
{ "ok": true, "data": { "message": {
    "msg_id": "6f1c…", "sender": "alice", "to": "bob", "text": "Chào Bob",
    "ts": 1760000000.12, "status": "SENT", "direction": "out"
} } }
```
Trạng thái tiếp theo (`ACKED` / `FAILED`) đến qua sự kiện `message_status`.
Lỗi: 400, 409 `NOT_ONLINE`.

### 3.7 `GET /api/messages?peer=<name|global>&limit=50` ✅

Lịch sử trong phiên hiện tại (lưu trong RAM của client). `peer=global` (mặc định) = kênh chung,
`peer=bob` = hội thoại riêng với bob. Sắp xếp cũ → mới.
```json
{ "ok": true, "data": { "messages": [ { ...Message... } ] } }
```

### 3.8 `POST /api/files` ⏳ PENDING (`file_transfer.py`)

Upload **raw bytes** (không dùng multipart cho đơn giản):
```
POST /api/files
Content-Type: application/octet-stream
Content-Length: 123456
X-Filename: bao%20cao.pdf      ← encodeURIComponent(file.name)
X-To: bob                      ← bỏ trống / không gửi = gửi cho tất cả
<bytes>
```
JS:
```js
fetch('/api/files', { method: 'POST', body: file,
  headers: { 'X-Filename': encodeURIComponent(file.name), 'X-To': to || '' } })
```
Response 200:
```json
{ "ok": true, "data": { "transfer_id": "c3a9…", "filename": "bao cao.pdf", "size": 123456 } }
```
Tiến độ gửi đến qua sự kiện `file_progress` / `file_done` / `file_failed`.
Giới hạn mặc định 100 MB (413 nếu vượt).
**Hiện tại:** khi chưa có `file_transfer`, bridge đọc bỏ body rồi trả 501 `NOT_IMPLEMENTED`.
Khi dev với `--mock` (cần `dev_mock.py`, không có trong repo) thì tệp được lưu vào `uploads/`
và có tiến độ giả để làm UI.

### 3.9 `GET /api/files/<transfer_id>` ⏳ PENDING

Tải về tệp đã nhận xong. Trả bytes với `Content-Disposition: attachment; filename*=UTF-8''<tên>`.
404 nếu chưa có / chưa xong.

## 4. Hàng đợi sự kiện — `GET /api/events` ✅

```
GET /api/events?since=<seq>&timeout=25
```
- `since`: số thứ tự sự kiện cuối JS đã xử lý (lần đầu dùng `0` hoặc `last_seq` từ `/api/status`).
- `timeout`: số giây tối đa giữ kết nối nếu chưa có gì mới (0–30, mặc định 25).
- Trả ngay khi có sự kiện `seq > since`; hết timeout thì trả mảng rỗng.

```json
{ "ok": true, "data": {
    "events": [
      { "seq": 43, "type": "message", "ts": 1760000001.5, "data": { ...Message... } }
    ],
    "next": 43,
    "reset": false
} }
```
- Lần gọi sau dùng `since = next`.
- `reset: true` nghĩa là bridge đã khởi động lại hoặc JS bị tụt quá xa (hàng đợi giữ 1000 sự kiện gần nhất) → JS nên tải lại `/api/status`, `/api/users`, `/api/messages`.

Vòng lặp mẫu:
```js
let since = 0;
async function poll() {
  while (true) {
    try {
      const r = await (await fetch(`/api/events?since=${since}&timeout=25`)).json();
      if (r.ok) {
        if (r.data.reset) await reloadAll();
        r.data.events.forEach(handleEvent);
        since = r.data.next;
      }
    } catch (e) { await new Promise(res => setTimeout(res, 2000)); } // bridge tắt → thử lại
  }
}
```

### Các loại sự kiện

| `type` | `data` | Ghi chú |
|---|---|---|
| `connection` | `{ "state": "ONLINE", "reason": null }` | Mỗi lần đổi trạng thái kết nối |
| `users` | `{ "users": ["alice","bob"] }` | Danh sách online mới |
| `message` | `Message` (`direction: "in"`) | Tin nhắn đến (chung hoặc riêng) |
| `message_status` | `{ "msg_id": "…", "status": "ACKED" }` | Tin mình gửi đổi trạng thái |
| `file_offer` ⏳ | `{ "transfer_id", "from", "filename", "size" }` | Có người gửi tệp tới |
| `file_progress` ⏳ | `{ "transfer_id", "direction": "out"\|"in", "bytes", "total" }` | Gửi tối đa ~10 lần/giây |
| `file_done` ⏳ | `{ "transfer_id", "direction", "filename", "url" }` | `url` = `/api/files/<id>` nếu là tệp nhận |
| `file_failed` ⏳ | `{ "transfer_id", "direction", "reason" }` | |
| `error` | `{ "code", "message" }` | Lỗi nền (ví dụ mất kết nối server) |

### Đối tượng `Message`

| Trường | Kiểu | Ý nghĩa |
|---|---|---|
| `msg_id` | string | uuid4 hex, do client gửi tạo |
| `sender` | string | |
| `to` | string \| null | `null` = tin chung |
| `text` | string | |
| `ts` | float | lúc tạo (phía người gửi) |
| `status` | string | `PENDING \| SENT \| ACKED \| FAILED` (tin đến luôn là `ACKED`) |
| `direction` | string | `out` (mình gửi) / `in` (nhận) |

## 5. Trạng thái

### Kết nối (`client.py`)

```
DISCONNECTED ──connect()──▶ CONNECTING ──HELLO_ACK──▶ CONNECTED ──login()──▶ AUTHENTICATING ──AUTH_OK──▶ ONLINE
      ▲                         │ timeout                                        │ AUTH_FAIL                │
      │◀────────────────────────┘                                 CONNECTED ◀────┘                          │
      │                                                                                                   │
      │◀── LOGGING_OUT ◀── logout() ──────────────────────────────────────────────────────────────────────┤
      │                                                                                                   │ mất heartbeat
      └──── hết số lần thử ──── RECONNECTING ◀────────────────────────────────────────────────────────────┘
                                    │ kết nối + đăng nhập lại thành công
                                    └──────────────▶ ONLINE
```

### Tin nhắn gửi đi (`messaging.py`)

```
PENDING ──đã giao cho transport──▶ SENT ──server MSG_ACK──▶ ACKED
                                     └──quá ACK_TIMEOUT (10 s)──▶ FAILED
```
`PENDING` chỉ tồn tại rất ngắn; nếu transport ném lỗi → `FAILED` ngay.

---

## 6. Phụ thuộc nội bộ (cho các thành viên khác) — ⏳ cần chốt

Phần này **không dành cho người 5**; là hợp đồng giữa client.py và module của các bạn khác.
Đề xuất dưới đây là thứ client đang dùng với mock — nếu module thật khác thì sửa chỗ này trước.

### 6.1 Transport (`reliable_udp.py` + bảo mật) ⏳

`ChatClient` chỉ làm việc với packet dạng **dict**. Việc đóng gói bytes, mã hoá, đánh số thứ tự,
ACK/retransmit, cửa sổ trượt… nằm trong transport.

```python
class Transport:
    def connect(self, server_addr: tuple[str, int]) -> None: ...
    def send(self, packet: dict) -> None: ...              # không chặn lâu; lỗi → raise OSError
    def recv(self, timeout: float) -> dict | None: ...     # None nếu hết timeout
    def close(self) -> None: ...
```
Câu hỏi cần chốt:
1. reliable_udp có cung cấp sẵn interface như trên không, hay client phải tự gọi `protocol.encode()`?
2. Mã hoá (AES?) đặt ở tầng nào, ai làm, trao đổi khoá thế nào (khoá chung cấu hình sẵn hay handshake)?
3. Transport có báo "gói đã được ACK ở tầng transport" không? (Nếu có, có thể thêm trạng thái `DELIVERED`.)

### 6.2 Các loại packet (`protocol.py`) ⏳

| Hướng | `type` | Trường khác |
|---|---|---|
| C→S | `HELLO` | `version` |
| S→C | `HELLO_ACK` | `session_id` |
| C→S | `AUTH` | `username`, `password` |
| S→C | `AUTH_OK` / `AUTH_FAIL` | `users` / `reason` |
| C→S | `LOGOUT` | |
| C↔S | `PING` / `PONG` | |
| S→C | `USER_LIST` | `users` |
| C→S | `MSG` | `msg_id`, `to` (null = broadcast), `text`, `ts` |
| S→C | `MSG` | `msg_id`, `sender`, `to`, `text`, `ts` |
| S→C | `MSG_ACK` / `MSG_FAIL` | `msg_id` / `msg_id`, `reason` |
| ⏳ | `FILE_*` | do `file_transfer.py` định nghĩa |

Quy ước: server **không** gửi lại tin broadcast cho chính người gửi.

### 6.3 File transfer (`file_transfer.py`) ⏳

Bridge cần một đối tượng có:
```python
class FileService:
    def send_file(self, path: str, filename: str, to: str | None) -> str: ...  # trả transfer_id, chạy nền
    def get_received(self, transfer_id: str) -> tuple[str, str] | None: ...    # (đường dẫn trên đĩa, tên tệp)
```
và phát sự kiện qua callback `on_event("file_progress", {...})` như bảng §4.

---

## Lịch sử thay đổi

| Ngày | Phiên bản | Nội dung |
|---|---|---|
| 10/10/2026 | v0.1 | Bản nháp đầu tiên |
