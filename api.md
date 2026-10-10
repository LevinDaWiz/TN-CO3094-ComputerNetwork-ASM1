# API giao diện và API nội bộ Python

Phiên bản: 1.0. Giao thức mạng liên quan: [protocol_spec.md](protocol_spec.md).

Tài liệu này chốt giao tiếp JavaScript↔Python client và hợp đồng giữa các module. Đây là API dự kiến để triển khai, chưa phải mã nguồn đã chạy.

## 1. Quy ước HTTP

- Base URL mặc định: http://127.0.0.1:8080. Python phục vụ cả HTML/CSS/JS và API cùng origin.
- Python tự đọc HTTP/1.1 bằng socket; mỗi response dùng Content-Length và Connection: close để đơn giản hóa v1.
- Đọc đủ header đến CRLF CRLF, rồi đọc đúng Content-Length. Không giả định một recv chứa đủ request.
- Giới hạn header 16 KiB, JSON body 64 KiB, file body 100 MiB; request có body phải có Content-Length. V1 không hỗ trợ Transfer-Encoding: chunked; trả 400 và đóng kết nối nếu có.
- JSON UTF-8; response dùng Content-Type: application/json; charset=utf-8. Download dùng application/octet-stream.
- Chỉ bind loopback; không cho phép CORS tùy ý. Kiểm tra Host và Origin khi hiện diện. Các request thay đổi trạng thái phải có X-Local-Token, token ngẫu nhiên do bridge cấp qua GET /api/bootstrap. Token này chỉ bảo vệ API cục bộ, không phải khóa phiên UDP.
- Không trả mật khẩu, khóa UDP hoặc nonce counter về trình duyệt.

Thành công:
```json
{"ok":true,"data":{}}
```
Lỗi:
```json
{"ok":false,"error":{"code":"USER_OFFLINE","message":"Người nhận không trực tuyến"}}
```
HTTP status: 200 đọc/thành công; 201 tạo tài nguyên; 202 đã xếp hàng; 400 input sai; 401 chưa đăng nhập; 403 local token sai; 404 không tìm thấy; 409 trạng thái xung đột; 413 quá lớn; 500 lỗi nội bộ; 503 server không sẵn sàng.

## 2. Endpoint

### GET /api/bootstrap

Không cần đăng nhập. Trả {local_token,api_version:"1.0"}. Token giữ trong bộ nhớ JavaScript, không ghi log.

### POST /api/login

Body: {username,password}. Server host/port và CA certificate nằm trong cấu hình Python client.

Trả 202: {status:"connecting"}. Tác vụ nền chạy TCP/TLS, LOGIN, UDP_BIND. Chỉ phát connected sau UDP_BIND_OK. Thất bại phát connection_changed và error. Nếu đang đăng nhập/đã connected trả 409.

### POST /api/logout

Body: {}. Trả 202 {status:"disconnecting"}; gửi LOGOUT best effort với cơ chế reliable, sau đó dọn client và phát disconnected. Logout khi đã disconnected có thể trả 200.

### GET /api/status

Trả {state,user,last_error}; state thuộc disconnected, connecting, connected, disconnecting. user={user_id,username} hoặc null. Không đưa session_id 64-bit ra JavaScript nếu không cần.

### GET /api/users

Cần connected. Trả {revision,users:[{user_id,username}]}; snapshot mới nhất đã nhận đủ từ server.

### POST /api/messages

Body:
```json
{"to":"u02","text":"Chào bạn!"}
```

to=null là global. text không rỗng và <=800 byte UTF-8. Python sinh message_id UUID.

Trả 202:
```json
{"ok":true,"data":{"message_id":"UUID","status":"queued"}}
```

Không chờ ACK trong HTTP handler. Trạng thái accepted/delivered/failed tới qua event; global có recipient_id riêng.

### GET /api/events?after=123

Polling khuyến nghị 500 ms, chỉ một request đang chạy; sau response dùng next_cursor cho lần kế tiếp. event_id tăng đơn điệu trong vòng đời tiến trình bridge, không reset khi logout/login.

```json
{"ok":true,"data":{"events":[{"event_id":124,"type":"message_status","data":{"message_id":"UUID","recipient_id":"u02","status":"delivered","error_code":null}}],"next_cursor":124}}
```

Không có event mới: events=[], next_cursor giữ nguyên. Mỗi response tối đa 100 event; nếu đủ 100, client lấy tiếp ngay. Giữ 10000 event trong RAM. Cursor quá cũ trả 409 EVENT_CURSOR_EXPIRED kèm current_cursor; UI thông báo có thể mất sự kiện, tải lại status/users/transfers rồi tiếp tục tại cursor mới.

### POST /api/files/offers

Body: {to,filename,size}. V1 chỉ private file transfer; không nhận đường dẫn máy người dùng.

Tạo bản ghi upload cục bộ, CHƯA gửi FILE_OFFER ra mạng vì chưa có nội dung/hash. Trả 201 {transfer_id,status:"awaiting_upload"}. Metadata chưa upload bị xóa sau 60 giây.

### PUT /api/files/{id}/content

Content-Type: application/octet-stream. Body là File/Blob; browser tự đặt Content-Length. Kích thước phải đúng metadata, tối đa 100 MiB.

Bridge đọc streaming xuống tệp tạm và tính SHA-256, không nạp toàn tệp vào RAM. Sau nhận đủ mới tạo FILE_OFFER mạng qua file module. Trả 202 {transfer_id,status:"offered"}; cập nhật accepted/transferring/completed/failed qua event. Không chờ toàn bộ truyền UDP để trả HTTP. PUT lại khi không awaiting_upload trả 409; upload lỗi dọn tệp tạm và đánh dấu failed.

### POST /api/files/{id}/accept

Body {}. Chỉ dùng với transfer hướng incoming ở trạng thái offered. Trả 202 {transfer_id,status:"accepted"}; gửi FILE_ACCEPT.

### POST /api/files/{id}/reject

Body {reason:"Không nhận tệp"}. Chỉ với incoming offered. Trả 202 {transfer_id,status:"rejected"}; gửi FILE_REJECT và dọn trạng thái liên quan.

### GET /api/files

Trả {transfers:[...]} gồm transfer_id,direction,peer_id,filename,size,status,bytes_done,progress,error_code. Dùng phục hồi UI sau refresh; chỉ là trạng thái phiên làm việc hiện tại.

### GET /api/files/{id}/download

Chỉ incoming completed. Trả byte tệp, Content-Disposition: attachment với filename được xử lý an toàn. Chưa hoàn tất trả 409. Không nhận đường dẫn tùy ý qua URL.

## 3. Trạng thái và sự kiện

Transfer status: awaiting_upload → offered → accepted → transferring → verifying → completed. Từ trạng thái chưa hoàn tất có thể chuyển failed; offered có thể chuyển rejected. awaiting_upload chỉ xuất hiện phía gửi.

| Event | data tối thiểu |
|---|---|
| connection_changed | state, user hoặc null, error_code hoặc null |
| users_updated | revision, users |
| message_received | message_id, from, to, text, sent_at |
| message_status | message_id, recipient_id hoặc null, status, error_code |
| file_offer | transfer_id, from, filename, size |
| file_status | transfer_id, direction, status, error_code |
| file_progress | transfer_id, direction, bytes_done, total_bytes, progress |
| file_completed | transfer_id, direction, filename, size |
| error | code, message, reference_id hoặc null |

progress là 0..100. Phía gửi bytes_done đếm byte đã ACK ở chặng client→server, phía nhận đếm byte đã lưu; 100% byte không đồng nghĩa completed. Chỉ FILE_RESULT thành công mới xác nhận toàn bộ transfer ở phía gửi. File rỗng có progress=100 khi completed. Điều tiết progress event tối đa 5 lần/giây/transfer.

## 4. JavaScript mẫu

```javascript
const boot = await fetch('/api/bootstrap').then(r => r.json());
const localToken = boot.data.local_token;

async function sendMessage(to, text) {
  const response = await fetch('/api/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Local-Token': localToken
    },
    body: JSON.stringify({to, text})
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error.message);
  return result.data;
}
```

## 5. API nội bộ Python

Chữ ký dưới đây là hợp đồng module, không phải implementation. peer_id là định danh peer trong transport registry; registry giữ địa chỉ và khóa. Không truyền khóa qua UI.

```python
# protocol.py
encode_packet(header: Header, plaintext: bytes, crypto: CryptoContext) -> bytes
decode_packet(raw: bytes, crypto: CryptoContext) -> Packet

# security.py
# encrypt trả nonce + ciphertext + tag; counter được khóa đồng bộ.
encrypt(ctx: CryptoContext, aad: bytes, plaintext: bytes) -> bytes
decrypt(ctx: CryptoContext, aad: bytes, wire_payload: bytes) -> bytes

# reliable_udp.py
send(peer_id: str, stream_id: int, packet_type: int,
     payload: bytes) -> str  # delivery_id, enqueue không block
on_payload(callback) -> None
on_delivery(callback) -> None
on_failure(callback) -> None
close_stream(peer_id: str, stream_id: int, reason: str) -> None

# sessions.py (server)
authenticate(username: str, password: str) -> Session
bind_udp(session_id: int, address: tuple) -> None
list_online_users() -> list[dict]
remove_session(session_id: int) -> None

# messaging.py
send_message(to: str | None, text: str) -> str  # message_id
handle_message(peer_id: str, payload: dict) -> None

# file_transfer.py
# path do Python bridge quản lý, không phải đường dẫn JSON từ browser.
offer_file(to: str, path: str, transfer_id: str) -> str
accept_transfer(transfer_id: str) -> None
reject_transfer(transfer_id: str, reason: str) -> None
handle_packet(peer_id: str, stream_id: int,
              packet_type: int, payload: bytes) -> None
list_transfers() -> list[dict]

# client.py: facade duy nhất HTTP bridge gọi
login(username: str, password: str) -> None  # khởi chạy nền
logout() -> None
get_status() -> dict
list_users() -> dict
send_message(to: str | None, text: str) -> str
create_upload(to: str, filename: str, size: int) -> str
submit_uploaded_file(transfer_id: str, temp_path: str) -> None
accept_transfer(transfer_id: str) -> None
reject_transfer(transfer_id: str, reason: str) -> None
list_transfers() -> list[dict]
get_download_path(transfer_id: str) -> str
get_events(after_event_id: int, limit: int = 100) -> dict
```

Callback contract:
- on_payload(peer_id, stream_id, packet_type, payload): đúng thứ tự với reliable stream, không lặp; ACK không đưa lên ứng dụng.
- on_delivery(delivery_id): peer trực tiếp ACK, không mang nghĩa người nhận cuối cùng đã nhận.
- on_failure(delivery_id, error_code): hết retry hoặc đóng peer/luồng.

Module raise AppError(code,message) cho lỗi kiểm tra đầu vào hoặc trạng thái. HTTP bridge ánh xạ lỗi sang HTTP status. Lỗi công việc nền chuyển thành event. Dùng queue.Queue giữa network/worker/HTTP; bảo vệ registry/counter bằng lock. Không giữ lock trong khi chờ socket hoặc gọi callback.

## 6. Phân công và nghiệm thu

- Người 1 sở hữu protocol.py/reliable_udp.py; phối hợp security.py để tính header/nonce đúng.
- Người 2 sở hữu server.py/sessions.py; thiết lập khóa và routing.
- Người 3 sở hữu client.py/messaging.py/http_bridge.py và hợp đồng API HTTP.
- Người 4 sở hữu file_transfer.py, stream file và kiểm tra hash.
- Người 5 sở hữu UI/security.py; phối hợp người 3 về HTTP/event và người 2 về TLS/session.

Kiểm thử API: login bất đồng bộ, JSON sai, text vượt giới hạn UTF-8, private/global chat, event cursor, upload sai size, file rỗng/100 MiB, download trước completed, local token sai, request TCP bị chia nhỏ, nhiều request khi UDP đang truyền tệp. Không tuyên bố các bài kiểm thử đã chạy khi mới có tài liệu.
