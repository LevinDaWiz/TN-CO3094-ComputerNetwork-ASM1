# Sơ đồ tuần tự — phía client

Vẽ bằng Mermaid (GitHub hiển thị trực tiếp; xuất ảnh cho báo cáo bằng https://mermaid.live).
Theo [1a_api.md](../1a_api.md) và [1b_protocol_spec.md](../1b_protocol_spec.md).

- **UI**: JavaScript trên trình duyệt (người 5).
- **HB**: `http_bridge.py`. **CL**: `ChatClient` + `Messenger` (`client.py`, `messaging.py`).
- **RU**: `ReliableUDP` (`reliable_udp.py`, mã hoá AES-GCM trong `protocol.py`).
- **SV**: server (`server.py`, `sessions.py`).

## 1. Đăng nhập

```mermaid
sequenceDiagram
    autonumber
    participant UI
    participant HB as http_bridge
    participant CL as ChatClient
    participant RU as ReliableUDP
    participant SV as Server

    UI->>HB: GET /api/bootstrap
    HB-->>UI: 200 {local_token}
    UI->>HB: POST /api/login {username, password} + X-Local-Token
    HB->>CL: login()
    Note over CL: state = connecting, bắt đầu luồng nền
    HB-->>UI: 202 {status: "connecting"}
    CL->>SV: TCP/TLS :9000 — LOGIN {username, password}
    SV-->>CL: LOGIN_OK {user_id, session_id, udp_port, c2s/s2c key, nonce prefix}
    Note over CL,SV: đóng TCP
    CL->>RU: register_peer(khoá c2s/s2c), start()
    CL->>RU: send(stream 1, UDP_BIND)
    RU->>SV: UDP_BIND (UDP :9001, mã hoá)
    SV-->>RU: ACK + UDP_BIND_OK
    RU-->>CL: on_payload(UDP_BIND_OK)
    CL->>RU: activate_peer() — bật heartbeat 5 s / hết hạn 15 s
    Note over CL: state = connected → sự kiện connection_changed
    SV-->>CL: USER_LIST (các phần cùng revision) → sự kiện users_updated
    loop mỗi 500 ms
        UI->>HB: GET /api/events?after=N
        HB-->>UI: {events: [connection_changed, users_updated], next_cursor}
    end
```

Nếu sai mật khẩu (`ERROR INVALID_CREDENTIALS`), lỗi TLS hoặc không nhận được `UDP_BIND_OK`
trong 10 giây, thì client quay về `disconnected` và phát `connection_changed` + `error`.

## 2. Gửi tin nhắn (riêng và chung)

```mermaid
sequenceDiagram
    autonumber
    participant UA as UI (Alice)
    participant CA as Client Alice
    participant SV as Server
    participant CB as Client Bob
    participant UB as UI (Bob)

    UA->>CA: POST /api/messages {to: "u02" | null, text}
    Note over CA: kiểm tra ≤ 800 byte UTF-8, sinh message_id
    CA->>SV: CHAT {message_id, to, text} (stream 2, reliable)
    CA-->>UA: 202 {message_id, status: "queued"}
    SV-->>CA: ACK (chỉ chặng Alice→server)
    SV->>CA: CHAT_STATUS {recipient_id, status: "accepted"}
    CA-->>UA: sự kiện message_status accepted
    alt to = "u02" (riêng)
        SV->>CB: CHAT {message_id, from: "u01", to, text, sent_at}
    else to = null (chung)
        SV->>CB: CHAT tới từng người online khác Alice
    end
    CB-->>SV: ACK
    CB-->>UB: sự kiện message_received
    SV->>CA: CHAT_STATUS {recipient_id: "u02", status: "delivered"}
    CA-->>UA: sự kiện message_status delivered
```

Tin chung có `CHAT_STATUS` riêng cho từng người nhận. `delivered` nghĩa là client đích đã
ACK gói CHAT, không có nghĩa người dùng đã đọc.

## 3. Gửi tin thất bại

```mermaid
sequenceDiagram
    autonumber
    participant UA as UI
    participant CA as Client
    participant RU as ReliableUDP
    participant SV as Server

    UA->>CA: POST /api/messages
    CA->>RU: send(CHAT)
    alt server báo lỗi
        SV->>CA: CHAT_STATUS {status: "failed", error_code: "USER_OFFLINE" | "NO_RECIPIENTS"}
    else server không ACK sau 8 lần retry (500 ms → 4 s)
        RU-->>CA: on_failure(delivery_id, DELIVERY_TIMEOUT)
        Note over RU,CA: lỗi stream 2 → đóng peer → client về disconnected
    end
    CA-->>UA: sự kiện message_status failed
```

## 4. Mất kết nối và đăng xuất

```mermaid
sequenceDiagram
    autonumber
    participant UI
    participant CL as ChatClient
    participant RU as ReliableUDP
    participant SV as Server

    alt server im lặng 15 s
        RU-->>CL: on_peer_closed(PEER_TIMEOUT)
        Note over CL: tin đang chờ → failed, state = disconnected
        CL-->>UI: sự kiện connection_changed {error_code: PEER_TIMEOUT} + error
        Note over UI: muốn tiếp tục phải đăng nhập lại (khoá phiên mới)
    else người dùng đăng xuất
        UI->>CL: POST /api/logout
        CL-->>UI: 202 {status: "disconnecting"}
        CL->>SV: LOGOUT (stream 1, reliable)
        SV-->>CL: ACK (chờ tối đa 3 s)
        CL->>RU: close()
        CL-->>UI: sự kiện connection_changed {state: "disconnected"}
    end
```

## 5. Gửi tệp (phần client; ⏳ chi tiết FILE_* do file_transfer.py)

```mermaid
sequenceDiagram
    autonumber
    participant UI
    participant HB as http_bridge
    participant CL as ChatClient
    participant FT as file_transfer
    participant SV as Server

    UI->>HB: POST /api/files/offers {to, filename, size}
    HB->>CL: create_upload()
    HB-->>UI: 201 {transfer_id, status: "awaiting_upload"}
    UI->>HB: PUT /api/files/{id}/content (bytes)
    HB->>CL: begin_upload() → đường dẫn tệp tạm
    Note over HB: ghi từng khúc xuống đĩa + tính SHA-256
    HB->>CL: submit_uploaded_file()
    CL->>FT: offer_file(to, path, transfer_id)
    HB-->>UI: 202 {status: "offered"}
    FT->>SV: FILE_OFFER → (chờ FILE_ACCEPT) → FILE_CHUNK… → FILE_END
    FT-->>UI: sự kiện file_progress / file_status / file_completed
```

## Ghi chú: `begin_upload` và `abort_upload`

Đây là **hai hàm Python nội bộ** trong facade `client.py`, bổ sung so với danh sách ở
`1a_api.md` §5.

```python
begin_upload(transfer_id: str, content_length: int) -> str   # trả đường dẫn tệp tạm
abort_upload(transfer_id: str, error_code: str) -> None
```

| Hàm | Khi nào bridge gọi | Làm gì |
|---|---|---|
| `begin_upload` | Nhận `PUT /api/files/{id}/content`, **trước** khi đọc body | Kiểm tra offer tồn tại, chưa hết hạn 60 giây, đang `awaiting_upload`, `Content-Length` đúng `size`; đánh dấu đang upload; trả đường dẫn tệp tạm |
| `abort_upload` | Upload hoặc `submit_uploaded_file` bị lỗi | Xoá offer và tệp tạm, phát sự kiện `file_status` với `status: "failed"`. Gọi nhiều lần không sao. |

Lý do cần thêm (chỉ dùng `list_transfers()` thì không đủ):

1. **Hai PUT cùng lúc cho một `transfer_id`**: `begin_upload` kiểm tra và đánh dấu trong
   cùng một lần khoá, nên request thứ hai nhận 409 `INVALID_STATE` thay vì cả hai cùng ghi tệp.
2. **Upload lỗi phải "dọn tệp tạm và đánh dấu failed"** (`1a_api.md`, PUT content): trạng
   thái offer nằm trong client, bridge không tự đánh dấu hay phát sự kiện được.

Lỗi `begin_upload` có thể trả: 404 `TRANSFER_NOT_FOUND`, 409 `INVALID_STATE`,
400 `INVALID_INPUT` (size không khớp), 501 `NOT_IMPLEMENTED` (chưa có file_transfer.py).
