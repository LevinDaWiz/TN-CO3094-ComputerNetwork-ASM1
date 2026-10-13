# Sơ đồ tuần tự — phía client

Vẽ bằng Mermaid (GitHub hiển thị trực tiếp; xuất ảnh cho báo cáo bằng https://mermaid.live).
Tên packet theo docs/api.md §6.2. Phần "Transport" là reliable_udp + mã hoá (⏳ của nhóm),
ở đây gộp thành một khối.

## 1. Đăng nhập

```mermaid
sequenceDiagram
    autonumber
    participant UI as Trình duyệt (JS)
    participant HB as http_bridge
    participant CL as ChatClient
    participant TR as Transport (RUDP + mã hoá)
    participant SV as Server

    UI->>HB: POST /api/login {username, password}
    HB->>CL: login(username, password)
    Note over CL: DISCONNECTED → CONNECTING
    CL->>TR: connect(server_addr)
    CL->>TR: HELLO {version}
    TR->>SV: (gói UDP đã mã hoá)
    SV-->>TR: HELLO_ACK {session_id}
    TR-->>CL: HELLO_ACK
    Note over CL: → CONNECTED, bật luồng heartbeat
    CL->>TR: AUTH {username, password}
    TR->>SV: AUTH (mã hoá)
    SV-->>CL: AUTH_OK {users}
    Note over CL: → AUTHENTICATING → ONLINE
    CL-->>HB: on_event("connection", ONLINE), on_event("users")
    HB-->>UI: 200 {username, state: ONLINE, users}
```

## 2. Gửi tin nhắn (tin chung và tin riêng)

```mermaid
sequenceDiagram
    autonumber
    participant UA as JS của Alice
    participant HB as http_bridge (Alice)
    participant MS as Messenger (Alice)
    participant CL as ChatClient + Transport (Alice)
    participant SV as Server
    participant CB as Client của Bob
    participant UB as JS của Bob

    UB->>CB: GET /api/events?since=n (long-poll, đang chờ)
    UA->>HB: POST /api/messages {to: "bob" | null, text}
    HB->>MS: send(to, text)
    Note over MS: tạo Message (msg_id), lưu lịch sử, PENDING
    MS->>CL: send_packet(MSG {msg_id, to, text, ts})
    Note over MS: → SENT, bật timer ACK_TIMEOUT
    HB-->>UA: 200 {message, status: SENT}
    CL->>SV: MSG (UDP tin cậy, mã hoá)
    alt to = "bob" (unicast)
        SV->>CB: MSG {sender: alice, to: bob, ...}
    else to = null (broadcast)
        SV->>CB: MSG {sender: alice, to: null, ...}
        Note over SV: gửi tới mọi người online trừ Alice
    end
    SV-->>CL: MSG_ACK {msg_id}
    CL->>MS: handler MSG_ACK
    Note over MS: huỷ timer, → ACKED
    MS->>HB: on_event("message_status", ACKED) vào EventQueue
    CB-->>UB: 200 {events: [message]} (long-poll trả về ngay)
    UA->>HB: GET /api/events?since=m
    HB-->>UA: 200 {events: [message_status ACKED]}
```

## 3. Gửi tin thất bại

```mermaid
sequenceDiagram
    autonumber
    participant UA as JS
    participant MS as Messenger
    participant CL as ChatClient
    participant SV as Server

    UA->>MS: POST /api/messages {to: "zoe"}
    MS->>CL: MSG
    CL->>SV: MSG
    alt người nhận không online
        SV-->>CL: MSG_FAIL {msg_id, reason}
        CL->>MS: handler MSG_FAIL → FAILED
    else không có phản hồi trong 10 s
        Note over MS: timer hết hạn → FAILED
    end
    MS-->>UA: sự kiện message_status {FAILED, reason}
```

## 4. Mất kết nối và tự kết nối lại

```mermaid
sequenceDiagram
    autonumber
    participant UI as JS
    participant CL as ChatClient
    participant SV as Server

    loop mỗi 3 s
        CL->>SV: PING
        SV-->>CL: PONG
    end
    Note over SV: server dừng / mạng đứt
    Note over CL: 10 s không nhận được gói nào
    CL-->>UI: sự kiện error SERVER_LOST, connection RECONNECTING
    loop tối đa 5 lần, cách nhau 2 s
        CL->>SV: HELLO
        alt server đã sống lại
            SV-->>CL: HELLO_ACK
            CL->>SV: AUTH (thông tin đăng nhập đã lưu)
            SV-->>CL: AUTH_OK
            CL-->>UI: connection ONLINE
        end
    end
    Note over CL: hết 5 lần → DISCONNECTED
```
