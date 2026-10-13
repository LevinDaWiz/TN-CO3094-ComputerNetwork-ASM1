# Thiết kế và triển khai giao thức CC v1

## 1. Phạm vi triển khai

Hai module `protocol.py` và `reliable_udp.py` cung cấp lớp đóng gói và truyền dữ
liệu tin cậy trên UDP socket. Transport xử lý đơn vị byte payload; module chat,
file và sessions giữ trách nhiệm nghiệp vụ. Giao diện gửi bất đồng bộ trả về
`delivery_id`, sau đó thông báo ACK hoặc thất bại qua callback.

## 2. Cấu trúc datagram

Header đóng gói bằng `struct.Struct("!2sBBBQIIH")`; dấu `!` quy định network byte
order, không thêm padding. Header dài 23 byte.

| Trường | Kiểu struct | Byte | Ý nghĩa |
|---|---|---:|---|
| magic | 2s | 2 | `b"CC"` |
| version | B | 1 | Phiên bản 1 |
| type | B | 1 | Mã thông điệp 1–15 |
| flags | B | 1 | Bit 0 reliable, bit 1 encrypted |
| session_id | Q | 8 | ID phiên khác 0, lấy từ đăng nhập |
| stream_id | I | 4 | Luồng độc lập |
| seq | I | 4 | Sequence bắt đầu 1, riêng từng chiều/luồng |
| payload_len | H | 2 | Số byte sau header, gồm nonce và tag |

Wire payload gồm nonce 12 byte, ciphertext, GCM tag 16 byte. Datagram tối đa
1200 byte nên plaintext tối đa 1149 byte. Receiver kiểm tra đúng tổng chiều dài;
loại bỏ sai magic/version/type/flags/stream, vượt kích thước hoặc sai authentication
tag trước khi ACK. Trường `payload_len` được codec tính lại khi encode.

AES-256-GCM dùng toàn bộ raw header làm AAD. Nonce gồm prefix 4 byte và counter
uint64 big-endian. Counter được bảo vệ bằng lock và tăng trên toàn bộ luồng trong
một chiều. Hai chiều dùng khóa/prefix riêng. Khi retransmit, sender dùng đúng
bytes đã mã hóa ban đầu, không mã hóa lại. Không wrap sequence/counter: ứng dụng
xử lý `SESSION_EXHAUSTED` bằng thiết lập phiên mới.

## 3. Thông điệp

| Mã | Tên | Luồng | Reliable | Payload |
|---:|---|---|---|---|
| 1 | UDP_BIND | 1 | Có | JSON `{}` |
| 2 | UDP_BIND_OK | 1 | Có | JSON `{}` |
| 3 | HEARTBEAT | 0 | Không | JSON `{}` |
| 4 | USER_LIST | 1 | Có | JSON snapshot phân trang |
| 5 | CHAT | 2 | Có | JSON message_id, to, text; server thêm from/sent_at |
| 6 | ACK | 0 | Không | `!II`: ack_stream_id, ack_seq |
| 7 | CHAT_STATUS | 2 | Có | JSON message_id, recipient_id, status, error_code |
| 8 | FILE_OFFER | >=3 | Có | JSON transfer_id, to, filename, size, chunk_size, total_chunks, sha256 |
| 9 | FILE_ACCEPT | >=3 | Có | JSON transfer_id |
| 10 | FILE_REJECT | >=3 | Có | JSON transfer_id, reason |
| 11 | FILE_CHUNK | >=3 | Có | `!I` chunk_index + 1..1024 raw bytes |
| 12 | FILE_END | >=3 | Có | JSON transfer_id |
| 13 | FILE_RESULT | >=3 | Có | JSON transfer_id, status, error_code |
| 14 | ERROR | >=1 | Có | JSON code, message, reference_id |
| 15 | LOGOUT | 1 | Có | JSON `{}` |

JSON encode UTF-8 compact, `ensure_ascii=False`, không nhận NaN/Infinity; codec
kiểm tra JSON là object và giới hạn byte. Schema nghiệp vụ (UUID, text <=800 byte,
size <=100 MiB, trường bắt buộc, quyền người gửi/nhận, chunk cuối) thuộc module
messaging/file/sessions. Codec không thay thế các kiểm tra này.

ACK không đi vào ordered delivery và không cần ACK. HEARTBEAT được transport
xử lý nội bộ để cập nhật liveness, không đưa lên callback ứng dụng.

## 4. Selective Repeat

Mỗi luồng reliable có `next_seq`, `send_base`, bảng pending, tập ACK ngoài thứ tự,
`recv_base` và bộ đệm receive riêng. Cửa sổ mặc định 16 gói.

Sender chỉ gửi sequence trong `[send_base, send_base+15]`. ACK của một gói sau
được ghi nhận và chỉ gỡ gói đó khỏi pending; không đẩy send_base vượt một sequence
chưa ACK. Sender chỉ trượt cửa sổ qua dãy sequence đã ACK liên tục.

Receiver nhận gói trong `[recv_base, recv_base+15]`, lưu trước khi ACK. Nếu có
đủ dãy liên tục, receiver đưa payload vào hàng đợi ứng dụng theo đúng thứ tự.
Gói trùng dưới recv_base được ACK lại nhưng không giao lại. Gói trùng còn trong
buffer không được ghi hai lần. Gói vượt cửa sổ bị bỏ và không ACK; sender sẽ
truyền lại khi timeout.

Ví dụ: gói 2, 3 đến trước gói 1. Receiver giữ 2 và 3 rồi ACK riêng từng gói,
chưa đưa dữ liệu lên ứng dụng. Khi gói 1 đến, receiver giao lần lượt 1, 2, 3.
Nếu ACK của gói 1 mất, sender retry cùng datagram, receiver chỉ ACK lại.

Timeout ban đầu 500ms; mỗi retry nhân đôi, tối đa 4s. Tối đa 8 retry ngoài lần
gửi đầu. Sau timeout cuối, báo `DELIVERY_TIMEOUT` và đóng luồng. Stream file lỗi
không đóng các file/chat khác. Stream 1/2 lỗi đóng peer để client kết nối lại;
những delivery khác được báo `RECONNECT_REQUIRED`.

## 5. Luồng và concurrency

Stream 0 dành cho ACK/heartbeat; 1 dành cho phiên/presence; 2 dành cho chat.
Mỗi file dùng luồng >=3 riêng. Client cấp ID lẻ, server cấp ID chẵn. ID đã đóng
được giữ tombstone và không tái sử dụng trong phiên.

Network worker đọc UDP và chạy timer; callback worker đưa sự kiện cho ứng dụng.
Không gọi callback hoặc socket send dưới lock. Callback phải chuyển công việc
sang queue nhanh. Scheduler round robin các file, ưu tiên control/chat và chừa
hai suất congestion window cho chúng khi cwnd >=3. Mất gói trên file A chỉ làm
kẹt thứ tự của file A; file B và chat không chờ recv_base của file A. Băng thông
và congestion window của một peer vẫn được chia sẻ.

Mặc định queue gửi tối đa 256 pending/stream, 4096 delivery toàn transport chưa
hoàn tất dispatch. Receive giữ tối đa 16 gói/stream và 4096 payload event toàn
transport. Khi event queue đầy, dữ liệu vẫn ở buffer đã dành chỗ, recv_base chưa
trượt; không ACK gói ngoài cửa sổ. Thông báo delivery và trạng thái peer cũng có
giới hạn. Không ACK dữ liệu không có khả năng giữ.

## 6. Heartbeat và điều khiển tắc nghẽn

Sau `activate_peer`, gửi heartbeat mỗi 5s. Bất kỳ datagram có xác thực và địa chỉ
nguồn đúng cập nhật last_seen; 15s không có gói hợp lệ thì đóng peer, báo
`PEER_TIMEOUT` và failure cho các delivery đang chờ. `on_peer_closed` cho phép
client cập nhật offline ngay cả khi không có delivery đang chờ.

Transport có controller AIMD cơ bản: cwnd ban đầu 4 gói, tăng theo slow start /
additive increase, giảm về 1 khi có timeout, ngưỡng slow start bằng một nửa cwnd
trước mất gói (tối thiểu 2), cwnd tối đa 16. Đây là baseline chưa có pacing/RTT
estimation; **không phải BBR/CUBIC**. `FixedWindow` chỉ dùng để cô lập flow control
trong test. Phương án BBR/CUBIC phải được xác nhận với giảng viên trước khi coi
hạng mục congestion control đã đáp ứng đầy đủ đề bài.

## 7. Kiểm thử đã thực hiện

Môi trường: Python 3.12.14/Linux, cryptography 50.0.2. 29 test tự động pass:

- Codec cho 15 loại gói, UTF-8, header 23 byte, datagram tối đa 1200 byte,
  sai header/tag/length, nonce và sequence exhaustion.
- ACK selective, mất data, mất ACK, duplicate, out-of-order, không trượt send
  window qua gap, không ACK ngoài receive window, sai nguồn/xác thực.
- Timeout với 8 retry và backoff, đóng file riêng, lỗi chat buộc kết nối lại,
  backpressure queue gửi/nhận, notification queue, parity/no-reuse, hai chiều.
- Heartbeat/idle expiry, control cho file rỗng, AIMD cơ bản, chat khi luồng file
  bị mất dữ liệu, localhost worker lifecycle, 20 client bằng UDP socket thật.
- Fault injection seed 2026: xác suất mất 15%, trùng 10%, delay 0–200ms và đảo
  thứ tự. Nhận 122917 byte file và 20 chat đúng thứ tự từng luồng, không lặp;
  SHA-256 file khớp, không có failure.

Demo localhost nhận 32775 byte và 5 chat, hash khớp. Các kiểm thử chỉ chứng minh
transport và codec, chưa chứng minh login TLS, server relay, UI hay FILE_RESULT
end-to-end. Windows/macOS và WAN chưa được kiểm thử. Lưu tombstone LOGOUT để
ACK lại trong 60s và quản lý địa chỉ UDP_BIND thuộc sessions.py, chưa nằm trong
hai module này.
