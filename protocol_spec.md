# Đặc tả giao thức cộng tác client–server

Phiên bản: 1.0. Ngôn ngữ triển khai: Python. Tài liệu liên quan: [api.md](api.md).

Đây là thiết kế nhóm đã chọn để bắt đầu lập trình, không phải xác nhận của giảng viên. Cần xác nhận phương án TCP/TLS cho đăng nhập và mức độ bắt buộc của BBR/CUBIC. Phần điều khiển tắc nghẽn vẫn là hạng mục chưa chốt; bản này không tuyên bố đã đáp ứng toàn bộ yêu cầu đó.

## 1. Kiến trúc

- Trình duyệt giao tiếp HTTP với Python client trên 127.0.0.1:8080.
- Client kết nối server bằng TCP/TLS cổng 9000 để đăng nhập và thiết lập phiên.
- Chat, presence và truyền tệp sử dụng UDP cổng 9001.
- Server chuyển tiếp mọi dữ liệu. Bảo mật từng chặng; server đọc được nội dung.
- Cổng được cấu hình. Dùng socket và threading; ssl cho TLS, cryptography cho AES-GCM. Không Flask/Django, WebSocket.

## 2. TCP và thiết lập phiên

Framing: `[length: uint32 big-endian][JSON UTF-8]`. Length không tính 4 byte đầu, nằm trong 1..65536. Đọc đủ header rồi body; một recv không tương đương một thông điệp.

LOGIN:
```json
{"type":"LOGIN","username":"thien","password":"..."}
```
LOGIN_OK (giá trị khóa dưới đây chỉ là placeholder):
```json
{"type":"LOGIN_OK","user_id":"u01","session_id":12345,"udp_port":9001,"c2s_key":"BASE64_32_BYTES","s2c_key":"BASE64_32_BYTES","c2s_nonce_prefix":"BASE64_4_BYTES","s2c_nonce_prefix":"BASE64_4_BYTES"}
```
ERROR:
```json
{"type":"ERROR","code":"INVALID_CREDENTIALS","message":"Sai thông tin đăng nhập"}
```

- Tài khoản demo tạo sẵn, không có đăng ký. Lưu mật khẩu bằng password hash có salt, không lưu dạng rõ.
- Một tài khoản một phiên; trùng trả ALREADY_LOGGED_IN.
- Client kiểm tra chứng chỉ server bằng CA/chứng chỉ cung cấp cùng dự án; không tắt xác minh TLS.
- Server sinh session_id khác 0, duy nhất trong các phiên; khóa và prefix mới cho mỗi phiên.
- Client gửi UDP_BIND đã mã hóa trên stream 1; server xác thực, ghi nhận địa chỉ nguồn thực tế và trả UDP_BIND_OK trên stream 1.
- Session_id chỉ là định danh; xác thực AES-GCM mới chứng minh quyền sử dụng phiên.
- Không đổi địa chỉ UDP trong phiên này. Nếu địa chỉ đổi, đăng nhập lại.
- Hai bên hoàn tất thiết lập và đóng TCP; UDP heartbeat duy trì phiên. Phiên chưa bind hết hạn sau 15 giây.

## 3. Header và mã hóa UDP

Format Python: `!2sBBBQIIH`, tổng cộng 23 byte, tất cả số nguyên unsigned network byte order.

| Trường | Byte | Quy định |
|---|---:|---|
| magic | 2 | b"CC" |
| version | 1 | 1 |
| type | 1 | Mã tại mục 4 |
| flags | 1 | Bit 0 reliable, bit 1 encrypted; bit khác bằng 0 |
| session_id | 8 | Phiên client ở chặng hiện tại |
| stream_id | 4 | ID luồng |
| seq | 4 | Số thứ tự riêng từng chiều, từng luồng |
| payload_len | 2 | Toàn bộ byte sau header |

Datagram: `[header 23][nonce 12][ciphertext][GCM tag 16]`.

- Tổng datagram tối đa 1200 byte; plaintext tối đa 1149 byte.
- payload_len = 12 + len(plaintext) + 16; độ dài nhận phải đúng 23 + payload_len.
- AES-256-GCM; raw header là AAD. Tất cả UDP kể cả ACK và heartbeat phải mã hóa.
- Hai khóa riêng c2s/s2c. Nonce = prefix 4 byte + counter uint64 8 byte big-endian; counter bắt đầu 0, tăng cho từng gói mới trên toàn bộ luồng của một chiều.
- Truyền lại giữ nguyên datagram đã mã hóa, không mã hóa nội dung khác với nonce cũ.
- Khởi động lại tạo phiên mới. Không ghi khóa/mật khẩu vào log.
- Sai magic/version/flags/length hoặc authentication tag: loại bỏ, không ACK.
- Server giải mã ở phiên người gửi, rồi mã hóa lại với khóa phiên người nhận.

## 4. Loại gói

| Mã | Tên | Reliable | Payload |
|---:|---|---|---|
| 1 | UDP_BIND | Có | JSON {} |
| 2 | UDP_BIND_OK | Có | JSON {} |
| 3 | HEARTBEAT | Không | JSON {} |
| 4 | USER_LIST | Có | JSON phân trang |
| 5 | CHAT | Có | JSON |
| 6 | ACK | Không | !II: ack_stream_id, ack_seq |
| 7 | CHAT_STATUS | Có | JSON |
| 8 | FILE_OFFER | Có | JSON |
| 9 | FILE_ACCEPT | Có | JSON |
| 10 | FILE_REJECT | Có | JSON |
| 11 | FILE_CHUNK | Có | !I chunk_index + raw bytes |
| 12 | FILE_END | Có | JSON |
| 13 | FILE_RESULT | Có | JSON |
| 14 | ERROR | Có | JSON |
| 15 | LOGOUT | Có | JSON {} |

JSON serialize UTF-8 compact, ensure_ascii=False. Kiểm tra giới hạn plaintext sau serialize, không tính theo số ký tự.

## 5. Luồng, ACK và lỗi truyền

- Stream 0: heartbeat và ACK, không ordered delivery.
- Stream 1: quản lý phiên/presence/error chung.
- Stream 2: CHAT và CHAT_STATUS.
- Stream >=3: một file transfer trên mỗi luồng. Client mở ID lẻ từ 3, server mở ID chẵn từ 4. Không tái sử dụng ID trong phiên.
- seq bắt đầu 1 cho mỗi chiều/luồng. Tạo phiên mới trước khi bộ đếm vượt phạm vi; không wrap.
- Reliable stream dùng Selective Repeat, cửa sổ gửi/nhận 16 gói. Sender chỉ gửi seq nằm trong [send_base, send_base+15]; ACK gói sau không mở thêm cửa sổ nếu send_base chưa được ACK.
- Receiver lưu gói trong cửa sổ rồi ACK, giao cho ứng dụng theo thứ tự liên tục. Gói đã nhận trùng ACK lại, không giao lại. Gói vượt cửa sổ không ACK.
- ACK payload gồm ID luồng và số thứ tự của gói được xác nhận. ACK không cần ACK; không được đưa vào cơ chế ordered delivery của luồng đích.
- Timeout ban đầu 500 ms, backoff nhân đôi tối đa 4 giây; tối đa 8 lần truyền lại ngoài lần gửi đầu.
- Hết lần thử: báo failure, đóng luồng bị lỗi để không kẹt thứ tự. Luồng file thất bại chỉ hủy file đó; lỗi stream 1 hoặc 2 đưa client về trạng thái cần kết nối lại.
- Hàng đợi và bộ đệm có giới hạn; không ACK dữ liệu chưa có khả năng giữ. Callback ứng dụng phải chuyển dữ liệu nhanh sang hàng đợi xử lý, không block socket loop.
- ACK ở chặng client→server không chứng minh client nhận cuối cùng đã nhận.
- Scheduling round-robin giữa luồng; ưu tiên ACK/control và chat, tránh file chiếm mọi lượt gửi. Đây không phải BBR/CUBIC.

## 6. Chat

Client→server:
```json
{"message_id":"UUID","to":"u02","text":"Chào bạn!"}
```
Server→recipient:
```json
{"message_id":"UUID","from":"u01","to":"u02","text":"Chào bạn!","sent_at":"2026-10-10T16:00:00Z"}
```

- to=null là global chat cho các người khác online tại thời điểm server chấp nhận.
- text không rỗng, tối đa 800 byte UTF-8; user_id tối đa 32 ký tự ASCII. Tổng payload vẫn phải <=1149 byte.
- Server lấy from từ phiên, không tin client tự khai báo. ID dùng UUID dạng chuỗi.
- CHAT_STATUS: message_id, recipient_id, status (accepted/delivered/failed), error_code (null hoặc mã).
- queued là trạng thái cục bộ. accepted là server nhận vào hàng đợi; delivered khi client đích ACK gói CHAT. Không có nghĩa người dùng đã đọc.
- Tin global theo dõi trạng thái riêng cho từng người nhận. Không có người nhận: failed/NO_RECIPIENTS.
- Dedupe message_id theo người gửi trong phiên. Retry transport không tạo message_id mới.

## 7. Truyền tệp

FILE_OFFER gửi trên luồng file mới:
```json
{"transfer_id":"UUID","to":"u02","filename":"report.pdf","size":245760,"chunk_size":1024,"total_chunks":240,"sha256":"64_HEX_CHARACTERS"}
```

Server chuyển offer trên luồng mới của phiên nhận, thêm from. Server giữ ánh xạ (phiên gửi, stream gửi) ↔ (phiên nhận, stream nhận); không dùng chung seq giữa hai chặng.

- Giới hạn v1: 100 MiB mỗi tệp, filename UTF-8 <=255 byte, một người nhận/tệp.
- chunk_size=1024; total_chunks=ceil(size/1024). Tệp rỗng hợp lệ, total_chunks=0.
- FILE_ACCEPT: {transfer_id}; FILE_REJECT: {transfer_id,reason}.
- Chờ chấp nhận tối đa 60 giây. Chỉ gửi dữ liệu sau FILE_ACCEPT.
- FILE_CHUNK gồm uint32 chunk_index bắt đầu 0 và byte tệp. Mọi chunk trừ cuối đủ 1024 byte; chunk cuối đúng số byte còn lại. Luồng xác định transfer_id.
- Người gửi gửi FILE_END {transfer_id} sau khi các chunk được ACK trên chặng gửi, cùng luồng với chunk.
- Server chuyển tiếp có bộ đệm giới hạn/backpressure, không tích lũy toàn bộ tệp trong RAM.
- Người nhận chỉ hoàn tất khi đủ chunk, đúng size và SHA-256; ghi tệp tạm, sau kiểm tra mới đổi tên.
- FILE_RESULT: {transfer_id,status:"completed"|"failed",error_code:null|"CHECKSUM_MISMATCH"|...}. Server chuyển kết quả về người gửi.
- FILE_END hoặc ACK từ server không thay thế FILE_RESULT completed.
- Chỉ dùng basename; nơi lưu do client nhận quyết định. Không ghi đè tệp có sẵn, không dùng đường dẫn từ bên gửi.
- Thất bại/mất phiên: dọn tệp tạm và báo lỗi. V1 không resume sau đăng nhập lại, không có API hủy chủ động.

## 8. Presence và đóng phiên

- Hai phía gửi HEARTBEAT mỗi 5 giây sau bind; nhận bất kỳ gói xác thực hợp lệ nào cập nhật last_seen.
- 15 giây không có gói hợp lệ: peer offline, thất bại các thao tác đang chờ.
- USER_LIST: {revision,part_index,part_count,users:[{user_id,username}]}.
- part_index bắt đầu 0; mỗi phần <=1149 byte plaintext. Client chỉ thay danh sách khi đủ phần cùng revision, bỏ revision cũ. Server gửi snapshot sau bind và khi online list đổi.
- LOGOUT reliable trên stream 1. Server ACK rồi dọn phiên; giữ trạng thái tối thiểu để ACK lại LOGOUT trùng trong 60 giây, không nhận hoạt động mới của phiên đó.

## 9. Mã lỗi và kiểm thử

ERROR JSON: {code,message,reference_id}; reference_id là message_id/transfer_id hoặc null.

Mã: INVALID_CREDENTIALS, ALREADY_LOGGED_IN, INVALID_SESSION, USER_OFFLINE, NO_RECIPIENTS, INVALID_PACKET, PAYLOAD_TOO_LARGE, TRANSFER_REJECTED, TRANSFER_TIMEOUT, CHECKSUM_MISMATCH, FILE_TOO_LARGE, IO_ERROR, DELIVERY_TIMEOUT.

Kiểm thử: encode/decode đúng 23 byte header; framing TCP bị chia/gộp; UDP mất/trùng/sai thứ tự; ACK mất; receiver window đầy; timeout; 10–20 client; chat khi truyền file; hash file rỗng/nhỏ/lớn; tag sai; logout/relogin không dùng khóa cũ.

## 10. Phân công

Người 1: codec, ACK/retry/window và scheduling. Người 2: server/session/presence/routing. Người 3: client điều phối và HTTP bridge. Người 4: file transfer. Người 5: UI và mã hóa, phối hợp người 2 về khóa phiên. Mọi thay đổi wire format phải sửa tài liệu này trước khi tích hợp.
