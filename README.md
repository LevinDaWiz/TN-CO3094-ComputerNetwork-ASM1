# CO3094 – Ứng dụng cộng tác client–server

Tài liệu thiết kế: [1b_protocol_spec.md](1b_protocol_spec.md) (giao thức mạng),
[1a_api.md](1a_api.md) (API HTTP và hợp đồng module Python),
[protocol_report.md](protocol_report.md) (codec và UDP tin cậy),
[0_HowToRunCode.md](0_HowToRunCode.md) (cách chạy test transport).

## Cài đặt

Yêu cầu Python 3.10+.

```bash
python -m pip install -r 01_requirements.txt
```

## Server (Người 2)

### 1. Sinh chứng chỉ TLS (lần đầu, trên máy chạy server)

TLS **bật mặc định** vì `LOGIN_OK` chứa khóa AES của phiên.

```bash
python tools/gen_cert.py                   # tạo certs/ca.crt, ca.key, server.crt, server.key
python tools/gen_cert.py --ip 192.168.1.10 # thêm IP LAN cụ thể (mặc định tự dò)
```

Gửi **chỉ** `certs/ca.crt` cho các máy client. Client luôn xác minh chứng chỉ
bằng CA này (không tắt xác minh) và phải kết nối bằng `localhost`, `127.0.0.1`
hoặc IP LAN có trong chứng chỉ; nếu IP server đổi thì sinh lại. Thư mục `certs/`
nằm trong `.gitignore`, không commit khóa riêng.

### 2. Chạy server

```bash
python server.py                                # TLS, 0.0.0.0, TCP 9000, UDP 9001
python server.py --host 0.0.0.0 --tcp-port 9000 --udp-port 9001 --login-timeout 10                  --cert certs/server.crt --key certs/server.key
python server.py --no-tls                       # CHỈ để debug: khóa phiên đi dạng rõ
```

Xem tất cả tùy chọn: `python server.py --help`.

> Hiện mới xong phần TCP login (`server.py`). Server thật chạy được khi
> `sessions.py` có `authenticate()` (bước tiếp theo). Phần UDP 9001 chưa làm.

### 3. Client thử đăng nhập

```bash
python tools/login_client.py user01 <mật khẩu>                                   # TLS, CA certs/ca.crt
python tools/login_client.py user01 <mật khẩu> --host 192.168.1.10 --cafile certs/ca.crt
python tools/login_client.py user01 <mật khẩu> --no-tls                          # server chạy --no-tls
```

Khóa phiên trong LOGIN_OK được che (`***`) khi in.

### Giao thức đăng nhập (tóm tắt)

Frame TCP: `[length: uint32 big-endian][JSON UTF-8]`, length trong 1..65536.
Hàm đọc/ghi frame nằm trong [framing.py](framing.py), dùng chung cho server và
client: `from framing import send_frame, recv_frame`. Lỗi frame là
`protocol.AppError` có `code`.

Mỗi kết nối gửi đúng một `LOGIN`, server trả `LOGIN_OK` hoặc `ERROR` rồi đóng.

| Tình huống | Mã lỗi |
|---|---|
| Sai tài khoản/mật khẩu | `INVALID_CREDENTIALS` |
| Tài khoản đang có phiên | `ALREADY_LOGGED_IN` |
| length = 0, JSON hỏng, thiếu trường, type khác `LOGIN` | `INVALID_PACKET` |
| length > 65536, username > 64 byte hoặc password > 1024 byte | `PAYLOAD_TOO_LARGE` |

Client im lặng quá `--login-timeout` giây bị đóng kết nối.

## Kiểm thử

```bash
python -m unittest discover -s . -v        # toàn bộ test của nhóm
python -m unittest discover -s tests -v    # chỉ test server/sessions
```
