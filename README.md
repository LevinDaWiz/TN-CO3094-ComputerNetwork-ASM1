# CO3094 – Ứng dụng cộng tác Client–Server (chat + truyền tệp)

Server Python (TCP/TLS :9000 để đăng nhập, UDP :9001 cho chat/truyền tệp). Mỗi client gồm một **Python client + HTTP bridge** chạy cục bộ và một **giao diện web** mở bằng trình duyệt.

## 0. Yêu cầu

- Python **3.10 trở lên** (đã chạy thử với 3.12), có `pip`.
- Thư viện bên ngoài duy nhất: `cryptography` (khai báo trong `dependencies.txt`).
- Cổng trống: TCP 9000, UDP 9001 (server), TCP 8080 (mỗi bridge; bridge thứ hai dùng 8081).

Tài khoản demo có sẵn (không có đăng ký): `user01 / pass01` … `user20 / pass20`.

## 1. Cài đặt (làm một lần, trên mọi máy)

Mở terminal tại thư mục gốc của dự án (thư mục chứa `server.py`).

```bash
# (khuyến nghị) tạo môi trường ảo
python -m venv .venv

# kích hoạt môi trường ảo
#   Windows (PowerShell):  .venv\Scripts\Activate.ps1
#   Windows (cmd):         .venv\Scripts\activate.bat
#   Linux / macOS:         source .venv/bin/activate

# cài thư viện
python -m pip install -r dependencies.txt
```

Kiểm tra: `python -c "import cryptography; print(cryptography.__version__)"` in ra số phiên bản (≥ 42).

## 2. Sinh chứng chỉ TLS (một lần, chỉ trên máy server)

```bash
python tools/gen_cert.py
```

Lệnh tạo thư mục `certs/` gồm `ca.crt`, `ca.key`, `server.crt`, `server.key`. Chứng chỉ tự dò IP LAN của máy; nếu cần chỉ định IP khác (ví dụ client ở máy khác), chạy `python tools/gen_cert.py --ip 192.168.1.10`.

> Chỉ `ca.crt` được phép chép sang máy client. Không chia sẻ `ca.key`, `server.key`.

## 3. Chạy server

Mở **terminal 1** và giữ nguyên:

```bash
python server.py
```

Server lắng nghe TCP 9000 và UDP 9001. Nếu Windows Firewall hỏi, bấm **Allow**. Dừng server bằng `Ctrl+C`. Xem thêm tùy chọn: `python server.py --help`.

(Tùy chọn) Kiểm tra server đã nhận đăng nhập, ở terminal khác:

```bash
python tools/login_client.py user01 pass01
```

Kết quả là một JSON `LOGIN_OK` (các khóa được che bằng `***`).

## 4. Kết nối client (cùng máy với server)

Mở **terminal 2** (thư mục dự án, đã kích hoạt môi trường ảo):

```bash
python http_bridge.py
```

Mở trình duyệt vào **http://127.0.0.1:8080**, nhập `user01` / `pass01`, bấm Đăng nhập. Trạng thái chuyển `connecting` → `connected` và danh sách người online xuất hiện.

### Client thứ hai trên cùng máy

Mở **terminal 3**:

```bash
python http_bridge.py --http-port 8081
```

Vào **http://127.0.0.1:8081**, đăng nhập bằng tài khoản khác (ví dụ `user02` / `pass02`). Hai client giờ có thể chat chung, chat riêng và gửi tệp cho nhau.

## 5. Kết nối client từ máy khác trong LAN

1. Trên máy server: xem IP LAN (ví dụ `192.168.1.10`), sinh chứng chỉ có IP đó (bước 2 với `--ip 192.168.1.10`), rồi chạy lại server (bước 3). Mở firewall cho TCP 9000 và UDP 9001.
2. Chép `certs/ca.crt` từ máy server sang máy client (đặt vào `certs/ca.crt` trong thư mục dự án của client).
3. Trên máy client, hoàn thành bước 1 rồi chạy:

```bash
python http_bridge.py --server-host 192.168.1.10 --ca-file certs/ca.crt
```

4. Mở **http://127.0.0.1:8080** trên máy client và đăng nhập.

## 6. Sử dụng nhanh

- Cột trái: bấm **Bạn bè** để vào kênh chung `#general`, bấm một người để chat riêng. Tin tối đa 800 byte UTF-8.
- Gửi tệp: chọn một người ở cột trái → nút `+` → **Tải Lên Tệp** (tối đa 100 MiB). Bên nhận bấm **Nhận** hoặc **Từ chối** ở cột phải. Tệp nhận được lưu trong thư mục `downloads/` (đổi bằng `--download-dir`).
- Dừng bridge hoặc server bằng `Ctrl+C`.

## 7. Chạy kiểm thử

```bash
python -m unittest discover -s tests -v
```

Toàn bộ 233 test phải báo `OK` (mất khoảng 30 giây). Demo truyền tệp qua UDP localhost: `python tools/file_transfer_demo.py`.

## 8. Xử lý lỗi thường gặp

| Hiện tượng | Nguyên nhân và cách xử lý |
|---|---|
| Đăng nhập kẹt ở `connecting` rồi báo lỗi | Chưa bật server, hoặc sai `--server-host`. Bật server (bước 3) trước bridge. |
| Lỗi xác minh chứng chỉ TLS | Thiếu `certs/ca.crt` trên máy client, hoặc chứng chỉ không chứa IP server. Sinh lại với `--ip <IP server>` và chép lại `ca.crt`. |
| `ALREADY_LOGGED_IN` | Tài khoản đang được dùng ở nơi khác (mỗi tài khoản một phiên). Dùng tài khoản khác hoặc đợi tối đa 15 giây sau khi client cũ đóng. |
| `INVALID_CREDENTIALS` | Sai tài khoản/mật khẩu; dùng `userNN` / `passNN` (NN từ 01 đến 20). |
| Báo cổng đã được sử dụng | Đổi cổng: `--http-port` cho bridge, `--tcp-port`/`--udp-port` cho server. |
| Client ở máy khác không vào được | Kiểm tra firewall (TCP 9000, UDP 9001) và hai máy cùng mạng LAN. |

## 9. Cấu trúc thư mục chính

- `server.py`, `sessions.py`, `server_udp.py`: server, phiên và tài khoản.
- `client.py`, `messaging.py`, `http_bridge.py`: Python client và HTTP bridge.
- `reliable_udp.py`, `protocol.py`, `framing.py`, `security.py`: truyền UDP tin cậy, mã hóa AES-GCM.
- `file_transfer.py`: truyền tệp.
- `web/`: giao diện web. `tools/`: sinh chứng chỉ và công cụ thử. `tests/`: kiểm thử.
- Đặc tả: `1a_api.md`, `1b_protocol_spec.md`, `docs/sequence.md`.
