Chạy 3 bước theo thứ tự — server trước, bridge sau, rồi mở trình duyệt:

**1. Cài thư viện và sinh chứng chỉ (làm 1 lần):**
```
python -m pip install -r 01_requirements.txt
python tools/gen_cert.py
```

**2. Chạy server chat (giữ terminal này mở):**
```
python server.py
```
Server lắng nghe TCP 9000 + UDP 9001. Tài khoản demo: `user01/pass01` … `user20/pass20`.

**3. Chạy bridge + mở web (terminal khác):**
```
python http_bridge.py
```
Rồi vào trình duyệt: http://127.0.0.1:8080

Muốn chat 2 người trên cùng máy thì mở thêm terminal thứ hai:
```
python http_bridge.py --http-port 8081
```
Người 1 vào `:8080`, người 2 vào `:8081`, đăng nhập 2 tài khoản khác nhau.

Nếu server ở máy khác (IP `192.168.1.10`), chép `certs/ca.crt` từ máy server sang rồi chạy:
```
python http_bridge.py --server-host 192.168.1.10 --ca-file certs/ca.crt
```

Lưu ý: tắt server hoặc bridge bằng `Ctrl+C`. Lỗi thường gặp là mở bridge mà quên bật server — khi đó đăng nhập sẽ kẹt ở `connecting` rồi báo lỗi qua sự kiện.