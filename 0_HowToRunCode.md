# Tải các thư viện còn thiếu trên

python -m pip install -r 01_requirements.txt

# Nếu chạy toàn bộ test

python -m unittest discover -s . -v

# Nếu chạy test giả như là: 

# Chỉ test đóng gói/giải mã
python -m unittest test_protocol_transport.CodecTests -v

# Chỉ test truyền UDP tin cậy
python -m unittest test_protocol_transport.TransportTests -v

# Chỉ test mất ACK
python -m unittest test_protocol_transport.TransportTests.test_lost_ack -v

# ===== Server và tài khoản (Người 2: server.py, sessions.py) =====

# Tài khoản demo (không có đăng ký): user01..user20 / mật khẩu pass01..pass20
# user_id tương ứng u01..u20. Mật khẩu chỉ để demo.
# accounts.json chỉ lưu hash PBKDF2-HMAC-SHA256 (600000 vòng, salt riêng từng tài khoản).
# Sinh lại accounts.json (salt mới, mật khẩu giữ nguyên):
python tools/make_accounts.py --force

# Sinh chứng chỉ TLS (lần đầu, trên máy chạy server; tự dò IP LAN, thêm --ip nếu cần)
# Chỉ gửi certs/ca.crt cho máy client; KHÔNG commit thư mục certs/ (có khóa riêng).
python tools/gen_cert.py
python tools/gen_cert.py --ip 192.168.1.10

# Chạy server (TLS bật mặc định; TCP 9000, UDP 9001)
python server.py
python server.py --host 0.0.0.0 --tcp-port 9000 --udp-port 9001 --login-timeout 10 --accounts accounts.json
python server.py --help

# Phiên đăng nhập nhưng chưa bind UDP bị xóa sau 15 giây; chỉnh khi test:
python server.py --unbound-timeout 3

# Chỉ để debug: tắt TLS (khóa phiên sẽ đi dạng rõ)
python server.py --no-tls

# Client thử đăng nhập (xác minh chứng chỉ bằng certs/ca.crt)
python tools/login_client.py user01 pass01
python tools/login_client.py user01 pass01 --host 192.168.1.10 --cafile certs/ca.crt
python tools/login_client.py user01 pass01 --no-tls

# Chỉ test server/tài khoản
python -m unittest discover -s tests -v
python -m unittest tests.test_server_login -v
python -m unittest tests.test_accounts -v
python -m unittest tests.test_sessions -v
