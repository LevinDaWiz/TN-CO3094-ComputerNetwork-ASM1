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

# ===== Server (Người 2: server.py, sessions.py) =====

# Tài khoản demo: user01..user20, mật khẩu pass01..pass20

# Sinh chứng chỉ TLS (chạy 1 lần trên máy server, gửi certs/ca.crt cho máy client)
python tools/gen_cert.py

# Sinh chứng chỉ khi client ở máy khác trong LAN (thêm IP máy server)
python tools/gen_cert.py --ip 192.168.1.10

# Chạy server (TCP 9000, UDP 9001; Windows Firewall hỏi thì bấm Allow; Ctrl+C để dừng)
python server.py

# Chạy server không TLS (chỉ để debug)
python server.py --no-tls

# Xem các tùy chọn của server (host, cổng, timeout...)
python server.py --help

# Thử đăng nhập
python tools/login_client.py user01 pass01

# Thử đăng nhập từ máy khác trong LAN
python tools/login_client.py user01 pass01 --host 192.168.1.10 --cafile certs/ca.crt

# Thử đăng nhập khi server chạy --no-tls
python tools/login_client.py user01 pass01 --no-tls

# Chỉ test server
python -m unittest discover -s tests -v

# Chỉ test đăng nhập TCP/TLS
python -m unittest tests.test_server_login -v

# Chỉ test tài khoản và phiên
python -m unittest tests.test_accounts tests.test_sessions -v

# Chỉ test chat và danh sách online qua UDP
python -m unittest tests.test_routing tests.test_server_udp tests.test_udp_service -v

# Chỉ test chuyển tiếp tệp qua server
python -m unittest tests.test_file_relay -v

# Chỉ test 20 client cùng lúc
python -m unittest tests.test_many_clients -v

# ===== Truyền tệp (Người 4: file_transfer.py) =====

# Test truyền tệp (server giả lập trong tests/, không phải server.py): mất/trùng/đảo gói + UDP thật
python -m unittest tests.test_file_transfer -v

# Demo A -> server -> B qua UDP localhost (in tiến độ, kiểm tra SHA-256, chat song song)
python tools/file_transfer_demo.py
python tools/file_transfer_demo.py --size-mib 100
python tools/file_transfer_demo.py --file duong_dan_toi_tep.pdf

# ===== Client + HTTP bridge (Người 3: client.py, messaging.py, http_bridge.py) =====

# Mở app chat (cần bật server trước và có certs/ca.crt), vào trình duyệt http://127.0.0.1:8080
python http_bridge.py

# Người thứ hai trên cùng máy (mở terminal khác), vào http://127.0.0.1:8081
python http_bridge.py --http-port 8081

# Kết nối tới server ở máy khác trong LAN (chép certs/ca.crt từ máy server sang)
python http_bridge.py --server-host 192.168.1.10 --ca-file certs/ca.crt

# Xem các tùy chọn (cổng, thư mục lưu tệp nhận...)
python http_bridge.py --help

# Thử API bằng curl: lấy token -> đăng nhập (thay <token>) -> xem sự kiện mới
curl http://127.0.0.1:8080/api/bootstrap
curl -X POST http://127.0.0.1:8080/api/login -H "X-Local-Token: <token>" -H "Content-Type: application/json" -d "{\"username\":\"user01\",\"password\":\"pass01\"}"
curl "http://127.0.0.1:8080/api/events?after=0"

# Test client: đăng nhập, chat, gửi tệp với server thật + HTTP bridge
python -m unittest tests.test_client -v

