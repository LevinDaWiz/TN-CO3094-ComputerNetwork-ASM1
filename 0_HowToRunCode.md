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