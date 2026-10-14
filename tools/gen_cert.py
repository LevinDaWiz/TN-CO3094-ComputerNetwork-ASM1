"""Sinh CA tự ký và chứng chỉ server cho TLS cổng đăng nhập.

Kết quả (mặc định trong thư mục ``certs/``):

* ``ca.crt``     - chứng chỉ CA, phát cho các máy client để xác minh server.
* ``ca.key``     - khóa riêng CA, chỉ giữ trên máy sinh chứng chỉ.
* ``server.crt`` - chứng chỉ server do CA ký, SAN gồm localhost, 127.0.0.1
                   và các IP LAN.
* ``server.key`` - khóa riêng server, chỉ để trên máy chạy server.

Các file khóa riêng KHÔNG được commit (đã có trong .gitignore).

Ví dụ::

    python tools/gen_cert.py                       # tự dò IP LAN
    python tools/gen_cert.py --ip 192.168.1.10     # thêm IP cụ thể
"""

import argparse
import datetime
import ipaddress
import os
import socket
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def detect_lan_ip():
    """Đoán IP LAN chính bằng cách "connect" UDP (không gửi gói nào)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        return None if ip.startswith("127.") or ip == "0.0.0.0" else ip
    except OSError:
        return None
    finally:
        s.close()


def _write_key(path, key):
    data = key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())
    # Tạo file với quyền 0600 (trên Linux/macOS) để khóa riêng không bị đọc lén.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _write_cert(path, cert):
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def generate(out_dir, ips=(), dns_names=("localhost",), days=365):
    """Sinh CA + chứng chỉ server vào ``out_dir``; trả về dict đường dẫn."""
    os.makedirs(out_dir, exist_ok=True)
    now = datetime.datetime.now(datetime.timezone.utc)
    start = now - datetime.timedelta(minutes=5)   # bù lệch đồng hồ giữa các máy
    end = now + datetime.timedelta(days=days)

    # --- CA tự ký ---
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CO3094 Demo CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start).not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # --- Chứng chỉ server do CA ký ---
    all_ips = ["127.0.0.1"] + [ip for ip in ips if ip and ip != "127.0.0.1"]
    san = [x509.DNSName(d) for d in dns_names]
    san += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in dict.fromkeys(all_ips)]

    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CO3094 Server")]))
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start).not_valid_after(end)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=False, crl_sign=False,
            content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                       critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    paths = {name: os.path.join(out_dir, name)
             for name in ("ca.crt", "ca.key", "server.crt", "server.key")}
    _write_cert(paths["ca.crt"], ca_cert)
    _write_key(paths["ca.key"], ca_key)
    _write_cert(paths["server.crt"], server_cert)
    _write_key(paths["server.key"], server_key)
    paths["san"] = [str(n.value) for n in san]
    return paths


def main(argv=None):
    p = argparse.ArgumentParser(description="Sinh CA và chứng chỉ server tự ký")
    p.add_argument("--out", default="certs", help="thư mục đầu ra (mặc định %(default)s)")
    p.add_argument("--ip", action="append", default=[],
                   help="IP LAN thêm vào SAN (lặp lại được)")
    p.add_argument("--dns", action="append", default=[],
                   help="tên miền thêm vào SAN ngoài localhost")
    p.add_argument("--no-detect", action="store_true", help="không tự dò IP LAN")
    p.add_argument("--days", type=int, default=365)
    args = p.parse_args(argv)

    ips = list(args.ip)
    if not args.no_detect:
        lan = detect_lan_ip()
        if lan:
            ips.append(lan)
    paths = generate(args.out, ips=ips, dns_names=["localhost"] + args.dns, days=args.days)
    print("Đã sinh chứng chỉ trong", os.path.abspath(args.out))
    print("SAN:", ", ".join(paths["san"]))
    print("Phát ca.crt cho client; giữ ca.key và server.key trên máy server.")


def _utf8_console():
    """Windows: console/pipe mặc định cp1252, in tiếng Việt sẽ lỗi -> ép UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


if __name__ == "__main__":
    _utf8_console()
    main()
