"""Nguoi 5: lop ma hoa/giiai ma dung thu vien mat ma tieu chuan.

Hop dong 1a_api.md muc 5::

    encrypt(ctx, aad, plaintext) -> bytes   # nonce + ciphertext + tag
    decrypt(ctx, aad, wire_payload) -> bytes

- Dung AES-256-GCM qua ``cryptography`` (thu vien tieu chuan), raw header
  lam AAD theo 1b muc 3.
- ``ctx`` la :class:`protocol.CryptoContext`: khoa 32 byte, prefix 4 byte,
  counter uint64 duoc khoa dong bo (thread-safe), tang tren toan bo luong
  mot chieu; truyen lai giu nguyen datagram, khong ma hoa lai voi nonce cu.
- Khong ghi khoa/mat khau/nonce vao log. Sai tag/prefix -> AppError,
  transport loai bo, khong ACK (1b muc 3).
- Khoa/phien do TLS cap (nguoi 2) va client giu (nguoi 3); module nay khong
  truyen khoa qua UI va khong cham toi socket/UDP.
"""
from __future__ import annotations

from protocol import AppError, CryptoContext  # noqa: F401  (tai xuat cho nguoi 1-3 dung)

__all__ = ["CryptoContext", "create_context", "encrypt", "decrypt"]


def create_context(key: bytes, nonce_prefix: bytes, counter: int = 0) -> CryptoContext:
    """Tao mot chieu AES-256-GCM. Key 32 byte, prefix 4 byte, counter bat dau 0."""
    return CryptoContext(key=key, nonce_prefix=nonce_prefix, counter=counter)


def encrypt(ctx: CryptoContext, aad: bytes, plaintext: bytes) -> bytes:
    """Ma hoa, tra ve nonce (12) + ciphertext + tag (16). Counter tang co khoa."""
    return ctx.encrypt(aad, plaintext)


def decrypt(ctx: CryptoContext, aad: bytes, wire_payload: bytes) -> bytes:
    """Giai ma va xac thuc tag/AAD. Sai -> AppError(INVALID_PACKET)."""
    return ctx.decrypt(aad, wire_payload)
