from protocol import CryptoContext, AppError

def create_context(key: bytes, nonce_prefix: bytes, counter: int=0) -> CryptoContext:
    return CryptoContext(key=key, nonce_prefix=nonce_prefix, counter=counter)

def encrypt(ctx: CryptoContext, aad:bytes, plaintext: bytes) ->bytes:
    return ctx.encrypt(aad, plaintext)

def decrypt(ctx: CryptoContext, aad:bytes, wire_payload: bytes) ->bytes:
    return ctx.decrypt(aad, wire_payload)

