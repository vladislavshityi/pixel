import base64
import secrets
import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey


def user_uuid_generator():
    return str(uuid.uuid4())

def short_id_generator():
    return str(secrets.token_hex(8))

def secret_api_key_generator():
    return str(secrets.token_hex(32))

def private_key_generator():
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes_raw()
    private_str = base64.urlsafe_b64encode(private_bytes).rstrip(b"=").decode("utf-8")
    return private_str

def public_key_generator(private_str):
    restored_private_bytes = base64.urlsafe_b64decode(private_str + '=' * (-len(private_str) % 4))
    restored_private_key = X25519PrivateKey.from_private_bytes(restored_private_bytes)
    public_key = restored_private_key.public_key()
    public_bytes = public_key.public_bytes_raw()
    public_str = base64.urlsafe_b64encode(public_bytes).rstrip(b"=").decode("utf-8")
    return public_str