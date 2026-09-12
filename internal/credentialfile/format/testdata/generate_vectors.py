"""Independent public fixtures: Python cryptography/OpenSSL and system libargon2.

Development-only dependencies, never imported by XOps or required by Go tests.
Run from any directory; overwrites only adjacent, checked-in fixture JSON files.
"""
import ctypes
import ctypes.util
import base64
import hashlib
import hmac
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def lp(b):
    return struct.pack(">H", len(b)) + b


def header(magic, fields, payload_len):
    return magic + struct.pack(">HHI", 1, 16 + len(fields), payload_len) + fields


def hkdf(key, salt, info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(key)


vault = bytes(range(16))
dek = bytes(range(32))
file_key = bytes(range(32, 64))
nonce = bytes(range(12))
store = b"offline"
item = b"0123456789abcdef0123456789abcdef"
secret = b"public server password"
password = b"public-test-password-only"
salt = b"public-test-salt"
argon = ctypes.CDLL(ctypes.util.find_library("argon2"))
argon.argon2id_hash_raw.argtypes = [ctypes.c_uint32, ctypes.c_uint32, ctypes.c_uint32,
                                  ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
                                  ctypes.c_size_t, ctypes.c_void_p, ctypes.c_size_t]
argon.argon2id_hash_raw.restype = ctypes.c_int
output = ctypes.create_string_buffer(32)
assert argon.argon2id_hash_raw(3, 65536, 1, password, len(password), salt, len(salt), output, 32) == 0
password_key = output.raw


def meta(suite, meta_salt, key):
    params = (65536, 3, 1) if suite == 1 else (0, 0, 0)
    fields = struct.pack(">HH", suite, 1) + vault + struct.pack(">QQIIBB", 1, 1, *params, len(meta_salt))
    fields += meta_salt + nonce + lp(store)
    h = header(b"XOPSMETA", fields, 48)
    return h + AESGCM(key).encrypt(nonce, dek, h)


file_salt = bytes(range(64, 96))
file_info = lp(b"XOps/encrypted-file/v1/key-file-wrap") + vault + lp(store)
wrapping_key = hkdf(file_key, file_salt, file_info)
meta_password = meta(1, salt, password_key)
meta_file = meta(2, file_salt, wrapping_key)


def item_file(expiry):
    fields = struct.pack(">H", 1) + vault + struct.pack(">Q", 1) + nonce
    fields += struct.pack(">Bq", expiry is not None, expiry or 0) + lp(store) + lp(item)
    h = header(b"XOPSITEM", fields, len(secret) + 16)
    return h + AESGCM(dek).encrypt(nonce, secret, h)


budget_info = lp(b"XOps/encrypted-file/v1/budget-mac") + lp(store) + struct.pack(">Q", 1)
budget_key = hkdf(dek, vault, budget_info)
budget_header = header(b"XOPSBUDG", struct.pack(">H", 1) + vault + struct.pack(">QQQ", 1, 3, 4) + lp(store), 32)
budget = budget_header + hmac.digest(budget_key, budget_header, "sha256")
current = header(b"XOPSCURR", vault + struct.pack(">QQ", 1, 1) + hashlib.sha256(meta_file).digest(), 0)
request = b"XOPSKDFQ" + struct.pack(">HIBIIBH", 1, 48 + len(password), 1, 65536, 3, 1, 32)
request += salt + struct.pack(">IH", 0x13, len(password)) + password
response = b"XOPSKDFR" + struct.pack(">HIBH", 1, 49, 0, 32) + password_key
failure = b"XOPSKDFR" + struct.pack(">HIBH", 1, 17, 1, 0)
block0 = b"XOPSMANF" + struct.pack(">HII", 1, 0, 1) + lp(item) + struct.pack(">I", len(item_file(None))) + hashlib.sha256(item_file(None)).digest()
block1 = b"XOPSMANF" + struct.pack(">HII", 1, 1, 1) + lp(b"z" * 32) + struct.pack(">I", len(item_file(1800000000123456789))) + hashlib.sha256(item_file(1800000000123456789)).digest()
root = hashlib.sha256(b"XOps/manifest/v1" + struct.pack(">I", 2) + hashlib.sha256(block0).digest() + hashlib.sha256(block1).digest()).digest()
empty_root = hashlib.sha256(b"XOps/manifest/v1" + struct.pack(">I", 0)).digest()
target_key = bytes(range(96, 128))
target_meta_hash = hashlib.sha256(b"public target metadata digest input").digest()
tx = b"XOPSTXNS" + struct.pack(">H", 1) + bytes(range(16, 32)) + bytes([3, 3])
tx += vault + vault + lp(store) + lp(store) + struct.pack(">QQQQ", 1, 2, 1, 2)
tx += hashlib.sha256(meta_file).digest() + target_meta_hash + root + root + struct.pack(">QQH", 2, 2, 0)


def tx_mac(key, generation):
    info = lp(b"XOps/encrypted-file/v1/transaction-mac") + lp(store) + struct.pack(">Q", generation)
    return hmac.digest(hkdf(key, vault, info), tx, "sha256")


state = json.dumps({"payload": base64.b64encode(tx).decode(),
                    "source_mac": base64.b64encode(tx_mac(dek, 1)).decode(),
                    "target_mac": base64.b64encode(tx_mac(target_key, 2)).decode()}, separators=(",", ":")).encode()
values = dict(vault=vault, dek=dek, file_key=file_key, nonce=nonce, salt=salt, password=password,
              file_salt=file_salt, password_key=password_key, wrapping_key=wrapping_key,
              meta_password=meta_password, meta_file=meta_file, item=item_file(None),
              item_expiry=item_file(1800000000123456789), budget=budget, current=current,
              request=request, response=response, failure=failure, secret=secret,
              manifest0=block0, manifest1=block1, manifest_root=root, empty_root=empty_root,
              state=state, state_payload=tx, target_key=target_key)
dest = Path(__file__).resolve().parent / "vectors.json"
dest.write_text(json.dumps({k: v.hex() for k, v in values.items()}, indent=2, sort_keys=True) + "\n")
print("Generated public independent fixtures:", dest)
