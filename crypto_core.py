from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

EXT_LENGTH = 12  # الطول الأقصى للامتداد

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_data(data: bytes, password: str, extension: str = '') -> bytes:
    salt = os.urandom(16)
    iv = os.urandom(16)
    key = derive_key(password, salt)

    ext_bytes = extension.encode().ljust(EXT_LENGTH, b'\0')
    full_data = ext_bytes + data  # نضيف الامتداد أولًا ثم نُشفّر كل شيء

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded = padder.update(full_data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    return salt + iv + encrypted

def decrypt_data(encrypted: bytes, password: str) -> tuple[bytes, str]:
    salt = encrypted[:16]
    iv = encrypted[16:32]
    ciphertext = encrypted[32:]

    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    full_data = unpadder.update(padded) + unpadder.finalize()

    ext = full_data[:EXT_LENGTH].rstrip(b'\0').decode(errors='ignore')
    file_data = full_data[EXT_LENGTH:]
    return file_data, ext

def encrypt_text(text: str, password: str) -> str:
    data = text.encode()
    encrypted = encrypt_data(data, password, extension='txt')
    return encrypted.hex()

def decrypt_text(hexdata: str, password: str) -> str:
    encrypted = bytes.fromhex(hexdata)
    decrypted, _ = decrypt_data(encrypted, password)
    return decrypted.decode(errors='ignore')



