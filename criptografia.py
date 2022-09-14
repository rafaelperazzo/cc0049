import base64
import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def gerarChave(password):
    salt = os.urandom(16)
    salt = b'1234567'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return (key)

def encriptar(texto,chave):
    f = Fernet(chave)
    encriptado = f.encrypt(texto.encode())
    return encriptado.decode()

def decriptar(texto,chave):
    f = Fernet(chave)
    decriptado = f.decrypt(texto.encode())
    return (decriptado.decode())
