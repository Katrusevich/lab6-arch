# Спільний модуль (умова 7): цей код використовують і сервер, і клієнт,
# тому я винесла його окремо, щоб не дублювати.
# Реалізацію RSA та AES я не писала сама (умова 8), а взяла бібліотеку cryptography.

import base64
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import MGF1, OAEP
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Перетворення байтів у base64-рядок і назад.
# Base64 потрібен, бо зашифровані дані — це «сирі» байти, а по HTTP зручно передавати текст.
def to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def from_b64(text: str) -> bytes:
    return base64.b64decode(text)


# ---------- Завдання 1. RSA (асиметричне шифрування) ----------
# RSA — це «поштова скринька з щілиною»: кинути лист (зашифрувати) може будь-хто
# з публічним ключем, а відкрити скриньку (розшифрувати) — лише власник приватного ключа.

@dataclass
class RsaKeys:
    public_key: str   # публічний ключ, base64
    private_key: str  # приватний ключ, base64


# OAEP — схема доповнення для RSA, вона робить шифр стійким (рекомендований варіант).
OAEP_PADDING = OAEP(mgf=MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


class RsaService:
    def generate_crypto_keys(self) -> RsaKeys:
        # Генерую пару ключів довжиною 2048 біт.
        private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_bytes = private.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        private_bytes = private.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
        return RsaKeys(public_key=to_b64(public_bytes), private_key=to_b64(private_bytes))

    def encrypt(self, public_key: str, plain_text: str) -> str:
        # Шифрую публічним ключем, результат повертаю як base64-рядок.
        key = serialization.load_der_public_key(from_b64(public_key))
        return to_b64(key.encrypt(plain_text.encode(), OAEP_PADDING))

    def decrypt(self, private_key: str, cipher_text: str) -> str:
        # Розшифровую приватним ключем: на вході base64, на виході звичайний текст.
        key = serialization.load_der_private_key(from_b64(private_key), password=None)
        return key.decrypt(from_b64(cipher_text), OAEP_PADDING).decode()


# ---------- Завдання 2. AES (симетричне шифрування) ----------
# AES — це «звичайний замок з одним ключем»: тим самим ключем і закривають, і відкривають.
# Він працює набагато швидше за RSA, тому повідомлення я шифрую саме ним.

@dataclass
class AesKey:
    key: str  # секретний ключ (32 байти = AES-256), base64
    iv: str   # вектор ініціалізації (16 байт), base64


class AesService:
    def generate_secret_key(self) -> AesKey:
        # os.urandom дає криптографічно випадкові байти.
        return AesKey(key=to_b64(os.urandom(32)), iv=to_b64(os.urandom(16)))

    def _cipher(self, aes_key: AesKey) -> Cipher:
        # Режим CBC: кожен блок залежить від попереднього, а IV задає «старт» для першого блоку.
        return Cipher(algorithms.AES(from_b64(aes_key.key)), modes.CBC(from_b64(aes_key.iv)))

    def encrypt(self, aes_key: AesKey, plain_text: str) -> str:
        # AES шифрує блоками по 16 байт, тому спочатку доповнюю текст (PKCS7) до кратної довжини.
        padder = padding.PKCS7(128).padder()
        data = padder.update(plain_text.encode()) + padder.finalize()
        encryptor = self._cipher(aes_key).encryptor()
        return to_b64(encryptor.update(data) + encryptor.finalize())

    def decrypt(self, aes_key: AesKey, cipher_text: str) -> str:
        # Зворотний порядок: розшифровую, потім прибираю доповнення.
        decryptor = self._cipher(aes_key).decryptor()
        data = decryptor.update(from_b64(cipher_text)) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return (unpadder.update(data) + unpadder.finalize()).decode()
