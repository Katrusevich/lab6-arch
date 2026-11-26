# Юніт-тести для Encrypt / Decrypt (Завдання 1 і 2) та перевірка всього каналу (Завдання 3).
# Головна ідея: якщо зашифрувати, а потім розшифрувати, маємо отримати той самий текст.

import json

import pytest
from fastapi.testclient import TestClient

from common.crypto_service import AesService, RsaService
from server.main import app

rsa = RsaService()
aes = AesService()


def test_rsa_encrypt_decrypt():
    keys = rsa.generate_crypto_keys()
    cipher = rsa.encrypt(keys.public_key, "Привіт, RSA!")
    assert cipher != "Привіт, RSA!"                                  # текст справді зашифровано
    assert rsa.decrypt(keys.private_key, cipher) == "Привіт, RSA!"  # і розшифровано назад


def test_rsa_wrong_key_fails():
    # Чужим приватним ключем розшифрувати не можна.
    cipher = rsa.encrypt(rsa.generate_crypto_keys().public_key, "secret")
    with pytest.raises(Exception):
        rsa.decrypt(rsa.generate_crypto_keys().private_key, cipher)


def test_aes_encrypt_decrypt():
    key = aes.generate_secret_key()
    cipher = aes.encrypt(key, "Привіт, AES!")
    assert cipher != "Привіт, AES!"
    assert aes.decrypt(key, cipher) == "Привіт, AES!"


def test_aes_wrong_key_fails():
    # Чужим AES-ключем отримати початковий текст не можна (буде помилка або «сміття»).
    cipher = aes.encrypt(aes.generate_secret_key(), "secret")
    try:
        result = aes.decrypt(aes.generate_secret_key(), cipher)
    except Exception:
        result = None
    assert result != "secret"


def test_api_rsa_endpoints():
    client = TestClient(app)
    new_id = client.post("/api/crypto-keys/generate/rsa-keys").json()["id"]
    assert client.get(f"/api/crypto-keys/rsa-public-key/{new_id}").status_code == 200
    assert client.get("/api/crypto-keys/rsa-public-key/99999").status_code == 404


def test_full_secure_channel():
    # Повторюю дії клієнта з діаграми, але через тестовий клієнт без запуску сервера.
    client = TestClient(app)
    response = client.get("/api/secure/public-key")
    public_key, rsa_id = response.json(), response.headers["x-rsa-id"]

    aes_key = aes.generate_secret_key()
    info = json.dumps({"sessionId": "test-session", "key": aes_key.key, "iv": aes_key.iv})
    response = client.post("/api/secure/session", json={"data": rsa.encrypt(public_key, info)},
                           headers={"x-rsa-id": rsa_id})
    assert response.json()["status"] == "ok"

    response = client.post("/api/secure/message", json={"data": aes.encrypt(aes_key, "Hello")},
                           headers={"x-session-id": "test-session"})
    assert aes.decrypt(aes_key, response.json()["data"]).startswith("Hello. Received:")
