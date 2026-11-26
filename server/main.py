# Web-сервіс на FastAPI (умови 1, 2).
# FastAPI сам будує опис Open API (умова 4): його видно на /docs (Swagger) і /openapi.json.
# Сховище — звичайні словники в пам'яті (умова 6), бази даних немає.

import json
import random
from datetime import datetime

from fastapi import FastAPI, Header, HTTPException, Response
from pydantic import BaseModel

from common.crypto_service import AesKey, AesService, RsaService

app = FastAPI(title="Lab 6 - Secure channel")

rsa_service = RsaService()
aes_service = AesService()

rsa_storage: dict[int, object] = {}   # id пари RSA -> RsaKeys
sessions: dict[str, AesKey] = {}      # номер сесії -> AES-ключ клієнта


class Envelope(BaseModel):
    # «Конверт» із зашифрованими даними у вигляді base64-рядка.
    data: str


def save_new_rsa_pair() -> int:
    # Генерую пару RSA і кладу в сховище під наступним цілим номером.
    new_id = len(rsa_storage) + 1
    rsa_storage[new_id] = rsa_service.generate_crypto_keys()
    return new_id


# За діаграмою: при старті сервер генерує і зберігає 10 пар RSA-ключів.
for _ in range(10):
    save_new_rsa_pair()


# ---------- Завдання 1 ----------

@app.post("/api/crypto-keys/generate/rsa-keys")
def generate_rsa_keys():
    # Генерую нову пару і повертаю її ідентифікатор. Якщо щось пішло не так — 400 з поясненням.
    try:
        return {"id": save_new_rsa_pair()}
    except Exception as error:
        raise HTTPException(status_code=400, detail=f"Не вдалося згенерувати ключі: {error}")


@app.get("/api/crypto-keys/rsa-public-key/{key_id}")
def get_public_key(key_id: int):
    # Повертаю публічний ключ (base64) за id. Якщо такої пари немає — 404.
    if key_id not in rsa_storage:
        raise HTTPException(status_code=404, detail=f"Пари ключів з id={key_id} немає")
    return rsa_storage[key_id].public_key


# ---------- Завдання 3 (додаткові ендпоінти, назви я визначила сама) ----------

@app.get("/api/secure/public-key")
def get_random_public_key(response: Response):
    # Крок a: сервер випадково обирає пару RSA, віддає публічний ключ,
    # а номер пари кладе в заголовок x-rsa-id.
    key_id = random.choice(list(rsa_storage))
    response.headers["x-rsa-id"] = str(key_id)
    return rsa_storage[key_id].public_key


@app.post("/api/secure/session")
def create_session(body: Envelope, x_rsa_id: int = Header()):
    # Крок e: розшифровую приватним ключем пари x-rsa-id дані клієнта
    # (номер сесії + AES-ключ + IV) і зберігаю їх у пам'яті.
    if x_rsa_id not in rsa_storage:
        raise HTTPException(status_code=404, detail="Невідомий x-rsa-id")
    try:
        info = json.loads(rsa_service.decrypt(rsa_storage[x_rsa_id].private_key, body.data))
        sessions[info["sessionId"]] = AesKey(key=info["key"], iv=info["iv"])
    except Exception:
        raise HTTPException(status_code=400, detail="Не вдалося розшифрувати дані сесії")
    # Підтвердження, що інформацію отримано.
    return {"status": "ok", "sessionId": info["sessionId"]}


@app.post("/api/secure/message")
def secure_message(body: Envelope, x_session_id: str = Header()):
    # Крок g: беру AES-ключ сесії, розшифровую повідомлення, дописую час отримання,
    # шифрую відповідь тим самим ключем і відправляю назад.
    aes_key = sessions.get(x_session_id)
    if aes_key is None:
        raise HTTPException(status_code=404, detail="Невідома сесія")
    try:
        text = aes_service.decrypt(aes_key, body.data)
    except Exception:
        raise HTTPException(status_code=400, detail="Не вдалося розшифрувати повідомлення")
    answer = f"{text}. Received: {datetime.now():%Y-%m-%d %H:%M:%S}"
    return {"data": aes_service.encrypt(aes_key, answer)}
