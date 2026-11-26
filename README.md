# Лабораторна робота №6 — шифрований канал (RSA + AES)

## Структура

| Папка / файл | Що це |
|---|---|
| `common/crypto_service.py` | спільний модуль: `RsaService`, `AesService` (Завдання 1, 2) |
| `server/main.py` | Web API на FastAPI, сховище в пам'яті |
| `client/client.py` | консольний клієнт (Завдання 3) |
| `tests/test_crypto.py` | юніт-тести |
| `Dockerfile` | контейнер сервера |
| `.github/workflows/ci.yml` | CI: тести + збірка Docker |

## Ендпоінти

| Метод | Шлях | Опис |
|---|---|---|
| POST | `/api/crypto-keys/generate/rsa-keys` | нова пара RSA, повертає `id` (400 при помилці) |
| GET | `/api/crypto-keys/rsa-public-key/{id}` | публічний ключ base64 (404, якщо немає) |
| GET | `/api/secure/public-key` | випадковий публічний ключ + заголовок `x-rsa-id` |
| POST | `/api/secure/session` | заголовок `x-rsa-id`, тіло `{"data": RSA(sessionId, key, iv)}` |
| POST | `/api/secure/message` | заголовок `x-session-id`, тіло `{"data": AES(текст)}` |

## Запуск

Усі команди — з папки проєкту `lab6_arch`.

1. Встановити бібліотеки: `pip install -r requirements.txt`
2. Тести: `python -m pytest -v`
3. Сервер: `python -m uvicorn server.main:app --port 8000`
4. Swagger: http://localhost:8000/docs
5. Клієнт (у другому терміналі): `python client/client.py`
6. Docker: `docker build -t lab6-server .`, потім `docker run --rm -p 8000:8000 lab6-server`
