# Консольний клієнт (Завдання 3).
# Кожне повідомлення проходить увесь шлях з sequence-діаграми:
# публічний ключ -> AES-ключ і сесія -> «рукостискання» через RSA -> повідомлення через AES.

import json
import os
import sys
import uuid

import requests

# Дозволяю запуск командою «python client/client.py»: додаю корінь проєкту в шлях пошуку модулів.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.crypto_service import AesService, RsaService  # noqa: E402

SERVER = os.getenv("SERVER_URL", "http://localhost:8000")

rsa_service = RsaService()
aes_service = AesService()


def send_secure(message: str) -> None:
    # a. Отримую публічний ключ і номер пари з заголовка x-rsa-id.
    response = requests.get(f"{SERVER}/api/secure/public-key")
    response.raise_for_status()
    public_key = response.json()
    rsa_id = response.headers["x-rsa-id"]
    print(f"[1] Отримала публічний ключ, x-rsa-id = {rsa_id}")

    # b. Створюю таємний ключ і вектор ініціалізації для AES.
    aes_key = aes_service.generate_secret_key()
    # c. Створюю номер сесії, до якої належить цей ключ.
    session_id = str(uuid.uuid4())
    print(f"[2] Створила AES-ключ і сесію {session_id}")

    # d. Шифрую дані сесії публічним RSA-ключем і відправляю на сервер.
    session_info = json.dumps({"sessionId": session_id, "key": aes_key.key, "iv": aes_key.iv})
    encrypted_info = rsa_service.encrypt(public_key, session_info)
    response = requests.post(
        f"{SERVER}/api/secure/session",
        json={"data": encrypted_info},
        headers={"x-rsa-id": rsa_id},
    )
    response.raise_for_status()
    print(f"[3] Сервер підтвердив сесію: {response.json()['status']}")

    # f. Шифрую повідомлення AES-ключем і відправляю з заголовком x-session-id.
    encrypted_message = aes_service.encrypt(aes_key, message)
    print(f"[4] Відправляю зашифроване: {encrypted_message}")
    response = requests.post(
        f"{SERVER}/api/secure/message",
        json={"data": encrypted_message},
        headers={"x-session-id": session_id},
    )
    response.raise_for_status()

    # h. Розшифровую відповідь і виводжу її разом з номером сесії.
    encrypted_answer = response.json()["data"]
    print(f"[5] Отримала зашифроване: {encrypted_answer}")
    print(f"[6] Відповідь сервера: {aes_service.decrypt(aes_key, encrypted_answer)}")
    print(f"    Сесія: {session_id}")


def main() -> None:
    print(f"Сервер: {SERVER}. Для виходу введіть exit.")
    # 1, 3. Прошу користувача ввести повідомлення, і так по колу.
    while True:
        message = input("\nВведіть повідомлення: ").strip()
        if message.lower() == "exit":
            break
        if not message:
            continue
        try:
            send_secure(message)
        except requests.RequestException as error:
            print(f"Помилка зв'язку з сервером: {error}")


if __name__ == "__main__":
    main()
