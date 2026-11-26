# Контейнер для Web-сервісу (умова 5).
FROM python:3.12-slim
WORKDIR /app

# Спочатку ставлю бібліотеки — Docker закешує цей шар і не качатиме їх при кожній збірці.
RUN pip install --no-cache-dir fastapi uvicorn cryptography

# Копіюю лише те, що потрібно серверу: спільний модуль і сам сервер.
COPY common ./common
COPY server ./server

EXPOSE 8000
CMD ["uvicorn", "server.main:app", "--host", "0.0.0.0", "--port", "8000"]
