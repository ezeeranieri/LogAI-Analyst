# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /app

# Instalar dependencias del sistema necesarias
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Instalar librerías de Python
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# Stage 2: Runner
FROM python:3.11-slim as runner

WORKDIR /app

# Crear usuario no privilegiado para seguridad (Hardening)
RUN adduser --disabled-password --gecos "" appuser

# Copiar solo las librerías instaladas desde el stage anterior
COPY --from=builder /install /usr/local

# Copiar el código de la aplicación
COPY src/ ./src/
COPY main.py .
COPY .env .

# Preparar directorio de datos y logs con permisos correctos
RUN mkdir -p /app/data && chown -R appuser:appuser /app

# Cambiar al usuario no privilegiado
USER appuser

# Crear volumen para persistencia
VOLUME /app/data

# Exponer el puerto de FastAPI
EXPOSE 8000

# Variables de entorno para producción
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Comando para iniciar la aplicación con Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
