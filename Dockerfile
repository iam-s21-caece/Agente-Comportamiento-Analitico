# Imagen del agente de análisis de seguridad para Keycloak.
# NOTA: este Dockerfile es SOLO del agente; no toca la imagen de Keycloak.
FROM python:3.12-slim

# Evita prompts y .pyc; salida sin buffer para que docker logs sea inmediato.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Cliente Docker (binario estático liviano) para el fallback H2 (docker exec) y
# para container_metrics cuando se usa la CLI. El SDK de Python (paquete docker)
# habla por el socket montado; la CLI cubre el camino de docker exec.
ARG DOCKER_CLI_VERSION=25.0.5
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates \
    && curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.tgz" \
       | tar -xz --strip-components=1 -C /usr/local/bin docker/docker \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Instalar dependencias primero (mejor cacheo de capas).
COPY requirements.txt ./
RUN pip install -r requirements.txt

# Copiar el código del agente.
COPY . .

# Directorio de datos persistentes (alertas + baseline + trazas), volumen.
RUN mkdir -p /data/alerts /data/traces
ENV ALERTS_DIR=/data/alerts \
    BASELINE_PATH=/data/baseline.json \
    TRACES_DIR=/data/traces

# Por defecto corre en modo continuo (foco de la investigación).
ENTRYPOINT ["python", "main.py"]
CMD ["--mode", "continuous"]
