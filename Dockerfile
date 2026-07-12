FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app
RUN groupadd --system secmind && useradd --system --gid secmind --home /app secmind

COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --upgrade pip && pip install ".[postgres,qdrant]"

RUN mkdir -p /app/data/inputs /app/data/uploads /app/data/runs \
    && chown -R secmind:secmind /app
USER secmind

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3)"]

CMD ["uvicorn", "secmind.api:app", "--host", "0.0.0.0", "--port", "8000"]

