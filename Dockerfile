FROM python:3.11-slim

WORKDIR /srv

COPY app ./app
COPY tests ./tests
COPY verify ./verify

ENV PORT=8000 \
    DATA_DIR=/data \
    PYTHONUNBUFFERED=1

EXPOSE 8000

CMD ["python", "-m", "app.server"]
