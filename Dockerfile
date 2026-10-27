# Obraz bazowy przypięty do digestu (powtarzalne buildy). Aktualizacja: docker pull python:3.14-slim
# i podmiana digestu z `docker image inspect python:3.14-slim --format '{{index .RepoDigests 0}}'`.
FROM python:3.14-slim@sha256:82abc9f53600280b0757126f83c5a7d47088592d2acb6b4c0b9e97f76865508c

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# unar — narzędzie dla rarfile (archiwa RAR, także na hasło)
RUN apt-get update \
    && apt-get install -y --no-install-recommends unar \
    && rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --uid 1000 miemli
WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
# Kod należy do roota: po ewentualnym przejęciu procesu aplikacji nie da się go podmienić
RUN SECRET_KEY=build python manage.py collectstatic --noinput

USER miemli
ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["gunicorn", "miemli.wsgi", "-b", "0.0.0.0:8000", "--workers", "3", "--timeout", "60"]
