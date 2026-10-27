# Obraz bazowy przypięty do digestu (powtarzalne buildy). Aktualizacja: docker pull python:3.14-slim
# i podmiana digestu z `docker image inspect python:3.14-slim --format '{{index .RepoDigests 0}}'`.
FROM python:3.14-slim@sha256:82abc9f53600280b0757126f83c5a7d47088592d2acb6b4c0b9e97f76865508c AS baza

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1
WORKDIR /app


# --- parser: jedyne miejsce, w którym dekodowane są dane z analizowanych plików -------------------
# Tylko mailcore + piaskownica i biblioteki parsujące. Bez Django, bez klienta bazy, bez sekretów.
FROM baza AS parser

# unar — narzędzie dla rarfile (archiwa RAR, także na hasło)
RUN apt-get update \
    && apt-get install -y --no-install-recommends unar \
    && rm -rf /var/lib/apt/lists/*

COPY requirements-parser.txt .
RUN pip install -r requirements-parser.txt
COPY mailcore/ mailcore/
COPY piaskownica/ piaskownica/

USER 65534:65534
CMD ["python", "-E", "-s", "-m", "piaskownica.serwer"]


# --- web i worker: Django; pliki od atakującego analizuje wyłącznie parser ------------------------
FROM baza AS web

RUN useradd --create-home --uid 1000 miemli
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .
# Kod należy do roota: po ewentualnym przejęciu procesu aplikacji nie da się go podmienić
RUN SECRET_KEY=build python manage.py collectstatic --noinput

USER miemli
ENTRYPOINT ["docker/entrypoint.sh"]
# timeout > czasu analizy w sandboxie (60 s) + oczekiwania w kolejce
CMD ["gunicorn", "miemli.wsgi", "-b", "0.0.0.0:8000", "--workers", "3", "--timeout", "120"]
