FROM python:3.14-slim

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
RUN SECRET_KEY=build python manage.py collectstatic --noinput \
    && chown -R miemli:miemli /app

USER miemli
ENTRYPOINT ["docker/entrypoint.sh"]
CMD ["gunicorn", "miemli.wsgi", "-b", "0.0.0.0:8000", "--workers", "3", "--timeout", "60"]
