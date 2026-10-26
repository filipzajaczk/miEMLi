# miEMLi

Wewnętrzne narzędzie zespołu CSIRT do analizy podejrzanych wiadomości `.eml` / `.msg`
dołączanych do incydentów w RTIR: czytelny podgląd wiadomości, analiza nagłówków
(SPF/DKIM/DMARC, Received, podszywanie), linki, załączniki z archiwami i zagnieżdżonymi
mailami oraz IOC z relacjami „skąd pochodzi”.

Specyfikacja: `docs/superpowers/specs/2026-10-26-miemli-design.md`

## Uruchomienie (Docker)

```bash
cp .env.example .env          # uzupełnij SECRET_KEY, POSTGRES_PASSWORD, DATABASE_URL, MIEMLI_HOST
docker compose up -d --build
docker compose exec web python manage.py createsuperuser
```

Aplikacja: `https://<MIEMLI_HOST>/`. Konta analityków zakłada się w `/admin/`.

### Klucze API (wzbogacenie IOC)

W `.env`: `GTI_API_KEY`, `CENSYS_API_TOKEN` oraz opcjonalnie `CENSYS_ORG_ID` (tylko gdy token ma rolę
„API Access” w organizacji Censys — inaczej Censys zwraca 403). Pusty klucz = dostawca wyłączony.
Po zmianie `.env`: `docker compose up -d`. Sprawdzenie kluczy (prawdziwe zapytania, nic nie zapisuje):

```bash
docker compose exec web python manage.py sprawdz_api
```

Lookupy wykonuje kontener `worker` (RQ ze schedulerem do ponowień), wyniki są w cache przez 24 h.

Certyfikat: na start Caddy wystawia własny (`tls internal`, przeglądarka pokaże ostrzeżenie).
Przejście na certyfikat z firmowego CA — patrz komentarz w `Caddyfile`.

## Praca lokalna

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest

export SECRET_KEY=dev DEBUG=1 SECURE_COOKIES=0
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

## Struktura

- `mailcore/` — parsowanie i analiza wiadomości (czysty Python, bez Django i bez sieci)
- `analizy/` — aplikacja Django: modele, widoki, ekran analizy
- `tests/samples/` — próbki testowe (prawdziwe zgłoszenia tylko w `tests/samples/private/`, poza repo)
