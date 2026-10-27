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
docker compose exec worker python manage.py sprawdz_api
```

Klucze API ma tylko kontener `worker` (`web` dostaje jedynie informację, którzy dostawcy są włączeni).
Lookupy wykonuje `worker` (RQ ze schedulerem do ponowień), wyniki są w cache przez 24 h.

Certyfikat: na start Caddy wystawia własny (`tls internal`, przeglądarka pokaże ostrzeżenie).
Przejście na certyfikat z firmowego CA — patrz komentarz w `Caddyfile`.

### Sandbox parsera (izolacja plików od atakującego)

Analizowane pliki dekoduje wyłącznie kontener `parser`: bez sieci (poza połączeniem od `web`), bez
sekretów, bez bazy i Redisa. Każdy plik analizuje świeży proces z limitami (1 GB pamięci, 30 s CPU,
60 s czasu). Obrazki z maili są przekodowywane do PNG, a nietypowe (np. TIFF udający PNG,
gigantyczne wymiary) oznaczane w raporcie obrazków.

**Produkcja — gVisor** (osobne jądro w przestrzeni użytkownika dla parsera):

```bash
# instalacja wg https://gvisor.dev/docs/user_guide/install/ (repozytorium apt), potem:
sudo runsc install
sudo systemctl restart docker
# w .env:
PARSER_RUNTIME=runsc
PARSER_WYMAGA_GVISOR=1
docker compose up -d --build
docker compose exec web python -c "import httpx; print(httpx.get('http://parser:8000/zdrowie').json())"
# oczekiwane: {'gvisor': True, ...}; przy braku gVisor aplikacja pokazuje czerwony baner
```

### Bezpieczeństwo kontenerów

- `web` i `worker`: system plików tylko do odczytu (zapis tylko w `tmpfs`), bez capabilities,
  `no-new-privileges`, limity pamięci i procesów; kod aplikacji należy do roota.
- Sieć `wewnetrzna` nie ma wyjścia do internetu — `web`, Postgres i Redis nie mogą łączyć się na zewnątrz.
  Do internetu wychodzą tylko `caddy` (HTTPS dla analityków) i `worker` (GTI, Censys).
- Redis wymaga hasła (`REDIS_PASSWORD` w `.env`), a zadania RQ są serializowane jako JSON (nie pickle).
- Skan zależności: `.venv/bin/pip-audit -r requirements.txt -r requirements-parser.txt`.

## Praca lokalna

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pytest

# PIASKOWNICA_URL= (pusty): analiza w procesie runserver, BEZ sandboxa — tylko do pracy nad kodem
export SECRET_KEY=dev DEBUG=1 SECURE_COOKIES=0 PIASKOWNICA_URL=
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

## Struktura

- `mailcore/` — parsowanie i analiza wiadomości (czysty Python, bez Django i bez sieci)
- `analizy/` — aplikacja Django: modele, widoki, ekran analizy
- `tests/samples/` — próbki testowe (prawdziwe zgłoszenia tylko w `tests/samples/private/`, poza repo)
