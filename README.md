# miEMLi

Wewnętrzne narzędzie zespołu CSIRT do analizy podejrzanych wiadomości `.eml` / `.msg`
dołączanych do incydentów w RTIR: czytelny podgląd wiadomości, analiza nagłówków
(SPF/DKIM/DMARC, Received, podszywanie), linki, załączniki z archiwami i zagnieżdżonymi
mailami oraz artefakty (adresy, domeny, IP, URL-e, pliki) z relacjami „skąd pochodzi”.

Specyfikacja: `docs/superpowers/specs/2026-10-26-miemli-design.md`

## Uruchomienie (Docker)

```bash
cp .env.example .env          # uzupełnij SECRET_KEY, POSTGRES_PASSWORD, DATABASE_URL, MIEMLI_HOST
docker compose up -d --build
docker compose exec web python manage.py createsuperuser
```

Aplikacja: `https://<MIEMLI_HOST>/`. Konta analityków zakłada się w `/admin/`. Każdy analityk zmienia
swoje hasło w profilu (kliknięcie nazwy użytkownika w pasku). Konta z uprawnieniem „w zespole” (`is_staff`)
widzą w pasku „Audyt” — dziennik zdarzeń (werdykty, usunięcia, wysyłki do Joe, zmiany haseł) z filtrami.

Werdykt analityka (phishing / spam / czysty / do weryfikacji) ustawia się na ekranie analizy; widać go
na liście analiz, którą można po nim filtrować.

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

### Joe Sandbox

Analityk ustawia swój klucz API Joe w profilu (kliknięcie nazwy użytkownika w pasku). Klucz jest
szyfrowany kluczem publicznym (`JOE_KLUCZ_PUBLICZNY` w `web`), a odczytać go potrafi tylko worker
(`JOE_KLUCZ_PRYWATNY`). Para kluczy:

```bash
docker compose run --rm worker python manage.py joe_generuj_klucze   # wynik wklej do .env
```

Wysyłka całego maila: sekcja „Analizuj w JOE” w analizie (ponowne wgranie pliku — oryginał nie jest
przechowywany, weryfikacja SHA256) albo checkbox „Wyślij też do Joe Sandbox” przy uploadzie. Parametry:
Live Interaction, internet, bez url-reputation, usunięcie z Joe po 30 dniach; limit `JOE_LIMIT_DZIENNY`
wysyłek na analityka. Status i werdykt Joe śledzi worker (co 30 s, maks. 2 h).

Worker wykonuje wyłącznie zadania z listy dozwolonych (`analizy/rq_worker.py`) — przejęty `web`
(który zna hasło Redisa) nie zleci mu dowolnej funkcji. Zapisane klucze Joe są bezpieczne przy
przejęciu `web` i bazy; klucz wpisany w profilu już po przejęciu `web` mógłby zostać przechwycony.

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
