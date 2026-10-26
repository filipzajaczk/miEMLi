# miemli — etap 4: wzbogacenie IOC (GTI, Censys) — specyfikacja

Data: 2026-10-26
Status: do przeglądu
Rozszerza: `docs/superpowers/specs/2026-10-26-miemli-design.md` (§5 pkt 3–4, §6, §9). W razie
sprzeczności ten dokument ma pierwszeństwo dla zakresu etapu 4.

## 1. Cel i zakres

Po utworzeniu analizy IOC są automatycznie sprawdzane w Google Threat Intelligence (GTI) i Censys.
Wyniki pojawiają się w tabeli IOC i w prawym panelu bez przeładowania strony, z linkiem do pełnej
analizy w danym narzędziu.

**W zakresie**

- Lookupy GTI: plik (SHA256), URL, domena, IP. Lookupy Censys: IP.
- Worker RQ w tle, cache wyników 24 h wspólny dla wszystkich analiz.
- Kolumny GTI / Censys / JOE w tabeli IOC, rozwijane szczegóły, kropki werdyktu w panelu.
- Przycisk „Odśwież wzbogacenie”.
- Ręczny smoke test na prawdziwych kluczach (`manage.py sprawdz_api`).

**Poza zakresem**

- **Joe Sandbox** — odłożony na sam koniec projektu (decyzja 2026-10-26, `NOTES.md`). W tym etapie
  kolumna JOE to wyłącznie link otwierający stronę Joe Sandbox w nowej karcie, bez API i bez
  przekazywania czegokolwiek. Brak klucza Joe w profilu użytkownika i modelu `ZgloszenieJoe`.
- Wysyłka plików do GTI (brak Private Scanning).
- RTIR i raport (etapy 6–7).

## 2. Ustalenia z nagranych odpowiedzi API (2026-10-26)

- **GTI** (`https://www.virustotal.com/api/v3`, nagłówki `x-apikey` oraz `x-tool: miemli` — bez
  `x-tool` brak `gti_assessment`):
  - `data.attributes.gti_assessment.verdict.value`: `VERDICT_MALICIOUS` | `VERDICT_SUSPICIOUS` |
    `VERDICT_BENIGN` | `VERDICT_UNDETECTED` (pole bywa nieobecne),
  - `gti_assessment.threat_score.value` (0–100), `gti_assessment.severity.value` (`SEVERITY_*`),
  - `last_analysis_stats` (`malicious`, `suspicious`, `undetected`, `harmless`, …),
  - domena: `creation_date` (epoch), `registrar`; IP: `country`, `asn`, `as_owner`;
    plik: `type_description`, `meaningful_name`, `names`; wspólne: `tags`, `first_seen_itw_date`,
    `last_analysis_date`,
  - nieznany wskaźnik → `404` z `error.code = NotFoundError`,
  - ID URL-a: base64url adresu bez `=`.
  - Brak nagłówków z informacją o limitach.
- **Censys Platform** (`https://api.platform.censys.io/v3/global/asset/host/{ip}`,
  `Authorization: Bearer <PAT>`):
  - `result.resource.services[]` (`port`, `protocol`, `transport_protocol`),
    `result.resource.autonomous_system` (`asn`, `name`, `bgp_prefix`), `result.resource.location`
    (`country_code`, `country`, `city`), `result.resource.dns.names`,
  - z `?organization_id=` obecny token dostaje `403` („not authorized … for this organization”),
    bez parametru — `200`. **Organization ID jest opcjonalne** (`CENSYS_ORG_ID`).
  - Cloudflare blokuje domyślny User-Agent Pythona (błąd 1010) — klient musi wysyłać własny
    User-Agent.
  - Adres bez usług (np. `192.0.2.1`) zwraca `200` z pustą listą usług.

## 3. Komponenty

### 3.1 Pakiet `integracje/` (czysty Python, bez Django)

| Plik | Odpowiedzialność |
|---|---|
| `wspolne.py` | `WynikDostawcy` (status, skrót, surowe, link), mapowanie HTTP → status, klient `httpx` (timeout 20 s, User-Agent `miemli/<wersja>`) |
| `gti.py` | `KlientGTI.sprawdz(typ, wartosc) -> WynikDostawcy` dla `plik`, `url`, `domena`, `ip` |
| `censys.py` | `KlientCensys.sprawdz_ip(ip) -> WynikDostawcy`; `organization_id` opcjonalne |

**Mapowanie HTTP → status**

| Odpowiedź | Status | Ponawiać? |
|---|---|---|
| 200 | `gotowe` | — |
| 404 | `brak_danych` | nie |
| 429 | `limit` | tak |
| 401, 403 | `blad` („sprawdź klucz lub uprawnienia”) | nie |
| 5xx, timeout, błąd sieci | `blad` | tak |

### 3.2 Django (aplikacja `analizy`)

- **Model `Wzbogacenie`** — wspólny cache, niezależny od analizy:
  - `klucz` (CharField 64, unikalny) = SHA256 z `"<dostawca>:<typ>:<wartosc>"` (bez indeksu na
    długiej wartości),
  - `dostawca` (`gti` | `censys`), `typ`, `wartosc` (TextField), `status`
    (`oczekuje` | `gotowe` | `brak_danych` | `limit` | `blad`), `skrot` (JSON), `surowe` (JSON,
    null), `link` (TextField, null), `blad` (TextField, puste), `zlecono` (DateTime, null),
    `sprawdzono` (DateTime, null).
  - Status `nieskonfigurowane` nie jest zapisywany — wyliczany przy wyświetlaniu z braku klucza.
- **`analizy/zadania.py`**
  - `zaplanuj(analiza, wymus=False) -> int` — liczba zakolejkowanych zadań,
  - `wzbogac(dostawca, typ, wartosc) -> None` — wykonywane przez worker.
- **Kto co sprawdza:** GTI → `plik`, `url`, `domena`, `ip`; Censys → `ip`; `email` → nic.
- **Konfiguracja (`.env`):** `GTI_API_KEY`, `CENSYS_API_TOKEN`, `CENSYS_ORG_ID` (opcjonalne).

## 4. Przepływ danych

1. **Nowa analiza** — po zatwierdzeniu transakcji (`transaction.on_commit`) wywołanie
   `zaplanuj(analiza)`. Dla każdej pary (IOC, dostawca) ze skonfigurowanym kluczem:
   - wynik `gotowe` lub `brak_danych` młodszy niż 24 h → bez zapytania,
   - `oczekuje` zlecone mniej niż 10 min temu → bez ponownego kolejkowania,
   - w pozostałych przypadkach → status `oczekuje`, `zlecono = teraz`, zadanie do kolejki `default`.
2. **Otwarcie istniejącej analizy** — bez automatycznego odpytywania. Kolejkowane są wyłącznie pary
   (IOC, dostawca), dla których nie istnieje żaden wpis `Wzbogacenie` (np. klucz dodany później).
   Przy wyniku wyświetlane jest „sprawdzono <data>”.
3. **Worker** — `wzbogac` wykonuje zapytanie i zapisuje wynik.
   - `limit`: ponowienia po 30 s, 120 s, 300 s; po wyczerpaniu zostaje status `limit`.
   - `blad` z błędu przejściowego (5xx, timeout, sieć): ponowienia po 10 s, 60 s; potem `blad`.
   - `blad` z 401/403: bez ponowień.
4. **Ekran** — tabela IOC i prawy panel są odświeżane fragmentem htmx co 2 s, wyłącznie gdy
   w analizie jest wpis `oczekuje`. Fragment bez wpisów `oczekuje` nie zawiera wyzwalacza, więc
   odpytywanie ustaje. Wpis `oczekuje` starszy niż 10 min jest wyświetlany jako `blad`
   („brak odpowiedzi workera”) i nie podtrzymuje odpytywania.
5. **„Odśwież wzbogacenie”** — przycisk w pasku górnym (POST, wymaga zalogowania):
   `zaplanuj(analiza, wymus=True)` kolejkuje wszystkie pary z pominięciem cache;
   zapis `Zdarzenie(typ="odswiezenie")`.

## 5. Wyświetlanie

### 5.1 Komórka GTI (skrót)

- Werdykt: `MALICIOUS` → `.bad` „złośliwy”; `SUSPICIOUS` → `.warn` „podejrzany”;
  `BENIGN` → `.ok` „nieszkodliwy”; `UNDETECTED` lub brak → `.neutral` „niewykryty”.
- Obok: ocena (`threat_score`) i wykrycia `malicious/(malicious+suspicious+undetected+harmless)`,
  np. `złośliwy · 30 · 64/67`.
- Domena: wiek z `creation_date` — poniżej 30 dni `.warn` („3 dni”), w przeciwnym razie wyciszony
  („27 lat”); brak daty → nic.
- IP: kod kraju (`US`).

### 5.2 Komórka Censys (tylko IP)

- Do 5 usług `port protokół` (np. `53 DNS · 443 HTTP · 853 DNS`), potem „+N”; ASN (`AS15169`).
- Pusta lista usług → „brak otwartych usług”.

### 5.3 Komórka JOE

- Link „JOE ↗” do `https://jbxcloud.joesecurity.org/` w nowej karcie, `rel="noopener noreferrer"`,
  dla IOC typu `plik` i `url`. Bez przekazywania żadnych danych.

### 5.4 Statusy

| Status | Widok |
|---|---|
| `oczekuje` | „…” (pulsujące) |
| `brak_danych` | wyciszone „brak danych” |
| `limit` | `.warn` „limit API”, dymek „ponów odświeżeniem” |
| `blad` | `.bad` „błąd”, dymek z powodem |
| nieskonfigurowane | „—”, dymek „brak klucza w .env” |

### 5.5 Szczegóły (rozwinięcie wiersza IOC)

- GTI: werdykt, ocena, ważność, wykrycia, pierwsze/ostatnie wystąpienie, tagi; plik — typ i nazwy;
  domena — rejestrator i data utworzenia; IP — ASN, właściciel, kraj.
- Censys: wszystkie usługi (port / protokół / transport), ASN z prefiksem BGP, lokalizacja, do 10
  nazw DNS.
- Linki: GTI `https://www.virustotal.com/gui/{file|url|domain|ip-address}/<id>`, Censys
  `https://platform.censys.io/hosts/<ip>`.
- „Sprawdzono: <data>”.

### 5.6 Panel IOC

- Przy każdym IOC kropka w kolorze werdyktu GTI (brak wyniku → bez kropki).

## 6. Bezpieczeństwo

- Odpowiedzi API są danymi niezaufanymi: tylko escapowanie Django, nigdy `|safe`.
- Adresy pochodzące z odpowiedzi (np. `last_final_url`) wyświetlane rozbrojone.
- Klucze wyłącznie w `.env`; nigdy w logach, odpowiedziach HTTP ani nagraniach testowych.
- Logi: dostawca, typ IOC, status, czas — bez wartości kluczy i bez pełnych odpowiedzi.

## 7. Testy

- Nagrania prawdziwych odpowiedzi (GTI: EICAR, nieznany hash, URL `https://www.google.com/`,
  `google.com`, `8.8.8.8`; Censys: `8.8.8.8`, `192.0.2.1`) w `tests/integracje/nagrania/`,
  przycięte do używanych pól. Test sprawdza, że nie zawierają wartości kluczy z `.env`.
- Klienci: `respx` — statusy 200/404/429/403/500/timeout, nagłówek `x-tool`, User-Agent,
  opcjonalne `organization_id`.
- Skróty: EICAR → złośliwy, `64/…`; `google.com` → nieszkodliwy, wiek w latach; `8.8.8.8` →
  usługi DNS/HTTP; `192.0.2.1` → brak usług.
- Zadania: RQ synchronicznie; świeży cache bez zapytania, stary — z zapytaniem, `wymus` zawsze,
  wspólny cache między analizami, brak klucza → brak zadania, ponowienia przy 429.
- Widoki: kolumny, odpytywanie tylko przy `oczekuje`, wpis wiszący > 10 min jako błąd,
  „Odśwież” (POST, login, audyt), escapowanie i rozbrajanie danych z API.
- Ręcznie: `python manage.py sprawdz_api` — prawdziwe zapytania o `8.8.8.8` i EICAR, wypisuje
  statusy (bez kluczy).

## 8. Kolejność budowy

1. `integracje/wspolne.py` (zależności `httpx`, `respx`).
2. Klient GTI + nagrania.
3. Klient Censys.
4. Model `Wzbogacenie`, migracja, `zaplanuj` / `wzbogac`, cache.
5. Ponowienia w workerze.
6. Kolumny w tabeli IOC i odpytywanie htmx.
7. Szczegóły, kropki w panelu, „Odśwież”, link JOE.
8. Docker na prawdziwych kluczach, `sprawdz_api`, README, NOTES.
