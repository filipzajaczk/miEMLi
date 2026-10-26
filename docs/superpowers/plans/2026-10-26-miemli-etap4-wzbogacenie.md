# miemli — Etap 4: wzbogacenie IOC (GTI, Censys) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** IOC każdej analizy są automatycznie sprawdzane w GTI i Censys przez worker RQ, z cache 24 h, a wyniki pojawiają się w tabeli IOC i panelu bez przeładowania strony; kolumna JOE to zwykły link.

**Architecture:** Czysty pakiet `integracje/` (klienci HTTP na `httpx`, bez Django) zwraca `WynikDostawcy`. Aplikacja `analizy` dostaje model `Wzbogacenie` (wspólny cache), moduł `zadania.py` (planowanie i wykonanie w workerze, ponowienia przez `enqueue_in`) oraz fragmenty htmx odpytywane co 2 s tylko przy wpisach `oczekuje`.

**Tech Stack:** Python 3.14, Django 6.1, django-rq 4.2 (RQ z wbudowanym schedulerem), httpx, respx (testy), htmx 2.0.4.

**Spec:** `docs/superpowers/specs/2026-10-26-miemli-etap4-wzbogacenie-design.md` (rozszerza `docs/superpowers/specs/2026-10-26-miemli-design.md`)

## Global Constraints

- Pakiety tylko w `.venv`; `httpx` do `requirements.txt`, `respx` do `requirements-dev.txt`, wersje przypięte `==` do najnowszych.
- Klucze wyłącznie w `.env`: `GTI_API_KEY`, `CENSYS_API_TOKEN`, `CENSYS_ORG_ID` (opcjonalne). Nigdy w logach, odpowiedziach HTTP, nagraniach testowych ani commitach.
- GTI: baza `https://www.virustotal.com/api/v3`, nagłówki `x-apikey: <klucz>` i `x-tool: miemli`.
- Censys: `https://api.platform.censys.io/v3/global/asset/host/{ip}`, `Authorization: Bearer <token>`, `?organization_id=` tylko gdy `CENSYS_ORG_ID` ustawione.
- Każde zapytanie HTTP: User-Agent `miemli/1.0`, timeout 20 s.
- Statusy w bazie: `oczekuje` | `gotowe` | `brak_danych` | `limit` | `blad`. `nieskonfigurowane` tylko wyliczane przy wyświetlaniu.
- Cache 24 h; `oczekuje` nie jest ponownie kolejkowane przez 10 min; `oczekuje` starsze niż 10 min wyświetlane jako błąd „brak odpowiedzi workera”.
- Ponowienia: `limit` po 30 s, 120 s, 300 s; błąd przejściowy (5xx, timeout, sieć) po 10 s, 60 s; 401/403 bez ponowień.
- Próg nowej domeny: 30 dni.
- Joe: wyłącznie link `https://jbxcloud.joesecurity.org/` (nowa karta, `rel="noopener noreferrer"`) dla IOC `plik` i `url`. Żadnego API Joe.
- Dane z API to dane niezaufane: tylko escapowanie Django (nigdy `|safe`), adresy rozbrojone przez `rozbroj()`.
- Interfejs po polsku, paleta Nord z `static/css/nord.css`, identyfikatory po polsku bez diakrytyków.
- Testy nie wykonują zapytań sieciowych ani nie wymagają Redisa.
- Commity kończą się linią `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Worker nie działa** (kontener padł) → wpisy wiszą w `oczekuje`; po 10 min ekran pokazuje „błąd: brak odpowiedzi workera” i przestaje odpytywać. Test: Task 6.
2. **Niepełna odpowiedź GTI** (brak `gti_assessment`, brak `verdict`, brak `last_analysis_stats`, brak `creation_date`) → „niewykryty”, brak wyjątku. Test: Task 2.
3. **Odpowiedź nie-JSON** (strona HTML Cloudflare 403 / 502 z proxy) → `blad` z czytelnym powodem, brak wyjątku w workerze. Test: Task 1.
4. **Klucz usunięty z `.env` po wcześniejszych sprawdzeniach** → zapisany wynik nadal widoczny; „—” (nieskonfigurowane) tylko gdy wyniku nie ma. Test: Task 6.
5. **Wrogie dane w odpowiedzi API** (`<script>` w nazwie pliku/tagu, `last_final_url` z `https://`) → wyświetlone jako tekst i rozbrojone. Test: Task 7.

---

## Struktura plików

```
integracje/
  __init__.py
  wspolne.py        WynikDostawcy, wykonaj(), klient httpx
  gti.py            KlientGTI
  censys.py         KlientCensys
analizy/
  models.py         + Wzbogacenie
  zadania.py        zaplanuj(), wzbogac(), dostawcy_dla()
  prezentacja.py    + widoki_wzbogacen(), WidokWzbogacenia
  templatetags/miemli.py  + wiek, klasa_werdyktu, opis_werdyktu
  management/commands/sprawdz_api.py
templates/analizy/
  _wzbogacenie_gti.html, _wzbogacenie_censys.html, _szczegoly_ioc.html, _odpytywanie.html
tests/integracje/
  nagrania/*.json   przycięte prawdziwe odpowiedzi
  test_wspolne.py, test_gti.py, test_censys.py, test_nagrania.py
tests/analizy/
  test_zadania.py, test_wzbogacenie_widoki.py
```

---

### Task 1: Wspólny klient HTTP i mapowanie statusów

**Files:**
- Create: `integracje/__init__.py`, `integracje/wspolne.py`; Modify: `requirements.txt`, `requirements-dev.txt`
- Test: `tests/integracje/__init__.py`, `tests/integracje/test_wspolne.py`

**Interfaces:**
- Produces:

```python
STATUSY = ("oczekuje", "gotowe", "brak_danych", "limit", "blad")
USER_AGENT = "miemli/1.0"
TIMEOUT = 20.0

@dataclass
class WynikDostawcy:
    status: str                      # "gotowe" | "brak_danych" | "limit" | "blad"
    skrot: dict = field(default_factory=dict)
    surowe: dict | None = None
    link: str | None = None
    blad: str = ""                   # powód po polsku, pusty gdy brak błędu
    ponawiac: bool = False           # True dla limit i błędów przejściowych

def nowy_klient() -> httpx.Client                     # User-Agent, timeout
def wykonaj(klient: httpx.Client, url: str, naglowki: dict, parsuj: Callable[[dict], dict],
            link: str | None, params: dict | None = None) -> WynikDostawcy
```

`wykonaj` mapuje: 200 + JSON → `gotowe` ze `skrot=parsuj(json)`, `surowe=json`; 404 → `brak_danych`; 429 → `limit`, `ponawiac=True`; 401/403 → `blad` „Odmowa dostępu (HTTP 403) — sprawdź klucz lub uprawnienia.”, `ponawiac=False`; 5xx → `blad` „Błąd serwera (HTTP 5xx).”, `ponawiac=True`; `httpx.TimeoutException` → `blad` „Przekroczono czas odpowiedzi.”, `ponawiac=True`; inny `httpx.HTTPError` → `blad` „Błąd połączenia.”, `ponawiac=True`; 200 bez poprawnego JSON albo wyjątek w `parsuj` → `blad` „Nieprawidłowa odpowiedź API.”, `ponawiac=False`. `link` przekazywany w każdym wyniku.

- [ ] **Step 1:** Zainstaluj w `.venv` `httpx` i `respx`, przypnij wersje (`requirements.txt`: httpx; `requirements-dev.txt`: respx).
- [ ] **Step 2: Failing testy** (`respx.mock`, URL `https://api.example/x`, `parsuj=lambda j: {"a": j["a"]}`):
  - `test_200`: `{"a": 1}` → `status == "gotowe"`, `skrot == {"a": 1}`, `surowe == {"a": 1}`, `link` zachowany.
  - `test_404`: → `brak_danych`, `ponawiac is False`.
  - `test_429`: → `limit`, `ponawiac is True`.
  - `test_403_html_cloudflare`: 403 z treścią `<html>Error 1010</html>` → `blad`, `"403" in blad`, `ponawiac is False`.
  - `test_500`: → `blad`, `ponawiac is True`.
  - `test_timeout`: `side_effect=httpx.ConnectTimeout` → `blad`, `ponawiac is True`.
  - `test_200_nie_json`: 200 z `<html>` → `blad`, `ponawiac is False`.
  - `test_parsuj_rzuca`: 200 z `{}` (brak klucza `a`) → `blad`, brak wyjątku.
  - `test_user_agent`: wysłane żądanie ma `User-Agent == "miemli/1.0"` (`respx.calls.last.request.headers`).
- [ ] **Step 3:** Run `.venv/bin/pytest tests/integracje -q` → FAIL (brak modułu).
- [ ] **Step 4:** Implementacja.  **Step 5:** Run → PASS.
- [ ] **Step 6:** Commit `"integracje: wspólny klient HTTP i mapowanie statusów"`.

---

### Task 2: Klient GTI i nagrania

**Files:**
- Create: `integracje/gti.py`, `tests/integracje/nagrania/gti_*.json`, `tests/integracje/test_gti.py`, `tests/integracje/test_nagrania.py`

**Interfaces:**
- Consumes: `WynikDostawcy`, `wykonaj`, `nowy_klient` (Task 1).
- Produces:

```python
GUI = "https://www.virustotal.com/gui"
class KlientGTI:
    def __init__(self, klucz: str, klient: httpx.Client | None = None): ...
    def sprawdz(self, typ: str, wartosc: str) -> WynikDostawcy   # typ: plik|url|domena|ip
def id_url(url: str) -> str          # base64url(url.encode("utf-8")) bez "="
def skrot_gti(odpowiedz: dict) -> dict
```

- Endpointy: `plik` → `/files/{sha256}`, `url` → `/urls/{id_url}`, `domena` → `/domains/{d}`, `ip` → `/ip_addresses/{ip}`. Typ spoza listy → `ValueError`.
- Linki: `plik` → `{GUI}/file/{sha256}`, `url` → `{GUI}/url/{sha256(url.encode()).hexdigest()}`, `domena` → `{GUI}/domain/{d}`, `ip` → `{GUI}/ip-address/{ip}`.
- `skrot_gti` (z `data.attributes`, każde pole opcjonalne):

```python
{"werdykt": "zlosliwy"|"podejrzany"|"nieszkodliwy"|"niewykryty",   # z gti_assessment.verdict.value
 "ocena": int|None, "waznosc": str|None,                            # threat_score.value, severity.value
 "wykrycia": [malicious, malicious+suspicious+undetected+harmless] | None,
 "utworzono": int|None, "rejestrator": str|None,                   # domena (epoch)
 "kraj": str|None, "asn": int|None, "wlasciciel": str|None,        # ip
 "typ_pliku": str|None, "nazwy": list[str] (≤5),                   # plik
 "tagi": list[str] (≤10), "pierwsze": int|None, "ostatnia_analiza": int|None}
```
  Mapowanie werdyktu: `VERDICT_MALICIOUS`→`zlosliwy`, `VERDICT_SUSPICIOUS`→`podejrzany`, `VERDICT_BENIGN`→`nieszkodliwy`, inne/brak→`niewykryty`.

- [ ] **Step 1: Nagrania.** Skopiuj odpowiedzi z `/tmp/claude-1000/-home-kali-Desktop-fifi-git-miemli/838428db-a6ed-4d40-8d6f-305e77e33e07/scratchpad/nagrania/gti_*.json` do `tests/integracje/nagrania/`, zostawiając w `cialo.data.attributes` tylko pola używane przez `skrot_gti` plus `gti_assessment`, oraz `data.id`/`data.type`. Jeśli katalog tymczasowy już nie istnieje — uruchom ponownie skrypt `nagraj_api.py` z tego samego katalogu (lub poproś o nagranie) zamiast pisać odpowiedzi z pamięci.
- [ ] **Step 2: Failing testy** (`test_nagrania.py`):
  - `test_nagrania_bez_kluczy`: dla każdej wartości `GTI_API_KEY`, `CENSYS_API_TOKEN`, `CENSYS_ORG_ID` z `.env` (jeśli plik i wartość istnieją; inaczej `pytest.skip`) żaden plik w `tests/integracje/nagrania/` jej nie zawiera.
- [ ] **Step 3: Failing testy** (`test_gti.py`, `respx` zwraca nagrania):
  - `test_eicar`: `sprawdz("plik", EICAR_SHA256)` → `gotowe`, `skrot["werdykt"] == "zlosliwy"`, `skrot["ocena"] == 30`, `skrot["wykrycia"] == [64, 67]`, `link == f"{GUI}/file/{EICAR_SHA256}"`.
  - `test_nieznany_hash`: nagranie 404 → `brak_danych`, `link` ustawiony.
  - `test_domena_google`: `werdykt == "nieszkodliwy"`, `utworzono == 874306800`, `rejestrator == "MarkMonitor Inc."`.
  - `test_ip`: `kraj == "US"`, `asn == 15169`, `wlasciciel == "Google LLC"`.
  - `test_url_id_i_link`: `id_url("https://www.google.com/") == "aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbS8"`; żądanie poszło na `/urls/aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbS8`.
  - `test_url_unicode`: `id_url("https://zażółć.pl/ą")` nie rzuca i jest base64url z UTF-8.
  - `test_naglowki`: żądanie ma `x-apikey` == klucz testowy i `x-tool == "miemli"`.
  - `test_skrot_niepelny`: `skrot_gti({"data": {"attributes": {}}})` → `werdykt == "niewykryty"`, `ocena is None`, `wykrycia is None`, brak wyjątku.
  - `test_zly_typ`: `sprawdz("email", "a@b.pl")` → `ValueError`.
- [ ] **Step 4:** Run → FAIL.  **Step 5:** Implementacja.  **Step 6:** Run → PASS.
- [ ] **Step 7:** Commit `"integracje: klient GTI z nagraniami"`.

---

### Task 3: Klient Censys

**Files:**
- Create: `integracje/censys.py`, `tests/integracje/nagrania/censys_*.json`, `tests/integracje/test_censys.py`

**Interfaces:**
- Consumes: Task 1.
- Produces:

```python
class KlientCensys:
    def __init__(self, token: str, organizacja: str = "", klient: httpx.Client | None = None): ...
    def sprawdz_ip(self, ip: str) -> WynikDostawcy        # link: https://platform.censys.io/hosts/{ip}
def skrot_censys(odpowiedz: dict) -> dict
# {"uslugi": [[port:int, protokol:str, transport:str], ...] (posortowane po porcie, bez limitu),
#  "asn": int|None, "as_nazwa": str|None, "bgp": str|None,
#  "kraj": str|None (country_code), "miasto": str|None, "dns": list[str] (≤10)}
```

- [ ] **Step 1: Nagrania** `censys_ip_8888_bez_org.json` → `censys_8888.json`, `censys_ip_testnet.json` → `censys_testnet.json`; przytnij `dns.names` do 10 wpisów (te z testnetu to obce domeny), zachowaj `services`, `autonomous_system`, `location`.
- [ ] **Step 2: Failing testy:**
  - `test_8888`: `gotowe`, `[53, "DNS", "tcp"] in skrot["uslugi"]`, `[443, "HTTP", "tcp"] in skrot["uslugi"]`, `asn == 15169`, `kraj == "US"`, `link == "https://platform.censys.io/hosts/8.8.8.8"`.
  - `test_brak_uslug`: nagranie testnet → `gotowe`, `skrot["uslugi"] == []`.
  - `test_bez_organizacji`: `KlientCensys("t")` → żądanie bez parametru `organization_id`.
  - `test_z_organizacja`: `KlientCensys("t", "org1")` → `organization_id=org1` w query.
  - `test_naglowki`: `Authorization == "Bearer t"`, `User-Agent == "miemli/1.0"`.
  - `test_403_org`: odpowiedź 403 z nagrania `{"title":"Forbidden",...}` → `blad`, `ponawiac is False`.
- [ ] **Step 3:** Run → FAIL.  **Step 4:** Implementacja.  **Step 5:** Run → PASS.
- [ ] **Step 6:** Commit `"integracje: klient Censys Platform"`.

---

### Task 4: Model `Wzbogacenie`, planowanie i wykonanie zadań

**Files:**
- Create: `analizy/zadania.py`, `analizy/migrations/0003_wzbogacenie.py` (makemigrations); Modify: `analizy/models.py`, `analizy/uslugi.py`, `analizy/views.py` (`szczegoly`), `miemli/settings.py`
- Test: `tests/analizy/test_zadania.py`

**Interfaces:**
- Consumes: `KlientGTI`, `KlientCensys`, `WynikDostawcy`.
- Produces:

```python
class Wzbogacenie(models.Model):
    klucz = CharField(max_length=64, unique=True)   # sha256(f"{dostawca}:{typ}:{wartosc}")
    dostawca = CharField(max_length=10)             # "gti" | "censys"
    typ = CharField(max_length=10); wartosc = TextField()
    status = CharField(max_length=12)
    skrot = JSONField(default=dict); surowe = JSONField(null=True)
    link = TextField(null=True); blad = TextField(blank=True, default="")
    zlecono = DateTimeField(null=True); sprawdzono = DateTimeField(null=True)
    @staticmethod
    def klucz_dla(dostawca: str, typ: str, wartosc: str) -> str

# analizy/zadania.py
CACHE = timedelta(hours=24); BLOKADA = timedelta(minutes=10)
DOSTAWCY = {"gti": ("plik", "url", "domena", "ip"), "censys": ("ip",)}
def skonfigurowany(dostawca: str) -> bool                        # z settings
def dostawcy_dla(typ: str) -> list[str]                          # tylko skonfigurowani
def zaplanuj(analiza, wymus: bool = False, tylko_brakujace: bool = False) -> int
def wzbogac(dostawca: str, typ: str, wartosc: str, proba: int = 0) -> None
def _kolejkuj(funkcja, *args, **kwargs) -> None                  # django_rq.enqueue; podmieniane w testach
def _klient(dostawca: str)                                       # KlientGTI / KlientCensys z settings
```

- Settings: `GTI_API_KEY = os.environ.get("GTI_API_KEY", "")`, `CENSYS_API_TOKEN`, `CENSYS_ORG_ID` analogicznie.
- `zaplanuj` — reguły ze specyfikacji §4 pkt 1 (świeży wynik → pomiń; `oczekuje` < 10 min → pomiń; inaczej `status="oczekuje"`, `zlecono=now()`, `_kolejkuj(wzbogac, dostawca, typ, wartosc)`); `wymus=True` pomija oba warunki; `tylko_brakujace=True` kolejkuje wyłącznie pary bez żadnego wpisu. Wartość dla `plik` = SHA256 (pole `IOC.wartosc`).
- `wzbogac(proba)` — wynik z `_klient(dostawca)`; ponowienia w Task 5; w tym tasku zawsze zapisuje wynik: `status`, `skrot`, `surowe`, `link`, `blad`, `sprawdzono=now()`. Log `logger.info("wzbogacenie %s %s %s", dostawca, typ, status)` — bez wartości kluczy.
- `uslugi.utworz_lub_otworz`: po utworzeniu `transaction.on_commit(lambda: zaplanuj(analiza))`.
- `views.szczegoly`: przy pierwszym otwarciu w sesji (tam, gdzie zapisuje `Zdarzenie("otwarcie")`) — `zaplanuj(analiza, tylko_brakujace=True)`.

- [ ] **Step 1: Failing testy** (fixture `kolejka` podmienia `analizy.zadania._kolejkuj` na listę wywołań; fixture `klienci` podmienia `_klient` na atrapę zwracającą zadany `WynikDostawcy` i liczącą wywołania; `settings.GTI_API_KEY = "k"`, `settings.CENSYS_API_TOKEN = "t"`):
  - `test_nowa_analiza_kolejkuje`: `utworz_lub_otworz` próbki `phishing_klasyczny` w `django_capture_on_commit_callbacks(execute=True)` → zakolejkowane: GTI dla każdego IOC `url`/`domena`/`ip` (nie `email`), Censys tylko dla `ip` `185.243.115.20`; wpisy mają `status == "oczekuje"`.
  - `test_swiezy_cache_bez_kolejki`: istniejący `Wzbogacenie(status="gotowe", sprawdzono=now()-1h)` dla domeny → `zaplanuj` jej nie kolejkuje.
  - `test_stary_cache_kolejkuje`: `sprawdzono=now()-25h` → kolejkuje.
  - `test_oczekuje_niedawno_bez_duplikatu`: `status="oczekuje", zlecono=now()-5min` → nie kolejkuje; `zlecono=now()-11min` → kolejkuje.
  - `test_wymus`: świeży wynik + `wymus=True` → kolejkuje.
  - `test_tylko_brakujace`: istniejący stary wpis → nie kolejkuje; para bez wpisu → kolejkuje.
  - `test_brak_klucza`: `settings.CENSYS_API_TOKEN = ""` → żadnych zadań Censys.
  - `test_wspolny_cache_miedzy_analizami`: dwie analizy z tą samą domeną (`zip_exe` jako dwa tickety) → po `wzbogac` dla pierwszej druga nie kolejkuje tej domeny.
  - `test_wzbogac_zapisuje`: atrapa zwraca `WynikDostawcy("gotowe", {"werdykt": "zlosliwy"}, {}, "L")` → wpis `gotowe`, `skrot`, `link == "L"`, `sprawdzono` ustawione.
  - `test_otwarcie_istniejacej_kolejkuje_tylko_brakujace`: GET `analizy:szczegoly` dla analizy z jednym wpisem `gotowe` sprzed 3 dni → ten wpis nie jest kolejkowany, brakujące tak.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja + `makemigrations analizy -n wzbogacenie`.  **Step 4:** Run `.venv/bin/pytest -q` → PASS (cały zestaw).
- [ ] **Step 5:** Commit `"Model Wzbogacenie, planowanie i wykonanie lookupów z cache"`.

---

### Task 5: Ponowienia w workerze

**Files:**
- Modify: `analizy/zadania.py`, `docker-compose.yml` (worker: `command: ["python", "manage.py", "rqworker", "default", "--with-scheduler"]`)
- Test: `tests/analizy/test_zadania.py`

**Interfaces:**
- Produces:

```python
OPOZNIENIA_LIMIT = (30, 120, 300); OPOZNIENIA_BLAD = (10, 60)
def _ponow(opoznienie_s: int, *args, **kwargs) -> None   # django_rq.get_queue().enqueue_in(timedelta(seconds=...), wzbogac, ...); podmieniane w testach
```

- `wzbogac(..., proba)`: gdy `wynik.ponawiac` i `proba < len(opóźnień dla statusu)` → `_ponow(opoznienia[proba], dostawca, typ, wartosc, proba=proba + 1)`, wpis zostaje `oczekuje` z `zlecono=now()` (wynik nie zapisywany); w przeciwnym razie zapis wyniku jak w Task 4. Opóźnienia: `limit` → `OPOZNIENIA_LIMIT`, `blad` z `ponawiac=True` → `OPOZNIENIA_BLAD`.

- [ ] **Step 1: Failing testy:**
  - `test_limit_ponawia_30s`: atrapa `limit, ponawiac=True`, `proba=0` → `_ponow` wywołane z `30` i `proba=1`; wpis `oczekuje`.
  - `test_limit_wyczerpany`: `proba=3` → brak `_ponow`, wpis `limit`.
  - `test_blad_przejsciowy`: `blad, ponawiac=True`, `proba=1` → `_ponow(60, ..., proba=2)`; `proba=2` → wpis `blad`.
  - `test_403_bez_ponowien`: `blad, ponawiac=False` → wpis `blad` od razu.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja.  **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `"Ponowienia lookupów przy limicie i błędach przejściowych"`.

---

### Task 6: Kolumny wzbogacenia i odpytywanie htmx

**Files:**
- Create: `templates/analizy/_wzbogacenie_gti.html`, `templates/analizy/_wzbogacenie_censys.html`, `templates/analizy/_odpytywanie.html`; Modify: `analizy/prezentacja.py`, `analizy/views.py`, `analizy/urls.py`, `analizy/templatetags/miemli.py`, `templates/analizy/sekcje/ioc.html`, `templates/analizy/_panel_ioc.html`, `templates/analizy/szczegoly.html`, `static/css/nord.css`
- Test: `tests/analizy/test_wzbogacenie_widoki.py`

**Interfaces:**
- Consumes: `Wzbogacenie`, `dostawcy_dla`, `skonfigurowany`, `DOSTAWCY`, `BLOKADA`.
- Produces:

```python
@dataclass
class WidokWzbogacenia:
    status: str          # oczekuje|gotowe|brak_danych|limit|blad|nieskonfigurowane|nie_dotyczy
    skrot: dict; link: str | None; blad: str; sprawdzono: datetime | None
def widoki_wzbogacen(analiza) -> tuple[dict[int, dict[str, WidokWzbogacenia]], bool]
    # {ioc.pk: {"gti": ..., "censys": ...}}, czy_trwa (jest "oczekuje" młodsze niż BLOKADA)
```
  Reguły: dostawca nie obsługuje typu → `nie_dotyczy`; brak wpisu i brak klucza → `nieskonfigurowane`; brak wpisu przy skonfigurowanym kluczu → `oczekuje`; wpis `oczekuje` z `zlecono` starszym niż `BLOKADA` → `blad` z `blad="Brak odpowiedzi workera."`; w pozostałych przypadkach status wpisu (także gdy klucz usunięto później).
- URL `analizy:wzbogacenie` `GET /analiza/<pk>/wzbogacenie/?sekcja=<s>&wiadomosc=<id>` (login) zwraca fragmenty OOB: `#odpytywanie` (zawsze), `#panel-ioc` (zawsze), `#tabela-ioc-cialo` (gdy `sekcja == "ioc"`).
- `_odpytywanie.html`: `<div id="odpytywanie" hx-swap-oob="true" {% if trwa %}hx-get="…" hx-trigger="every 2s" hx-swap="none"{% endif %}></div>`; ten sam element renderowany w `szczegoly.html`.
- Filtry: `klasa_werdyktu` (`zlosliwy`→`bad`, `podejrzany`→`warn`, `nieszkodliwy`→`ok`, inne→`neutral`), `opis_werdyktu` (`złośliwy`/`podejrzany`/`nieszkodliwy`/`niewykryty`), `wiek(epoch) -> str` (< 30 dni: `"1 dzień"`/`"N dni"`; < 365 dni: `"N mies."`; dalej `"1 rok"`, `"2–4 lata"` (np. `"3 lata"`), `"5+ lat"` (np. `"27 lat"`, także `"22 lata"`, `"25 lat"` wg polskich reguł: końcówka 2–4 poza 12–14 → `lata`), `nowa_domena(epoch) -> bool` (< 30 dni).
- Komórki zgodnie ze spec §5.1–5.4: GTI `{{ opis }} · {{ ocena }} · {{ wykrycia.0 }}/{{ wykrycia.1 }}`, domena + wiek (`.warn` gdy nowa), IP + kraj; Censys do 5 usług `port protokół` + `+N` + `AS{asn}`, pusta lista → „brak otwartych usług”; statusy: `…` (klasa `.pulsuje`), „brak danych”, „limit API”, „błąd” (dymek = `blad`), „—” (dymek „brak klucza w .env”), `nie_dotyczy` → pusta komórka.

- [ ] **Step 1: Failing testy** (analiza z próbki `phishing_klasyczny`, wpisy `Wzbogacenie` tworzone w teście, `settings` z kluczami):
  - `test_kolumny`: `?sekcja=ioc` zawiera nagłówki `GTI`, `Censys`, `JOE`.
  - `test_komorka_gti_zlosliwy`: wpis GTI `gotowe` dla URL `…/login` ze `skrot={"werdykt":"zlosliwy","ocena":80,"wykrycia":[12,90]}` → `złośliwy · 80 · 12/90` i klasa `bad`.
  - `test_nowa_domena`: domena `utworzono=now-3 dni` → `3 dni` w elemencie z klasą `warn`.
  - `test_censys_uslugi`: IP z 7 usługami → 5 usług i `+2`, `AS15169`.
  - `test_odpytywanie_gdy_oczekuje`: wpis `oczekuje` (`zlecono=now`) → strona zawiera `hx-trigger="every 2s"`.
  - `test_brak_odpytywania_gdy_gotowe`: wszystkie wpisy `gotowe` → strona i fragment `analizy:wzbogacenie` bez `every 2s`.
  - `test_wiszacy_wpis_jako_blad` *(Review Focus 1)*: `oczekuje`, `zlecono=now-11min` → „Brak odpowiedzi workera.” w odpowiedzi, brak `every 2s`.
  - `test_klucz_usuniety_wynik_widoczny` *(Review Focus 4)*: wpis `gotowe` + `settings.GTI_API_KEY = ""` → werdykt widoczny; IOC bez wpisu → „brak klucza w .env”.
  - `test_fragment_oob`: GET `analizy:wzbogacenie?sekcja=ioc` → zawiera `id="panel-ioc"`, `id="tabela-ioc-cialo"`, `hx-swap-oob`; bez `<html`.
  - `test_fragment_wymaga_logowania`: bez sesji → 302.
  - `test_wiek`: `wiek(now-1d)=="1 dzień"`, `wiek(now-3d)=="3 dni"`, `wiek(now-60d)=="2 mies."`, `wiek(now-3*365d)=="3 lata"`, `wiek(now-27*365d)=="27 lat"`, `wiek(now-22*365d)=="22 lata"`, `wiek(now-12*365d)=="12 lat"`, `wiek(None)==""`.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja.  **Step 4:** Run `.venv/bin/pytest -q` → PASS.
- [ ] **Step 5:** Commit `"Kolumny GTI/Censys w tabeli IOC i odpytywanie htmx"`.

---

### Task 7: Szczegóły IOC, kropki w panelu, „Odśwież”, link JOE

**Files:**
- Create: `templates/analizy/_szczegoly_ioc.html`; Modify: `analizy/views.py`, `analizy/urls.py`, `templates/analizy/sekcje/ioc.html`, `templates/analizy/_panel_ioc.html`, `templates/analizy/szczegoly.html`, `static/css/nord.css`
- Test: `tests/analizy/test_wzbogacenie_widoki.py`

**Interfaces:**
- Consumes: `widoki_wzbogacen`, `zaplanuj`, `Zdarzenie`.
- Produces:
  - `analizy:szczegoly_ioc` `GET /analiza/<pk>/ioc/<ioc_pk>/` (login; IOC spoza analizy → 404) — fragment szczegółów wg spec §5.5; w tabeli wiersz IOC ma `hx-get` na ten URL z `hx-target` na wiersz szczegółów pod nim.
  - `analizy:odswiez` `POST /analiza/<pk>/odswiez/` (login, `require_POST`) → `zaplanuj(analiza, wymus=True)`, `Zdarzenie(typ="odswiezenie", szczegoly={"zadania": n})`, odpowiedź: przekierowanie na `analizy:szczegoly` (dla htmx: nagłówek `HX-Redirect`).
  - Przycisk „Odśwież wzbogacenie” w pasku górnym (`hx-post`, CSRF z `hx-headers` w `base.html`).
  - Kolumna JOE: dla `plik` i `url` link „JOE ↗” do `https://jbxcloud.joesecurity.org/`, `target="_blank" rel="noopener noreferrer"`; dla innych typów pusta.
  - Panel: kropka `<span class="kropka {{ klasa_werdyktu }}">` przy IOC z wynikiem GTI `gotowe`.

- [ ] **Step 1: Failing testy:**
  - `test_szczegoly_gti_i_censys`: IOC `ip` z wpisami GTI (`kraj`, `asn`, `wlasciciel`) i Censys (usługi, `bgp`, `dns`) → fragment zawiera `Google LLC`, `8.8.8.0/24`, link `https://platform.censys.io/hosts/` i `https://www.virustotal.com/gui/ip-address/`, „Sprawdzono:”.
  - `test_szczegoly_cudzy_ioc_404`: `ioc_pk` z innej analizy → 404.
  - `test_wrogie_dane_api` *(Review Focus 5)*: `skrot={"nazwy": ["<script>alert(1)</script>"], "tagi": ["<b>x</b>"]}` → odpowiedź zawiera `&lt;script&gt;`, nie zawiera `<script>alert`; `surowe` z `last_final_url = "https://evil.example/x"` nie jest wyświetlane surowo (szczegóły nie zawierają `https://evil.example`).
  - `test_odswiez_post`: POST zalogowany → 302 na szczegóły, `Zdarzenie(typ="odswiezenie")` istnieje, `_kolejkuj` wywołane mimo świeżego cache.
  - `test_odswiez_get_405`: GET → 405.  `test_odswiez_wymaga_logowania`: bez sesji → 302 na logowanie, brak zadań.
  - `test_link_joe`: tabela IOC zawiera `href="https://jbxcloud.joesecurity.org/"`, `rel="noopener noreferrer"`, `target="_blank"` dla wiersza `url`; wiersz `email` bez linku JOE.
  - `test_kropka_w_panelu`: wpis GTI `zlosliwy` → panel zawiera `kropka bad`.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja.  **Step 4:** Run `.venv/bin/pytest -q` → PASS.
- [ ] **Step 5: Weryfikacja wizualna** (Playwright, `runserver` z kluczami z `.env`): wgraj `phishing_klasyczny.eml`, poczekaj na wyniki (worker: `python manage.py rqworker default --with-scheduler` przy lokalnym Redisie lub w Dockerze), rozwiń wiersz IP, kliknij „Odśwież”.
- [ ] **Step 6:** Commit `"Szczegóły IOC, kropki werdyktu, odświeżanie i link JOE"`.

---

### Task 8: Smoke test na prawdziwych kluczach, Docker, dokumentacja

**Files:**
- Create: `analizy/management/__init__.py`, `analizy/management/commands/__init__.py`, `analizy/management/commands/sprawdz_api.py`; Modify: `.env.example`, `README.md`, `NOTES.md`
- Test: `tests/analizy/test_sprawdz_api.py`

**Interfaces:**
- `python manage.py sprawdz_api` — dla skonfigurowanych dostawców: GTI `plik` EICAR (`275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f`) i `ip` `8.8.8.8`, Censys `8.8.8.8`; wypisuje `dostawca typ status` i powód błędu; nieskonfigurowany → `gti: brak klucza`. Nie zapisuje do bazy, nie wypisuje kluczy. Kod wyjścia 1, gdy którykolwiek wynik to `blad`.

- [ ] **Step 1: Failing testy** (`_klient` podmieniony na atrapę): wynik `gotowe` → wyjście zawiera `gti plik gotowe`, kod 0; wynik `blad` → kod 1 (`CommandError` lub `SystemExit(1)`); brak klucza → `brak klucza`; wyjście nie zawiera wartości `settings.GTI_API_KEY`.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja.  **Step 4:** Run → PASS.
- [ ] **Step 5:** `.env.example`: dopisz `GTI_API_KEY=`, `CENSYS_API_TOKEN=`, `CENSYS_ORG_ID=` z komentarzem (ORG opcjonalne).
- [ ] **Step 6: Docker.** `docker compose up -d --build`; `docker compose exec web python manage.py sprawdz_api` → GTI i Censys `gotowe`; `docker compose logs worker` zawiera scheduler (`Scheduler for default started` lub równoważne) i brak wartości kluczy (`grep` po wartościach z `.env` → brak trafień); end-to-end przez `https://localhost`: upload `phishing_klasyczny.eml`, po ≤ 60 s w tabeli IOC brak `…`.
- [ ] **Step 7:** README (konfiguracja kluczy, `sprawdz_api`), NOTES (stan po etapie 4, następny: etap 6 RTIR). Commit `"Etap 4: sprawdz_api, dokumentacja"`.
