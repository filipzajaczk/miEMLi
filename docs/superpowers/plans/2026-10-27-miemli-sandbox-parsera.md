# miemli — Sandbox parsera — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Całe przetwarzanie wrogich plików (parsowanie, archiwa, QR, HTML, obrazki) przenieść do osobnego kontenera `parser` w gVisor, w którym każdy plik jest analizowany przez świeży proces z limitami; `web` tylko wysyła bajty i waliduje JSON; obrazki przekodowane do PNG z raportem nietypowych obrazków.

**Architecture:** Nowy pakiet `piaskownica/` (bez Django): `obrazki.py` (rozpoznanie formatu, raport, przekodowanie), `zadanie.py` (proces potomny: stdin→JSON, limity `setrlimit`), `serwer.py` (stdlib `ThreadingHTTPServer`, semafor 2, kolejka 8), `gvisor.py`. `web` używa `analizy/piaskownica_klient.py` (httpx do `http://parser:8000`, a w testach/dev — tryb w procesie). Osobny target Dockerfile `parser`, sieć `piaskownica`.

**Tech Stack:** Python 3.14 stdlib (`http.server`, `subprocess`, `resource`), Pillow, httpx, respx, Django 6.1, Docker + gVisor (`runsc`).

**Spec:** `docs/superpowers/specs/2026-10-27-miemli-sandbox-parsera-design.md` (rozszerza `docs/superpowers/specs/2026-10-26-miemli-design.md`)

## Global Constraints

- Limity procesu potomnego: pamięć adresowa 1 GB (`RLIMIT_AS`), CPU 30 s (`RLIMIT_CPU` soft 30 / hard 31), otwarte pliki 64, zapis plików 300 MB (`RLIMIT_FSIZE`), core 0; czas rzeczywisty 60 s → `SIGKILL`.
- Serwer: maks. 2 procesy równolegle, maks. 8 żądań oczekujących (dalej `503`), maks. treść żądania 55 MB (dalej `413`).
- Odpowiedź parsera: `{"status": "ok", "wynik": {...}}` lub `{"status": "przerwana", "powod": "czas"|"pamiec"|"awaria"|"nieobslugiwany"|"za_duzy"}`.
- Walidacja w `web`: maks. 20 MB, klucze `wiadomosc`, `analiza`, `ioc`; maks. 5000 IOC; `typ` ∈ {plik, url, domena, ip, email}; `wartosc` str ≤ 8192; `id` int; `rodzic_id` null lub int mniejszy od `id`.
- Obrazki: wejście tylko PNG/JPEG/GIF/BMP; wyjście PNG ≤ 1600 px szerokości, ≤ 2 MB; maks. 20 na wiadomość; GIF — pierwsza klatka. Kody uwag i progi dokładnie wg spec §8.1 (`ZA_DUZY_PLIK` > 10 MB, `ZA_DUZO_PIKSELI` > 20 Mpx, `NIETYPOWE_WYMIARY` bok > 10 000 px lub proporcje > 50:1).
- Parser loguje tylko SHA256, rozmiar, czas, status, powód. Bez treści i nazw plików.
- Kontener `parser`: UID 65534, `read_only`, `tmpfs /tmp` 300 MB `noexec,nosuid,nodev`, `cap_drop: [ALL]`, `no-new-privileges`, `mem_limit: 2.5g`, `pids_limit: 64`, `runtime: ${PARSER_RUNTIME:-runc}`, tylko sieć `piaskownica` (`internal: true`), zero sekretów.
- Haki testowe procesu potomnego (`PIASKOWNICA_TEST=petla|pamiec|abort|polowa`) działają wyłącznie, gdy `PIASKOWNICA_TRYB_TESTOWY=1`; w obrazie `parser` ta zmienna nie jest ustawiana.
- Commity kończą się `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Przejęty parser zwraca poprawny strukturalnie, ale wrogi JSON** (`<script>` w temacie, `javascript:` w IOC URL, ogromne stringi) → wyświetlone jako tekst, rozbrojone, nic się nie wykonuje. Test: Task 5.
2. **Parser zrywa połączenie w trakcie** (restart kontenera, reset TCP) → „Sandbox analizy niedostępny”, brak 500. Test: Task 5.
3. **Proces potomny wypisuje połowę JSON-a i pada** → `awaria`, nie wyjątek w serwerze. Test: Task 3.
4. **Nazwa pliku z nową linią / unicode / bardzo długa** w nagłówku żądania do parsera → poprawnie zakodowana, bez wstrzyknięcia nagłówka. Test: Task 5.
5. **Wiele równoczesnych uploadów** → część dostaje `503` → komunikat „niedostępny” zamiast zawieszenia. Test: Task 3 (serwer) i Task 5 (komunikat).

---

## Struktura plików

```
piaskownica/__init__.py
piaskownica/obrazki.py      wykryj_format(), przetworz_obrazki(), WynikObrazka
piaskownica/zadanie.py      analizuj_plik(), ustaw_limity(), main()   (python -m piaskownica.zadanie)
piaskownica/serwer.py       uruchom(host, port), obsluga /analizuj, /zdrowie   (python -m piaskownica.serwer)
piaskownica/gvisor.py       w_gvisor()
requirements-parser.txt
mailcore/html_bezpieczny.py   bezpieczny_html(..., obrazy=...)
mailcore/serializacja.py      do_json(..., obrazki=...)
analizy/piaskownica_klient.py analizuj_w_piaskownicy(), waliduj_wynik(), wyjątki, stan_piaskownicy()
analizy/uslugi.py             przełączenie na klienta
tests/piaskownica/...         test_obrazki.py, test_zadanie.py, test_serwer.py, test_gvisor.py
tests/analizy/test_piaskownica_klient.py, test_raport_obrazkow.py
```

---

### Task 1: Obrazki — rozpoznanie formatu, raport, przekodowanie

**Files:**
- Create: `piaskownica/__init__.py`, `piaskownica/obrazki.py`, `tests/piaskownica/__init__.py`, `tests/piaskownica/test_obrazki.py`
- Modify: `mailcore/html_bezpieczny.py`, `mailcore/serializacja.py`, `tests/mailcore/test_html_bezpieczny.py`

**Interfaces:**
- Produces:

```python
# piaskownica/obrazki.py
DOZWOLONE = ("PNG", "JPEG", "GIF", "BMP")
def wykryj_format(dane: bytes) -> str
    # "PNG"|"JPEG"|"GIF"|"BMP"|"TIFF"|"WEBP"|"SVG"|"EPS"|"ICO"|"PSD"|"JPEG2000"|"AVIF/HEIC"|"NIEZNANY" — tylko sygnatury bajtów
@dataclass
class WynikObrazka:
    wpis: dict            # wpis raportu dokładnie wg spec §8.1 (klucze: nazwa, sha256, rozmiar, content_id,
                          # mime_zadeklarowany, format_wykryty, szerokosc, wysokosc, klatki, status, uwagi)
    png: bytes | None     # przekodowany obraz albo None (pominięty)
def czy_obrazek(z: Zalacznik) -> bool        # mime image/* lub content_id lub wykryty format obrazu
def przetworz_obrazki(w: Wiadomosc) -> dict[str, list[WynikObrazka]]   # klucz = Wiadomosc.id, obejmuje zagnieżdżone

# mailcore/html_bezpieczny.py
def bezpieczny_html(html: str, zalaczniki: list[Zalacznik], obrazy: dict[str, bytes | str] | None = None) -> str
    # obrazy: content_id → PNG (osadzony jako data:image/png) albo str z powodem pominięcia;
    # brak wpisu / obrazy=None → <span class="obrazek-pominiety">[obrazek pominięty]</span>; NIGDY oryginalne bajty
# mailcore/serializacja.py
def do_json(w: Wiadomosc, wynik: WynikAnalizy, obrazki: dict[str, list[WynikObrazka]] | None = None) -> dict
    # każda wiadomość w JSON dostaje klucz "obrazki": [wpis, ...] (pusta lista, gdy brak)
```

Format „obrazek pominięty”: `<span class="obrazek-pominiety">[obrazek pominięty: {powód}]</span>`, powód np. `format TIFF`, `za duży`, `uszkodzony`, `limit liczby`.

- [ ] **Step 1: Failing testy** (`tests/piaskownica/test_obrazki.py`; obrazy generowane Pillow w teście, SVG/EPS jako bajty tekstowe):
  - `test_wykryj_format`: PNG, JPEG, GIF, BMP, TIFF, WEBP, SVG (`<?xml…<svg` i `<svg`), EPS (`%!PS`), ICO, PSD (`8BPS`), JPEG2000, `ftyp`+`avif`/`heic` → `AVIF/HEIC`, `b"abc"` → `NIEZNANY`.
  - `test_bez_dekodera_dla_nieobslugiwanych`: monkeypatch `PIL.Image.open` rzucający `AssertionError`; TIFF przechodzi przez `przetworz_obrazki` → status `pominiety`, uwaga `FORMAT_NIEOBSLUGIWANY`, bez wyjątku.
  - `test_przekodowany_png_inny_niz_oryginal`: PNG 100×50 → `png.startswith(b"\x89PNG")`, `png != dane`, status `przekodowany`, `szerokosc == 100`.
  - `test_format_niezgodny`: TIFF jako `logo.png` z `image/png` → uwagi zawierają `FORMAT_NIEZGODNY` i `FORMAT_NIEOBSLUGIWANY`; JPEG jako `a.png` → `FORMAT_NIEZGODNY`, status `przekodowany`.
  - `test_animacja`: GIF 3 klatki → `klatki == 3`, uwaga `ANIMACJA`, status `przekodowany`.
  - `test_za_duzo_pikseli`: PNG 6000×4000 → `ZA_DUZO_PIKSELI`, `pominiety`.
  - `test_nietypowe_wymiary`: PNG 20000×10 → `NIETYPOWE_WYMIARY`.
  - `test_przeskalowany`: PNG 3000×100 → `PRZESKALOWANY`, wynik PNG ma szerokość 1600.
  - `test_uszkodzony`: `b"\x89PNG\r\n\x1a\n" + b"\x00"*30` → `USZKODZONY`, `pominiety`.
  - `test_za_duzy_plik`: obraz > 10 MB (np. BMP 2000×1800×24 bit) → `ZA_DUZY_PLIK`, `pominiety`, bez dekodowania.
  - `test_limit_liczby`: 25 obrazków → 20 `przekodowany`, 5 z `LIMIT_LICZBY`.
  - `test_zagniezdzona_wiadomosc`: obraz w mailu zagnieżdżonym → wpis pod kluczem `"0.1"`.
- [ ] **Step 2: Failing testy** w `tests/mailcore/test_html_bezpieczny.py`: zmień `test_cid_jako_data_uri` → przy `obrazy={"logo1": b"\x89PNGxyz"}` w wyniku `data:image/png;base64,` z bajtów *mapy*, nie oryginału; nowy `test_cid_bez_mapy_pominiety` → `obrazek-pominiety` i brak `data:`; nowy `test_cid_z_powodem` → `obrazy={"x": "format TIFF"}` → `[obrazek pominięty: format TIFF]`.
- [ ] **Step 3:** Run `.venv/bin/pytest tests/piaskownica tests/mailcore/test_html_bezpieczny.py -q` → FAIL.
- [ ] **Step 4:** Implementacja. Kolejność kontroli w `przetworz_obrazki`: rozmiar pliku → format (sygnatura) → `Image.open(formats=DOZWOLONE)` nagłówek (wymiary, `n_frames`) → piksele/wymiary → limit liczby → `load()` + `thumbnail((1600, …))` + zapis PNG (`optimize=False`); PNG > 2 MB → pominięty z uwagą `ZA_DUZY_PLIK`. `FORMAT_NIEZGODNY`: format ≠ format z MIME (`image/png`→PNG, `image/jpeg`|`image/jpg`→JPEG, `image/gif`→GIF, `image/bmp`→BMP) lub ≠ format z rozszerzenia nazwy, gdy znane.
- [ ] **Step 5:** Run `.venv/bin/pytest -q` → PASS (cały zestaw; zaktualizuj inne testy tylko tam, gdzie zakładały osadzanie oryginalnych bajtów — z ledgerem).
- [ ] **Step 6:** Commit `"piaskownica: rozpoznanie formatu i raport obrazków, przekodowanie do PNG"`.

---

### Task 2: Proces potomny (`zadanie.py`)

**Files:**
- Create: `piaskownica/zadanie.py`, `tests/piaskownica/test_zadanie.py`

**Interfaces:**
- Consumes: `parsuj`, `analizuj`, `Limity`, `NieobslugiwanyPlik`, `PlikZaDuzy`, `przetworz_obrazki`, `do_json`.
- Produces:

```python
def analizuj_plik(dane: bytes, nazwa: str, ignorowane: frozenset[str] = frozenset(),
                  max_rozmiar: int = 50 * 1024 * 1024) -> dict
    # {"status": "ok", "wynik": do_json(...)} | {"status": "przerwana", "powod": "nieobslugiwany"|"za_duzy"}
def ustaw_limity() -> None          # wartości z Global Constraints
def main(argv: list[str] | None = None) -> int
    # argumenty: --nazwa (URL-encoded), --ignorowane "a.pl,b.pl", --max-rozmiar N
    # stdin: bajty; stdout: JSON z analizuj_plik; MemoryError → kod 3 bez JSON; inne wyjątki → kod 4
```

- [ ] **Step 1: Failing testy** (uruchamiają prawdziwy proces: `subprocess.run([sys.executable, "-I", "-m", "piaskownica.zadanie", "--nazwa", ...], input=..., capture_output=True, timeout=90, cwd=<repo>, env={..., "PYTHONPATH": <repo>})`):
  - `test_korpus_przez_proces`: dla `phishing_klasyczny` i `zip_aes_haslo_w_tresci` zbiór `(typ, wartosc)` (pliki po `etykieta`) z `wynik["ioc"]` == oczekiwania z `tests/samples/*.expected.json`.
  - `test_nieobslugiwany` (PNG zamiast maila) → `{"status": "przerwana", "powod": "nieobslugiwany"}`.
  - `test_za_duzy` (`--max-rozmiar 10`) → `za_duzy`.
  - `test_limity_ustawione`: z hakiem `PIASKOWNICA_TEST=limity` (tylko przy `PIASKOWNICA_TRYB_TESTOWY=1`) proces wypisuje `resource.getrlimit` dla AS/CPU/NOFILE/FSIZE/CORE → wartości z Global Constraints.
  - `test_pamiec`: `PIASKOWNICA_TEST=pamiec` (alokacja 2 GB) → kod wyjścia 3, pusty stdout.
  - `test_haki_wylaczone_bez_trybu_testowego`: `PIASKOWNICA_TEST=abort` bez `PIASKOWNICA_TRYB_TESTOWY` → normalna analiza, kod 0.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja (limity ustawiane jako pierwsza instrukcja `main`, przed importem bibliotek parsujących; `ignorowane` przekazywane do `analizuj`).  **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `"piaskownica: proces potomny z limitami systemowymi"`.

---

### Task 3: Serwer HTTP i wykrywanie gVisor

**Files:**
- Create: `piaskownica/serwer.py`, `piaskownica/gvisor.py`, `tests/piaskownica/test_serwer.py`, `tests/piaskownica/test_gvisor.py`

**Interfaces:**
- Produces:

```python
# piaskownica/gvisor.py
SYGNATURA_PROC_VERSION = "Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016"
def w_gvisor(proc_version: str | None = None, dmesg: str | None = None) -> bool
    # True gdy /proc/version == sygnatura gVisor lub dmesg zawiera "gVisor"; argumenty do testów, domyślnie odczyt systemu

# piaskownica/serwer.py
ROWNOLEGLE = 2; KOLEJKA = 8; MAKS_ZADANIE = 55 * 1024 * 1024; CZAS = 60
def utworz_serwer(host: str, port: int) -> ThreadingHTTPServer
def uruchom_proces(dane: bytes, nazwa: str, ignorowane: str, max_rozmiar: int) -> dict   # mapuje wynik procesu na odpowiedź
# POST /analizuj: ciało = bajty; nagłówki X-Miemli-Nazwa (URL-encoded), X-Miemli-Ignorowane, X-Miemli-Max-Rozmiar
# GET  /zdrowie → {"gvisor": bool, "wersja": "1"}
# python -m piaskownica.serwer → nasłuch 0.0.0.0:8000
```

Mapowanie procesu: `TimeoutExpired` lub zakończenie sygnałem `SIGXCPU`/`SIGKILL` → `czas`; kod 3 → `pamiec`; inny kod ≠ 0, sygnał lub stdout nie będący poprawnym JSON → `awaria`; kod 0 + JSON → ten JSON. Ponad `KOLEJKA` oczekujących → `503`; treść > `MAKS_ZADANIE` → `413`; inne ścieżki → `404`. Log: `sha256 rozmiar czas status powod`.

- [ ] **Step 1: Failing testy** (serwer na porcie 0 w wątku; `PIASKOWNICA_TRYB_TESTOWY=1` w środowisku testu):
  - `test_analizuj_ok`: POST próbki → 200, `status == "ok"`, `wynik["ioc"]` niepuste.
  - `test_czas`: `PIASKOWNICA_TEST=petla`, `CZAS` podmieniony na 3 s → `powod == "czas"` w ≤ 10 s.
  - `test_awaria_abort`: `PIASKOWNICA_TEST=abort` → `awaria`.
  - `test_awaria_polowa_json` *(Review Focus 3)*: `PIASKOWNICA_TEST=polowa` (wypisuje `{"status": "ok", "wyn` i `os._exit(0)`) → `awaria`.
  - `test_pamiec_przez_serwer`: `PIASKOWNICA_TEST=pamiec` → `pamiec`.
  - `test_kolejka_503` *(Review Focus 5)*: `ROWNOLEGLE=1`, `KOLEJKA=1`, hak `petla` + `CZAS=5`; 3 równoczesne żądania → co najmniej jedno `503`.
  - `test_413`: treść > `MAKS_ZADANIE` (podmieniony na 1000) → 413.
  - `test_zdrowie`: `GET /zdrowie` → `{"gvisor": False, "wersja": "1"}` na zwykłym jądrze.
  - `test_log_bez_nazw`: `caplog` po analizie `zip_exe` nie zawiera `faktura` ani tematu.
  - `test_w_gvisor`: `w_gvisor(SYGNATURA_PROC_VERSION, "")` True; `w_gvisor("Linux version 6.x …", "Starting gVisor...")` True; `w_gvisor("Linux version 6.x", "")` False.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja (`threading.BoundedSemaphore(ROWNOLEGLE)` + licznik oczekujących pod `Lock`).  **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `"piaskownica: serwer HTTP z kolejką i wykrywanie gVisor"`.

---

### Task 4: Obraz i kontener `parser`

**Files:**
- Create: `requirements-parser.txt`; Modify: `Dockerfile`, `docker-compose.yml`, `.env.example`, `.dockerignore`

**Interfaces:**
- Produces: target Dockerfile `parser` (CMD `python -I -m piaskownica.serwer`, USER 65534, `WORKDIR /app`, tylko `mailcore/`, `piaskownica/`, `requirements-parser.txt`) i target `web` (obecna zawartość); usługa compose `parser` wg Global Constraints; sieć `piaskownica` (`internal: true`) z członkami `web` i `parser`; `web` i `worker` budowane z `target: web`.

- [ ] **Step 1:** `requirements-parser.txt` = wersje z `requirements.txt` dla: extract-msg, nh3, beautifulsoup4, pyzipper, py7zr, rarfile, zxing-cpp, pillow.
- [ ] **Step 2:** Dockerfile wieloetapowy: `FROM python@<digest> AS baza` (apt `unar`), `FROM baza AS parser`, `FROM baza AS web`. Compose: usługa `parser` (bez `env_file`/sekretów; `environment` tylko `PYTHONDONTWRITEBYTECODE`), `.env.example`: `PARSER_RUNTIME=runc`, `PARSER_WYMAGA_GVISOR=0`, komentarz o `runsc`.
- [ ] **Step 3: Weryfikacja:** `docker compose up -d --build`; następnie:
  - `docker compose exec parser python -c "import socket; ..."` → `redis`, `postgres`, `www.virustotal.com` nieosiągalne;
  - `docker compose exec parser env` → brak `SECRET`, `KEY`, `TOKEN`, `PASSWORD`, `DATABASE`;
  - `docker compose exec parser id -u` → `65534`; zapis do `/app` → „Read-only file system”;
  - `docker compose exec web python -c "import httpx; print(httpx.get('http://parser:8000/zdrowie').json())"` → `{"gvisor": false, "wersja": "1"}`.
- [ ] **Step 4:** Commit `"Kontener parser: osobny obraz, sieć piaskownica, bez sekretów i internetu"`.

---

### Task 5: Klient w `web`, walidacja, przełączenie uploadu

**Files:**
- Create: `analizy/piaskownica_klient.py`, `tests/analizy/test_piaskownica_klient.py`
- Modify: `analizy/uslugi.py`, `analizy/views.py`, `miemli/settings.py`, `miemli/settings_test.py`, `tests/analizy/test_upload.py`

**Interfaces:**
- Consumes: `analizuj_plik` (tryb w procesie), odpowiedź serwera z Task 3.
- Produces:

```python
class PiaskownicaNiedostepna(Exception): ...
class AnalizaPrzerwana(Exception):
    def __init__(self, powod: str): self.powod = powod   # czas|pamiec|awaria|nieprawidlowa_odpowiedz
MAKS_ODPOWIEDZ = 20 * 1024 * 1024; MAKS_IOC = 5000
def waliduj_wynik(wynik: object) -> dict             # zwraca wynik lub rzuca AnalizaPrzerwana("nieprawidlowa_odpowiedz")
def analizuj_w_piaskownicy(dane: bytes, nazwa: str) -> dict
    # settings.PIASKOWNICA_URL == "" → analizuj_plik w procesie; inaczej httpx POST (timeout 90 s)
    # "przerwana"/"nieobslugiwany" → NieobslugiwanyPlik; "za_duzy" → PlikZaDuzy; inne → AnalizaPrzerwana
    # 503, błąd połączenia, timeout → PiaskownicaNiedostepna
def stan_piaskownicy() -> dict | None                 # GET /zdrowie, cache 60 s; None gdy niedostępny lub tryb w procesie
```
- Ustawienia: `PIASKOWNICA_URL = os.environ.get("PIASKOWNICA_URL", "http://parser:8000")`, `PARSER_WYMAGA_GVISOR = _bool(..., False)`; `settings_test`: `PIASKOWNICA_URL = ""`. Dev bez Dockera: `PIASKOWNICA_URL=` (pusty) w środowisku → tryb w procesie (README).
- `utworz_lub_otworz`: wynik z klienta; IOC z `wynik["ioc"]` (słowniki z `do_json`); `AnalizaPrzerwana` → `Zdarzenie(typ="analiza_przerwana", analiza=None, szczegoly={"sha256", "plik", "powod"})` i ponowne rzucenie.
- Widok `upload`: komunikaty z tabeli spec §6 (dokładne teksty); `PiaskownicaNiedostepna` → „Sandbox analizy niedostępny — spróbuj za chwilę.”

- [ ] **Step 1: Failing testy** (`respx` z `settings.PIASKOWNICA_URL = "http://parser.test"`):
  - `test_web_nie_parsuje_lokalnie`: monkeypatch `mailcore.parsuj.parsuj` i `piaskownica.zadanie.analizuj_plik` rzucające `AssertionError`; respx zwraca wynik zrobiony wcześniej przez `analizuj_plik` próbki → upload 302, analiza w bazie.
  - `test_przerwana_czas`: respx `{"status": "przerwana", "powod": "czas"}` → strona zawiera „przekroczony czas” i „Joe Sandbox”; `Zdarzenie(typ="analiza_przerwana")` z `powod == "czas"` i `sha256`; brak `Analiza`.
  - `test_przerwana_awaria_loguje_ostrzezenie`: `powod == "awaria"` → „parser przerwał pracę”, `caplog` ma WARNING.
  - `test_niedostepny_503` i `test_zerwane_polaczenie` *(Review Focus 2)*: 503 / `httpx.ConnectError` / `httpx.RemoteProtocolError` → „Sandbox analizy niedostępny”, status 200, brak 500.
  - `test_walidacja`: parametryzacja — nie-JSON, brak `ioc`, `ioc` = str, 5001 IOC, `typ="exe"`, `wartosc` 9000 znaków, `rodzic_id` ≥ `id`, odpowiedź > 20 MB → `AnalizaPrzerwana("nieprawidlowa_odpowiedz")`.
  - `test_wrogi_wynik_wyswietlany_bezpiecznie` *(Review Focus 1)*: poprawny strukturalnie wynik z tematem `<script>alert(1)</script>` i IOC URL `javascript:alert(1)` → strona szczegółów zawiera `&lt;script&gt;`, nie zawiera `<script>alert`, a `javascript:` nie występuje w atrybucie `href`.
  - `test_naglowek_nazwy` *(Review Focus 4)*: nazwa `"zażółć\r\nX-Evil: 1.eml"` → wysłany nagłówek `X-Miemli-Nazwa` jest URL-encoded (brak `\r`, `\n`), brak nagłówka `X-Evil`; nazwa 1000 znaków → obcięta do 255 przed wysłaniem.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja.  **Step 4:** Run `.venv/bin/pytest -q` → PASS (istniejące testy uploadu przechodzą w trybie w procesie).
- [ ] **Step 5:** Commit `"web: analiza przez sandbox parsera, walidacja odpowiedzi, przerwane analizy"`.

---

### Task 6: Raport obrazków w interfejsie i ostrzeżenie o gVisor

**Files:**
- Create: `tests/analizy/test_raport_obrazkow.py`
- Modify: `templates/analizy/sekcje/wiadomosc.html`, `templates/analizy/_wiersze_ioc.html`, `templates/analizy/_szczegoly_ioc.html`, `templates/base.html`, `analizy/prezentacja.py`, `analizy/views.py` (podgląd: styl `.obrazek-pominiety` w `SZABLON_PODGLADU`), `analizy/templatetags/miemli.py`, `static/css/nord.css`

**Interfaces:**
- Consumes: `wynik["wiadomosc"]…["obrazki"]` (Task 1), `stan_piaskownicy()` (Task 5).
- Produces:
  - `prezentacja.obrazki_po_sha(wynik: dict) -> dict[str, dict]` — wszystkie wpisy raportu z całego drzewa po `sha256`.
  - `PODEJRZANE_UWAGI = {"FORMAT_NIEOBSLUGIWANY", "FORMAT_NIEZGODNY", "ZA_DUZO_PIKSELI", "ZA_DUZY_PLIK", "NIETYPOWE_WYMIARY", "USZKODZONY"}`.
  - Filtr `opis_uwagi_obrazka(kod) -> str` (np. `FORMAT_NIEZGODNY` → „format niezgodny”).
  - Baner w `base.html` dla zalogowanych: gdy `settings.PARSER_WYMAGA_GVISOR` i `stan_piaskownicy()` zwraca `gvisor: false` → „Uwaga: parser nie działa w gVisor — izolacja analizy jest osłabiona.” (context processor `analizy.kontekst.piaskownica`).

- [ ] **Step 1: Failing testy** (analizy tworzone w trybie w procesie z maili budowanych w teście):
  - `test_ramka_obrazki`: mail z PNG cid → sekcja „Obrazki (1)”, format „PNG”, wymiary „100×50”, status „przekodowany”.
  - `test_ostrzezenie_o_nietypowych`: mail z TIFF jako `logo.png` → na górze sekcji „Nietypowe obrazki w wiadomości (1)”, odznaka `warn` „format niezgodny”.
  - `test_animacja_neutralna`: animowany GIF → odznaka `neutral` „animacja”, brak ostrzeżenia na górze.
  - `test_ioc_odznaka_i_szczegoly`: IOC pliku TIFF → w tabeli odznaka „format niezgodny: TIFF”; w szczegółach IOC wymiary/format/uwagi.
  - `test_podglad_ramka_pominietego`: podgląd zawiera `[obrazek pominięty: format TIFF]` i styl `.obrazek-pominiety`.
  - `test_baner_gvisor`: `PARSER_WYMAGA_GVISOR=True` + `stan_piaskownicy` podmieniony na `{"gvisor": False}` → baner na liście analiz; `{"gvisor": True}` lub `PARSER_WYMAGA_GVISOR=False` → brak.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja.  **Step 4:** Run `.venv/bin/pytest -q` → PASS.
- [ ] **Step 5: Wizualnie** (Playwright, `runserver` z `PIASKOWNICA_URL=`): mail z TIFF-em `logo.png`, animowanym GIF-em i zwykłym PNG — ramka obrazków, ostrzeżenie, podgląd.
- [ ] **Step 6:** Commit `"Raport obrazków w interfejsie i ostrzeżenie o braku gVisor"`.

---

### Task 7: Dokumentacja i test całości w Dockerze

**Files:**
- Modify: `README.md`, `NOTES.md`

- [ ] **Step 1:** `docker compose up -d --build`; przez `https://localhost` (curl z sesją) wgraj wszystkie próbki z `tests/samples/*.eml` i `tests/samples/private/testowa_wiadomosc.msg` → każda 302 na analizę; `docker compose logs parser` zawiera tylko linie `sha256 rozmiar czas status` (bez nazw plików i tematów); `docker compose logs web` bez tracebacków.
- [ ] **Step 2:** Plik zabijający parser: wgraj mail z obrazkiem 30 Mpx i mail z zip-bombą → analiza powstaje z ostrzeżeniami (limity mailcore), parser działa dalej (`/zdrowie` 200).
- [ ] **Step 3:** README: architektura z parserem, instalacja gVisor (spec §13), `PARSER_RUNTIME`, `PARSER_WYMAGA_GVISOR`, tryb dev `PIASKOWNICA_URL=`. NOTES: stan, następne kroki (RTIR, Joe).
- [ ] **Step 4:** Usuń dane testowe z bazy Dockera. Commit `"Sandbox parsera: dokumentacja i weryfikacja w Dockerze"`.
