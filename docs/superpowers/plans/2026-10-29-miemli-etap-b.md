# miemli — Etap B — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Oś czasu nagłówków (anomalie przeskoków, kraj/ASN z GTI/Censys, klient i ARC) oraz wyszukiwarka analiz z odznakami „w N innych analizach”.

**Architecture:** Anomalie, klient i ARC liczy `mailcore` w sandboxie parsera (nowe pola `AnalizaWiadomosci`, walidowane w `waliduj_wynik`). Kraj/ASN dokleja warstwa prezentacji z istniejących `Wzbogacenie`. Wyszukiwarka to osobny moduł `analizy/wyszukiwanie.py` + widok `/szukaj/`; odznaki liczone jednym zapytaniem po nowym, indeksowanym `IOC.skrot`.

**Tech Stack:** Python 3.14, Django 6.1, htmx 2.0.4, pytest.

**Spec:** `docs/superpowers/specs/2026-10-29-miemli-etap-b-os-czasu-wyszukiwarka-design.md`

## Global Constraints

- Teksty po polsku dokładnie jak w spec (progi: `CZAS_WSTECZ` > 5 min, `DLUGI_POSTOJ` > 1 h, `CZAS_W_PRZYSZLOSCI` > 15 min, `DATA_ODLEGLA` > 24 h; ARC maks. 50 ogniw; nagłówki klienta przycięte do 300 znaków; wyszukiwarka: wejście maks. 2048 znaków, tekst ≥ 3 znaki, maks. 200 wyników).
- Adnotacja ARC dosłownie: „Wyniki deklarowane przez serwery pośredniczące — podpisy ARC nie są weryfikowane kryptograficznie.”
- `mailcore` bez Django i bez sieci. CSP bez inline w stronach aplikacji. Wartości artefaktów w UI rozbrojone.
- Analizy sprzed zmiany (bez nowych pól w `wynik`) wyświetlają się bez błędów.
- Zapytania wyszukiwarki nie trafiają do `Zdarzenie` ani do logów.
- Branch `etap-b`; commity kończą się `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Nagłówki Received z czasem bez strefy (`-0000`) lub z różnymi strefami** → porównania bez `TypeError` (naiwne = UTC). Test: Task 1.
2. **Wrogi parser zwraca `arc`/`klient`/`uwagi` złego typu lub 10 000 ogniw** → `AnalizaPrzerwana`, nie 500. Test: Task 2.
3. **Wyszukiwanie `evil.com` przy artefakcie `notevil.com`** → brak dopasowania; `com` (bez kropki) traktowane jako tekst. Test: Task 4.
4. **Strona analizy z setkami artefaktów** → liczba zapytań SQL odznak stała (nie rośnie z liczbą artefaktów). Test: Task 5.
5. **`q` z HTML/JS (`<script>`), znakami sterującymi albo 100 kB tekstu** → escapowane, przycięte, 200; nic w logach. Test: Task 4.

---

### Task 1: Anomalie przeskoków i `DATA_ODLEGLA` (mailcore)

**Files:** Modify `mailcore/analiza/received.py`, `mailcore/analiza/__init__.py`; Test `tests/mailcore/analiza/test_received.py`

**Interfaces — Produces:**
- `Hop.uwagi: list[Sygnal]` (domyślnie `[]`; `Sygnal` z `mailcore.analiza.podszywanie`).
- `sciezka_received(w: Wiadomosc, teraz: datetime | None = None) -> list[Hop]` — `teraz` domyślnie `datetime.now(UTC)`; czasy naiwne traktowane jako UTC.
- `sygnaly_czasu(w: Wiadomosc, hopy: list[Hop]) -> list[Sygnal]` — `DATA_ODLEGLA`; `analizuj` dopisuje wynik do `sygnaly`.
- Opisy: `CZAS_WSTECZ` „Czas cofa się o {n} min względem poprzedniego serwera — wpis sfałszowany albo zły zegar.”, `DLUGI_POSTOJ` „Postój {h} h {m} min na poprzednim serwerze.”, `CZAS_W_PRZYSZLOSCI` „Czas w przyszłości — nagłówek sfałszowany albo zły zegar.”, `BRAK_CZASU` „Brak czytelnego czasu.”, `BRAK_IP` „Brak adresu IP.”, `DATA_ODLEGLA` „Data wysłania różni się o {n} h od pierwszego serwera.”

- [ ] **Step 1: Failing testy:** `test_czas_wstecz` (−5 min 1 s → kod; −5 min → brak), `test_dlugi_postoj` (1 h 1 s → kod z „1 h 0 min”; 1 h → brak), `test_przyszlosc` (`teraz` + 16 min → kod; + 15 min → brak), `test_brak_czasu_i_ip`, `test_strefy_i_naiwne` (*Review Focus 1*: hop `-0000` po hopie `+0200` — bez wyjątku, poprawna różnica), `test_data_odlegla` (24 h 1 s w obie strony → sygnał; 24 h → brak; brak `Date` → brak), `test_sygnal_w_analizie` (`analizuj(...).wiadomosci["0"].sygnaly` zawiera `DATA_ODLEGLA`).
- [ ] **Step 2–4:** FAIL → implementacja → PASS (`.venv/bin/pytest -q tests/mailcore`).
- [ ] **Step 5:** Commit `"Oś czasu: anomalie przeskoków Received i odległa data wysłania"`.

---

### Task 2: Klient i ARC (mailcore + walidacja w web)

**Files:** Create `mailcore/analiza/klient.py`, `tests/mailcore/analiza/test_klient.py`; Modify `mailcore/analiza/__init__.py`, `mailcore/analiza/ioc.py`, `analizy/piaskownica_klient.py`, `tests/analizy/test_piaskownica_klient.py`, `tests/mailcore/analiza/test_ioc.py`

**Interfaces — Produces:**
- `@dataclass Klient(x_mailer: str | None, user_agent: str | None, x_originating_ip: str | None)`; `klient(w) -> Klient` (wartości przycięte do 300; `x_originating_ip` bez `[]`, tylko gdy poprawny IP, postać kanoniczna).
- `@dataclass OgniwoArc(i: int, serwer: str | None, spf: str | None, dkim: str | None, dmarc: str | None)`; `@dataclass LancuchArc(ogniwa: list[OgniwoArc], kompletny: bool, cv: str | None)`; `lancuch_arc(w) -> LancuchArc | None` (None bez nagłówków ARC; maks. 50 ogniw, sortowane po `i`; `serwer` = `authserv-id` — pierwszy token po `i=N;`; wyniki parsowane jak `uwierzytelnienie._wynik`; `cv` z `ARC-Seal` najwyższego `i`; `kompletny` = numery 1..n bez luk i dla każdego `i` trzy nagłówki).
- `AnalizaWiadomosci` + pola `klient: Klient`, `arc: LancuchArc | None` (na końcu, po `linki`).
- `ioc.py`: publiczny `x_originating_ip` → artefakt `ip`, `zrodlo="naglowek"` (żeby GTI/Censys dały kraj).
- `piaskownica_klient`: `_analiza_ok` sprawdza opcjonalne `klient` (dict ze str|None, każda ≤ 300) i `arc` (None albo dict: `ogniwa` lista ≤ 50 dictów z `i` int, pozostałe str|None; `kompletny` bool; `cv` str|None) oraz `received[*].uwagi` (lista dictów z `kod`, `opis` str). Brak kluczy = poprawne (stare/zwykłe wyniki).

- [ ] **Step 1: Failing testy:** `test_klient_naglowki` (X-Mailer, User-Agent, `X-Originating-IP: [185.243.115.20]` → `185.243.115.20`; 400 znaków → 300; IP `abc` → None), `test_arc_pelny` (2 ogniwa → `kompletny`, wyniki, `serwer`, `cv="pass"`), `test_arc_niepelny` (brak `ARC-Seal` dla i=2 → `kompletny=False`), `test_arc_luka` (i=1 i 3 → `False`), `test_arc_limit` (60 ogniw → 50), `test_bez_arc` (→ None), `test_x_originating_ip_artefakt` (publiczny → `ip` w IOC; `10.0.0.1` → brak). Walidacja (*Review Focus 2*): parametryzacja `klient` nie-dict / wartość 301 znaków / `arc.ogniwa` 51 elementów / `i` str / `kompletny` str / `uwagi` nie-lista → `AnalizaPrzerwana`; `test_walidacja_poprawnego` nadal przechodzi; wynik bez `klient`/`arc` poprawny.
- [ ] **Step 2–4:** FAIL → implementacja → PASS (`.venv/bin/pytest -q tests/mailcore tests/analizy/test_piaskownica_klient.py`); dodatkowo prawdziwe próbki (`tests/samples/*.eml`, `msg`, `private`) przechodzą `waliduj_wynik`.
- [ ] **Step 5:** Commit `"Klient i łańcuch ARC w analizie nagłówków; X-Originating-IP jako artefakt"`.

---

### Task 3: Oś czasu w interfejsie (kraj/ASN, uwagi, klient, ARC)

**Files:** Modify `analizy/prezentacja.py`, `analizy/views.py` (`_kontekst_szczegolow`, widok wzbogacenia), `templates/analizy/sekcje/received.html`, `templates/analizy/_wzbogacenie_oob.html`, `static/css/nord.css`; Create `templates/analizy/_os_czasu_wiersze.html`; Test `tests/analizy/test_os_czasu.py`

**Interfaces:**
- Consumes: Task 1/2 pola w `analiza.wynik["analiza"][wid]` (`received[*].uwagi`, `klient`, `arc`), `widoki_wzbogacen`.
- Produces: `prezentacja.geo_ip(analiza, wzbogacenia) -> dict[str, dict]` — klucz: IP (postać kanoniczna), wartość `{"stan": "gotowe"|"oczekuje"|"brak", "kraj": str|None, "asn": int|None, "wlasciciel": str|None}`; GTI ma pierwszeństwo, braki uzupełnia Censys. IP niepubliczny → nie ma w słowniku, szablon pokazuje „sieć wewnętrzna”.
- `klasa_uwagi_hopu(kod)`: `CZAS_WSTECZ`/`CZAS_W_PRZYSZLOSCI` → `bad`, `DLUGI_POSTOJ` → `warn`, reszta `neutral`.
- Wiersze przeskoków w `<tbody id="os-czasu-cialo">` z `_os_czasu_wiersze.html`; `_wzbogacenie_oob.html` dokłada ten fragment OOB tylko gdy `sekcja == "received"` (kontekst odpytywania przekazuje sekcję tak jak dla tabeli artefaktów).

- [ ] **Step 1: Failing testy:** `test_kraj_z_gti` (wpis `Wzbogacenie` GTI `{"kraj": "RU", "asn": 12345, "wlasciciel": "X"}` → „RU” i „AS12345” w sekcji), `test_kraj_z_censys_gdy_brak_gti`, `test_oczekuje` („…”), `test_ip_wewnetrzne` („sieć wewnętrzna”), `test_uwagi_hopu` (odznaka `bad` z opisem `CZAS_WSTECZ`), `test_blok_klienta_i_arc` (X-Mailer, adnotacja ARC dosłownie, „łańcuch niekompletny”), `test_stara_analiza` (wynik bez `uwagi`/`klient`/`arc` → 200, bez bloku), `test_oob_os_czasu` (odpowiedź odpytywania dla `sekcja=received` zawiera `id="os-czasu-cialo"` z `hx-swap-oob`).
- [ ] **Step 2–4:** FAIL → implementacja → PASS.
- [ ] **Step 5:** Commit `"Oś czasu w sekcji Received: kraj i ASN, anomalie, klient i ARC"`.

---

### Task 4: Wyszukiwarka

**Files:** Create `analizy/wyszukiwanie.py`, `templates/analizy/szukaj.html`, `tests/analizy/test_wyszukiwanie.py`; Modify `miemli/urls.py`, `templates/base.html` (pole w pasku), `static/css/nord.css`

**Interfaces — Produces:**
- `uzbroj(tekst: str) -> str` — `hxxp`→`http` (bez względu na wielkość liter), `[.]`/`(.)`/`[dot]`→`.`, `[@]`/`[at]`→`@`, `[:]`→`:`; przycięcie, maks. 2048 znaków.
- `rozpoznaj(tekst: str) -> tuple[str, str]` — rodzaj ∈ `hash|ip|email|url|domena|tekst|za_krotki` i wartość znormalizowana (ip kanoniczne, email/domena małe litery, domena przez IDNA; domena wymaga kropki i braku spacji).
- `@dataclass WynikWyszukiwania(analizy: list[Analiza], dopasowania: dict[int, str], obcieto: bool, komunikat: str = "")`; `szukaj(tekst: str) -> WynikWyszukiwania` — dopasowania wg tabeli spec §2.1, analizy z `.defer("wynik")`, najnowsze pierwsze, maks. 200 (`obcieto=True` przy 201+). Opisy dopasowań rozbrojone: „domena: …”, „ip: …”, „e-mail: …”, „url: …”, „plik: …”, „plik .eml/.msg”, „temat”, „nazwa pliku”, „komentarz”.
- Widok `szukaj_widok` (`GET /szukaj/`, name `szukaj`, `login_required`), szablon jak lista analiz + kolumna „Dopasowanie”; pole w pasku `<form method="get" action="{% url 'szukaj' %}">` z `name="q"`, wartość zachowana.

- [ ] **Step 1: Failing testy:** `test_uzbroj` (parametryzacja: `hxxps://evil[.]com/x`, `1.2.3[.]4`, `jan[@]evil(.)com`, `evil[dot]com`), `test_rozpoznaj` (każdy rodzaj + `com` → `tekst`, `ab` → `za_krotki`), wyszukiwanie po: sha256 artefaktu, md5 z `hashe`, sha256 całego pliku, IP, e-mailu, URL (+ jego domena), domenie z subdomeną, temacie, nazwie pliku, komentarzu; `test_bez_falszywej_subdomeny` (*Review Focus 3*: `evil.com` ≠ `notevil.com`), `test_limit_200` (201 analiz → 200, `obcieto`), `test_wymaga_logowania`, `test_bez_wyniku_w_sql`, `test_wrogie_q` (*Review Focus 5*: `<script>alert(1)</script>` escapowane; 100 kB → 200; `caplog` bez treści zapytania; brak nowych `Zdarzenie`), `test_pole_w_pasku` (strona listy zawiera `action="/szukaj/"`).
- [ ] **Step 2–4:** FAIL → implementacja → PASS.
- [ ] **Step 5:** Commit `"Wyszukiwarka analiz (hash, IP, e-mail, URL, domena z subdomenami, tekst)"`.

---

### Task 5: `IOC.skrot` i odznaki „w N innych analizach”

**Files:** Modify `analizy/models.py` (+ migracja schematu i danych `0012_ioc_skrot`), `analizy/uslugi.py`, `analizy/prezentacja.py`, `analizy/views.py`, `templates/analizy/_wiersze_ioc.html`, `templates/analizy/_panel_ioc.html`; Test `tests/analizy/test_odznaki.py`

**Interfaces — Produces:**
- `IOC.skrot = CharField(max_length=64, db_index=True, default="")`; `IOC.skrot_dla(typ: str, wartosc: str) -> str` (sha256 hex z `f"{typ}:{wartosc}"`), ustawiany w `utworz_lub_otworz`.
- Migracja danych `uzupelnij_skrot(apps, schema_editor)`: `only("pk","typ","wartosc")`, `iterator(chunk_size=1000)`, `bulk_update` partiami.
- `prezentacja.inne_analizy(analiza) -> dict[int, int]` — `ioc.pk` → liczba innych analiz (tylko > 0): jedno zapytanie grupujące po `skrot` z `Count("analiza", distinct=True)`, `exclude(analiza=analiza)`, `filter(skrot__in=...)`.
- Odznaka: `<a class="b neutral" href="{% url 'szukaj' %}?q={{ wartosc|urlencode }}">w N innych analizach</a>` (forma „w 1 innej analizie” dla N=1) w tabeli artefaktów i panelu. Consumes: trasa `szukaj` z Task 4.

- [ ] **Step 1: Failing testy:** `test_odznaka` (ta sama domena w 2 innych analizach → „w 2 innych analizach”, link `?q=`), `test_bez_biezacej` (artefakt tylko w bieżącej → brak), `test_forma_1`, `test_stala_liczba_zapytan` (*Review Focus 4*: `django_assert_max_num_queries` taki sam dla analizy z 5 i 200 artefaktami), `test_migracja_skrotu` (wyzerowany `skrot` → funkcja migracji ustawia `IOC.skrot_dla`).
- [ ] **Step 2–4:** FAIL → implementacja → PASS.
- [ ] **Step 5:** Commit `"Odznaki „w N innych analizach” przy artefaktach (IOC.skrot z indeksem)"`.

---

### Task 6: Weryfikacja w przeglądarce, dokumentacja

**Files:** Modify `README.md`, `NOTES.md`

- [ ] **Step 1:** `.venv/bin/pytest -q` → wszystko PASS. Lokalny `runserver` (`PIASKOWNICA_URL=`, `DEBUG=1`, SQLite w scratchpadzie, tymczasowe konto): oś czasu na próbce z kilkoma przeskokami (w tym zmodyfikowanej z cofniętym czasem i ARC — pliki testowe w scratchpadzie), odznaki przy domenie występującej w dwóch analizach, wyszukiwanie wartości rozbrojonej z paska, kliknięcie odznaki → wyniki. Docker `up -d --build`, migracje.
- [ ] **Step 2:** README (oś czasu, wyszukiwarka, odznaki), NOTES (stan etapu B, etap C następny). Usunięcie danych testowych. Commit `"Etap B: dokumentacja"`.
