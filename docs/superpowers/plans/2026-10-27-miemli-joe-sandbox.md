# miemli — Integracja z Joe Sandbox — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Analityk wysyła cały mail do Joe Sandbox Cloud swoim kluczem (Live Interaction) — z sekcji „Joe Sandbox” (ponowne wgranie, weryfikacja SHA256) lub checkboxem przy uploadzie — a miemli śledzi status i werdykt; klucze Joe szyfrowane kluczem publicznym, którego parę prywatną ma tylko worker.

**Architecture:** `analizy/klucze_joe.py` (PyNaCl `SealedBox`) — `web` szyfruje kluczem publicznym, worker odszyfrowuje prywatnym. `integracje/joe.py` — czysty klient HTTP (httpx, odczyt strumieniowy ≤ 1 MB). `analizy/joe_zadania.py` — zlecenie w `web` (walidacje, szyfrogram pliku do kolejki) i zadania workera (wysyłka, śledzenie co 30 s, sprawdzenie klucza). Sekcja `?sekcja=joe` + strona `/profil/`.

**Tech Stack:** Python 3.14, Django 6.1, django-rq (JSONSerializer), httpx, respx, PyNaCl, htmx.

**Spec:** `docs/superpowers/specs/2026-10-27-miemli-joe-sandbox-design.md`

## Global Constraints

- Parametry wysyłki dokładnie: `live-interaction=1`, `internet-access=1`, `url-reputation=0`, `delete-after-days=30`, `accept-tac=1`, `comments="miemli, analiza #<id>"`; bez `systems`.
- API: baza `JOE_API_URL` (domyślnie `https://jbxcloud.joesecurity.org/api`); klucz w polu formularza `apikey`, nigdy w nagłówku; `POST /v2/submission/new`, `POST /v2/submission/info`, `POST /v2/account/info`.
- Link do analizy budowany przez miemli: `https://jbxcloud.joesecurity.org/analysis/<webid>`; `webid` i `id_zgloszenia` muszą pasować do `^[A-Za-z0-9_-]{1,64}$`.
- Odpowiedzi Joe: maks. 1 MB (odczyt strumieniowy), komunikat błędu Joe maks. 200 znaków.
- Klucz Joe: `^[A-Za-z0-9]{20,128}$`; w bazie szyfrogram + 4 ostatnie znaki; nigdy w HTML, logach ani audycie.
- Tekst jawny szyfrogramów: klucz = `f"{uzytkownik_id}:{klucz}"`, plik = `f"{zgloszenie_id}:".encode() + dane`.
- Limity: duplikat (ten sam analityk + analiza) 10 min; `JOE_LIMIT_DZIENNY` (domyślnie 20) od północy (strefa `Europe/Warsaw`).
- Śledzenie co 30 s, maks. 2 h od `wyslano`; ponowienia: limit 60 s, 300 s; sieć/5xx 30 s, 120 s.
- Zadania Joe w kolejce: `result_ttl=0`, `failure_ttl=0`; argumenty wyłącznie str/int (JSON).
- Redis: `--save "" --appendonly no`.
- `web` ma tylko `JOE_KLUCZ_PUBLICZNY`; `JOE_KLUCZ_PRYWATNY` tylko worker.
- Komunikaty (dokładne teksty) wg spec §5 i §6. Okno potwierdzenia przez `data-potwierdz` (bez JS inline — CSP).
- Commity kończą się `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Joe zwraca „finished” bez listy analiz albo bez `detection`/`score`** → `zakonczone`, werdykt `nieznany`, brak wyjątku. Test: Task 2.
2. **Analityk usuwa klucz, gdy wysyłka czeka w kolejce** → zgłoszenie `blad` „Ustaw klucz Joe w profilu.”, brak wyjątku w workerze. Test: Task 3.
3. **Analiza usunięta, gdy zadanie czeka** (kaskadowo znika `ZgloszenieJoe`) → zadanie kończy się po cichu. Test: Task 3.
4. **Podwójne kliknięcie „Wyślij”** → drugie żądanie odrzucone jako duplikat, jedna wysyłka. Test: Task 4.
5. **Wgrany plik inny niż analizowany** (inny mail, ten sam mail z dopisanym bajtem) → „To nie jest ten sam plik co w analizie.”, nic nie trafia do kolejki. Test: Task 4.

---

## Struktura plików

```
analizy/klucze_joe.py                         szyfrowanie SealedBox
analizy/management/commands/joe_generuj_klucze.py
analizy/models.py                             + ProfilAnalityka, ZgloszenieJoe
analizy/profil.py                             widok /profil/ i formularz
analizy/joe_zadania.py                        zlec_wysylke (web), zadania workera
integracje/joe.py                             klient API Joe
templates/analizy/profil.html, templates/analizy/sekcje/joe.html, templates/analizy/_joe_historia.html
tests/analizy/test_klucze_joe.py, test_profil.py, test_joe_zadania.py, test_joe_widoki.py
tests/integracje/test_joe.py
```

---

### Task 1: Szyfrowanie kluczy, profil analityka

**Files:**
- Create: `analizy/klucze_joe.py`, `analizy/management/commands/joe_generuj_klucze.py`, `analizy/profil.py`, `templates/analizy/profil.html`, `tests/analizy/test_klucze_joe.py`, `tests/analizy/test_profil.py`
- Modify: `requirements.txt` (PyNaCl), `analizy/models.py`, `miemli/urls.py`, `miemli/settings.py`, `miemli/settings_test.py`, `templates/base.html`, migracja

**Interfaces:**
- Produces:

```python
# analizy/klucze_joe.py
class BladOdszyfrowania(Exception): ...
def nowa_para() -> tuple[str, str]                          # (publiczny_b64, prywatny_b64)
def zaszyfruj_klucz(uzytkownik_id: int, klucz: str) -> str  # settings.JOE_KLUCZ_PUBLICZNY
def odszyfruj_klucz(uzytkownik_id: int, szyfrogram: str) -> str   # settings.JOE_KLUCZ_PRYWATNY
def zaszyfruj_plik(zgloszenie_id: int, dane: bytes) -> str
def odszyfruj_plik(zgloszenie_id: int, szyfrogram: str) -> bytes
# brak klucza prywatnego / zły szyfrogram / inny identyfikator → BladOdszyfrowania

# analizy/models.py
class ProfilAnalityka(models.Model):
    uzytkownik = OneToOneField(User, CASCADE, related_name="profil")
    joe_klucz_szyfr = TextField(null=True, blank=True)
    joe_klucz_koncowka = CharField(max_length=4, blank=True, default="")
    joe_klucz_stan = CharField(max_length=12, default="nieznany")   # nieznany|sprawdzanie|dziala|odrzucony
    joe_klucz_zmieniono = DateTimeField(null=True, blank=True)
def profil_dla(uzytkownik) -> ProfilAnalityka                     # get_or_create

# analizy/profil.py — URL "profil" (/profil/), login_required
# POST akcja=zapisz (pole klucz_joe) | akcja=usun
```
- Ustawienia: `JOE_KLUCZ_PUBLICZNY`, `JOE_KLUCZ_PRYWATNY` (env, domyślnie `""`), `JOE_LIMIT_DZIENNY` (env int, 20), `JOE_API_URL`. `settings_test`: puste klucze (testy ustawiają parę z `nowa_para()`).
- Po zapisie klucza: `joe_klucz_stan="sprawdzanie"` i zlecenie sprawdzenia — w tym tasku przez `analizy.joe_zadania.zlec_sprawdzenie_klucza(uzytkownik_id)` zdefiniowane jako no-op stub (pełna implementacja w Task 3).

- [ ] **Step 1:** Zainstaluj `pynacl` (przypnij w `requirements.txt`).
- [ ] **Step 2: Failing testy** `test_klucze_joe.py` (fixture ustawia `settings.JOE_KLUCZ_PUBLICZNY/PRYWATNY` z `nowa_para()`):
  - `test_round_trip_klucza`: `odszyfruj_klucz(7, zaszyfruj_klucz(7, "Abc123..."))` == wejście.
  - `test_round_trip_pliku`: bajty 0–255 ×1000.
  - `test_inny_uzytkownik_odrzucony`: `odszyfruj_klucz(8, zaszyfruj_klucz(7, k))` → `BladOdszyfrowania`.
  - `test_inne_zgloszenie_odrzucone`: analogicznie dla pliku.
  - `test_bez_klucza_prywatnego`: `settings.JOE_KLUCZ_PRYWATNY = ""` → `BladOdszyfrowania`.
  - `test_wymiana_pary`: szyfrogram ze starej pary, odszyfrowanie nową → `BladOdszyfrowania`.
  - `test_szyfrogram_nie_zawiera_jawnego`: jawny klucz nie występuje w szyfrogramie ani jego base64-dekodzie.
  - `test_komenda_generuj`: `call_command("joe_generuj_klucze")` wypisuje `JOE_KLUCZ_PUBLICZNY=` i `JOE_KLUCZ_PRYWATNY=`; para działa.
- [ ] **Step 3: Failing testy** `test_profil.py`:
  - `test_profil_wymaga_logowania` (GET → 302 na logowanie).
  - `test_zapis_klucza`: POST `akcja=zapisz`, `klucz_joe="A"*30+"x7f3"` → 302 na profil; `profil.joe_klucz_koncowka == "x7f3"`, `joe_klucz_stan == "sprawdzanie"`, szyfrogram odszyfrowuje się do klucza; `Zdarzenie(typ="joe_klucz_ustawiony")` bez klucza w `szczegoly`.
  - `test_klucz_nigdy_w_html`: po zapisie GET profilu nie zawiera klucza, zawiera `…x7f3`; pole ma `type="password"` i `autocomplete="off"`.
  - `test_zly_format`: `"krótki"`, `"a"*129`, `"klucz z spacją…"` → komunikat „Nieprawidłowy format klucza Joe.”, nic nie zapisane.
  - `test_usuniecie`: `akcja=usun` → szyfrogram `None`, końcówka `""`, `Zdarzenie(typ="joe_klucz_usuniety")`.
  - `test_get_nie_zmienia`: GET z parametrami nie zapisuje.
  - `test_link_profilu_w_pasku`: lista analiz zawiera link do `/profil/`.
- [ ] **Step 4:** Run → FAIL.  **Step 5:** Implementacja + `makemigrations analizy -n profil_analityka`.  **Step 6:** Run `.venv/bin/pytest -q` → PASS.
- [ ] **Step 7:** Commit `"Joe: szyfrowanie kluczy analityków (SealedBox) i strona profilu"`.

---

### Task 2: Klient API Joe

**Files:**
- Create: `integracje/joe.py`, `tests/integracje/test_joe.py`

**Interfaces:**
- Produces:

```python
BAZA = "https://jbxcloud.joesecurity.org/api"
PARAMETRY = {"live-interaction": "1", "internet-access": "1", "url-reputation": "0",
             "delete-after-days": "30", "accept-tac": "1"}
MAKS_ODPOWIEDZ = 1024 * 1024
@dataclass
class WynikJoe:
    status: str          # "ok" | "odrzucony" | "limit" | "niedostepny"
    dane: dict = field(default_factory=dict)
    blad: str = ""
    ponawiac: bool = False
def wyslij(klucz: str, dane: bytes, nazwa_pliku: str, komentarz: str, baza: str = BAZA) -> WynikJoe
    # ok → dane = {"id_zgloszenia": str}
def stan_zgloszenia(klucz: str, id_zgloszenia: str, baza: str = BAZA) -> WynikJoe
    # ok → dane = {"status": "w_kolejce"|"trwa"|"zakonczone", "webid": str|None, "werdykt": str|None, "wynik": int|None}
def info_konta(klucz: str, baza: str = BAZA) -> WynikJoe
def link_analizy(webid: str) -> str              # ValueError gdy webid nie pasuje do wzorca
```

Mapowanie: 200 + `{"data": …}` → `ok`; 401/403 → `odrzucony` „Klucz Joe odrzucony — sprawdź go w profilu.”; 429 → `limit`, `ponawiac=True`; 5xx/timeout/sieć → `niedostepny`, `ponawiac=True`; 200/400 z `{"errors": [{"message": …}]}` → `odrzucony` „Joe nie przyjął pliku: <message[:200]>”; nie-JSON, odpowiedź > 1 MB, zły `submission_id`/`webid` → `niedostepny` „Nieprawidłowa odpowiedź Joe.”, `ponawiac=False`.
`stan_zgloszenia` (`/v2/submission/info`): `status` `submitted`→`w_kolejce`, `running`→`trwa`, `finished`→`zakonczone`; `webid` z `data.analyses[0].webid`; werdykt i wynik z `data.most_relevant_analysis` (fallback `analyses[0]`): `detection` `malicious`→`zlosliwy`, `suspicious`→`podejrzany`, `clean`→`czysty`, inne/brak→`nieznany`; `score` int lub `None`.

- [ ] **Step 1: Failing testy** (`respx`):
  - `test_wyslij_parametry`: żądanie multipart zawiera pola `apikey`, wszystkie `PARAMETRY`, `comments`, plik o nazwie `analiza-12.eml`; nagłówki NIE zawierają klucza; brak pola `systems[]`; wynik `ok`, `id_zgloszenia == "123"`.
  - `test_wyslij_401_403` → `odrzucony`, `ponawiac is False`.
  - `test_wyslij_429` → `limit`, `ponawiac is True`.
  - `test_wyslij_500_i_timeout` → `niedostepny`, `ponawiac is True`.
  - `test_wyslij_blad_joe`: 400 `{"errors": [{"message": "Unsupported file type " + "x"*500}]}` → `odrzucony`, `blad` zaczyna się od „Joe nie przyjął pliku:” i ma ≤ 230 znaków.
  - `test_odpowiedz_za_duza`: strumień > 1 MB → `niedostepny` „Nieprawidłowa odpowiedź Joe.”.
  - `test_nie_json` → jw.
  - `test_zly_id_zgloszenia`: `submission_id = "../x"` → jw.
  - `test_stan_trwa_i_zakonczone`: `running` z webid → `trwa`, `webid`; `finished` + `most_relevant_analysis` `{"detection": "malicious", "score": 87}` → `zakonczone`, `zlosliwy`, 87.
  - `test_stan_zakonczone_bez_analiz` *(Review Focus 1)*: `finished`, `analyses: []`, brak `most_relevant_analysis` → `zakonczone`, `werdykt == "nieznany"`, `webid is None`.
  - `test_link_analizy`: `link_analizy("1234567")` → `https://jbxcloud.joesecurity.org/analysis/1234567`; `link_analizy("x/../y")` → `ValueError`.
  - `test_info_konta_ok_i_odrzucony`.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja (odczyt przez `httpx.stream`, limit jak w `analizy/piaskownica_klient._czytaj_z_limitem`, User-Agent `miemli/1.0`, timeout 60 s dla wysyłki i 20 s dla pozostałych).  **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `"integracje: klient Joe Sandbox"`.

---

### Task 3: Zgłoszenia i zadania workera

**Files:**
- Create: `analizy/joe_zadania.py`, `tests/analizy/test_joe_zadania.py`
- Modify: `analizy/models.py` (+ `ZgloszenieJoe`, migracja), `docker-compose.yml` (Redis `--save "" --appendonly no`), `analizy/profil.py` (prawdziwe `zlec_sprawdzenie_klucza`)

**Interfaces:**
- Consumes: `klucze_joe.*`, `integracje.joe.*`, `ProfilAnalityka`.
- Produces:

```python
class ZgloszenieJoe(models.Model):
    analiza = FK(Analiza, CASCADE, related_name="zgloszenia_joe"); uzytkownik = FK(User, PROTECT)
    utworzono = DateTimeField(auto_now_add=True); wyslano = DateTimeField(null=True)
    status = CharField(max_length=12)   # zlecone|wyslane|w_kolejce|trwa|zakonczone|blad|limit|czas_minal
    id_zgloszenia = CharField(max_length=64, null=True); webid = CharField(max_length=64, null=True)
    werdykt = CharField(max_length=12, null=True); wynik = IntegerField(null=True)
    blad = TextField(blank=True, default=""); sprawdzono = DateTimeField(null=True)
    AKTYWNE = ("zlecone", "wyslane", "w_kolejce", "trwa")
    @property link -> str | None       # link_analizy(webid) gdy webid

class BladZlecenia(Exception): ...      # komunikat dla analityka w str(e)
def zlec_wysylke(analiza, uzytkownik, dane: bytes) -> ZgloszenieJoe
def zlec_sprawdzenie_klucza(uzytkownik_id: int) -> None
def wyslij_do_joe(zgloszenie_id: int, szyfrogram: str, proba: int = 0) -> None
def sprawdz_joe(zgloszenie_id: int) -> None
def sprawdz_klucz_joe(uzytkownik_id: int) -> None
def _kolejkuj(funkcja, *args, opoznienie: int = 0) -> None   # django_rq, result_ttl=0, failure_ttl=0; podmieniane w testach; błąd Redisa → logger.warning
```
- `zlec_wysylke`: kolejność walidacji i teksty jak spec §5 pkt 1 (SHA256 → klucz → duplikat 10 min → limit dzienny), potem zgłoszenie `zlecone`, `Zdarzenie(typ="joe_wyslanie", analiza=…, szczegoly={"zgloszenie": id})`, `_kolejkuj(wyslij_do_joe, id, zaszyfruj_plik(id, dane))`.
- `wyslij_do_joe`: brak zgłoszenia → return; odszyfrowanie pliku (błąd → `blad` „Błąd wewnętrzny wysyłki.”) i klucza (brak/błąd → `blad` „Ustaw ponownie klucz Joe w profilu.”, `profil.joe_klucz_stan="odrzucony"`); nazwa `analiza-<id>.<eml|msg>` (rozszerzenie z `analiza.nazwa_pliku`, inaczej `eml`); wynik `ok` → `wyslane`, `wyslano=now`, `_kolejkuj(sprawdz_joe, id, opoznienie=30)`; `limit`/`niedostepny` z `ponawiac` → ponowienie wg Global Constraints (ten sam szyfrogram), po wyczerpaniu `limit`/`blad`; `odrzucony` → `blad` z komunikatem.
- `sprawdz_joe`: brak zgłoszenia lub status nieaktywny → return; `ok` → aktualizacja pól; `zakonczone` → koniec; inaczej, jeśli `now - wyslano < 2 h` → `_kolejkuj(sprawdz_joe, id, opoznienie=30)`, w przeciwnym razie `czas_minal`; błędy przejściowe → kolejna próba za 30 s (w granicy 2 h).
- `sprawdz_klucz_joe`: `info_konta` → `dziala` / `odrzucony`; błąd przejściowy → `nieznany`.

- [ ] **Step 1: Failing testy** (`_kolejkuj` podmieniony na listę; klient Joe przez `respx` lub podmienione funkcje `integracje.joe`; para kluczy w fixture):
  - `test_zlecenie_ok`: poprawne bajty próbki → zgłoszenie `zlecone`, zdarzenie, w kolejce `(wyslij_do_joe, (id, szyfrogram))`.
  - `test_kolejka_tylko_szyfrogram`: bajty maila i fragmenty jego treści (temat) nie występują w `json.dumps(args)` zadania.
  - `test_inny_plik` *(Review Focus 5)*: inne bajty oraz te same + `b"\n"` → `BladZlecenia("To nie jest ten sam plik co w analizie.")`, kolejka pusta.
  - `test_brak_klucza`, `test_duplikat_10_min`, `test_limit_dzienny` (`settings.JOE_LIMIT_DZIENNY=2`) — teksty wg spec.
  - `test_wysylka_ok_i_sledzenie`: `wyslij_do_joe` → `wyslane`, zaplanowane `sprawdz_joe` z `opoznienie=30`; `sprawdz_joe` z `running` → `trwa` + kolejne zaplanowanie; z `finished` → `zakonczone`, werdykt, brak zaplanowania.
  - `test_ponowienia_limit`: `limit` przy próbach 0,1 → ponowienia 60 i 300 s; przy próbie 2 → `limit`.
  - `test_odrzucony_klucz`: 403 → `blad` „Klucz Joe odrzucony — sprawdź go w profilu.”.
  - `test_klucz_usuniety_w_trakcie` *(Review Focus 2)*: profil bez klucza → `blad` „Ustaw ponownie klucz Joe w profilu.”, bez wyjątku.
  - `test_analiza_usunieta_w_trakcie` *(Review Focus 3)*: usunięcie analizy, potem `wyslij_do_joe(id, …)` i `sprawdz_joe(id)` → brak wyjątku, brak zapytań do Joe.
  - `test_czas_minal`: `wyslano = now - 2h1min`, `running` → `czas_minal`.
  - `test_sprawdz_klucz`: `dziala` / `odrzucony`.
  - `test_logi_bez_klucza_i_nazwy`: `caplog` po wysyłce nie zawiera klucza ani `analiza.nazwa_pliku`.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja + `makemigrations analizy -n zgloszenie_joe`; Redis w compose.  **Step 4:** Run `.venv/bin/pytest -q` → PASS.
- [ ] **Step 5:** Commit `"Joe: zgłoszenia, wysyłka i śledzenie w workerze"`.

---

### Task 4: Sekcja „Joe Sandbox” i checkbox przy uploadzie

**Files:**
- Create: `templates/analizy/sekcje/joe.html`, `templates/analizy/_joe_historia.html`, `tests/analizy/test_joe_widoki.py`
- Modify: `analizy/views.py`, `analizy/urls.py`, `analizy/forms.py`, `analizy/prezentacja.py`, `templates/analizy/_glowna.html`, `templates/analizy/lista.html`, `static/css/nord.css`

**Interfaces:**
- Consumes: `zlec_wysylke`, `BladZlecenia`, `ZgloszenieJoe`, `profil_dla`.
- Produces:
  - `?sekcja=joe` dozwolona w `szczegoly` (spoza listy `SEKCJE` w nawigacji); pozycja „Analizuj w JOE” w menu robi `hx-get="?sekcja=joe&wiadomosc=…"` (zamiast linku zewnętrznego), zachowuje klasę `nav-joe`, `on` gdy aktywna.
  - `analizy:joe_wyslij` `POST /analiza/<pk>/joe/` (login, pole `plik`) → sukces: 302 na `?sekcja=joe`; `BladZlecenia` → strona sekcji z komunikatem (status 200).
  - `analizy:joe_historia` `GET /analiza/<pk>/joe/historia/` → fragment `_joe_historia.html`; element z `hx-trigger="every 5s"` tylko gdy istnieje zgłoszenie w `ZgloszenieJoe.AKTYWNE`.
  - `UploadForm.do_joe = BooleanField(required=False, label="Wyślij też do Joe Sandbox")`; po udanym `utworz_lub_otworz` z zaznaczonym checkboxem → `zlec_wysylke(analiza, user, dane)`; `BladZlecenia` → komunikat zapisany w `request.session["joe_komunikat"]` i pokazany raz w sekcji Joe; przekierowanie na `?sekcja=joe`.
  - Formularze wysyłki z `data-potwierdz` = tekst ze spec §4.1.
- Historia: kolumny analityk, czas (`Y-m-d H:i`), status (opis po polsku), werdykt (odznaka `bad`/`warn`/`ok`/`neutral`) + wynik, link „Otwórz w Joe ↗” (`target="_blank" rel="noopener noreferrer"`) gdy `webid`, błąd.

- [ ] **Step 1: Failing testy:**
  - `test_menu_joe_otwiera_sekcje`: nawigacja zawiera `class="nav-joe"` z `hx-get` na `sekcja=joe`, bez `jbxcloud` w `href`.
  - `test_sekcja_bez_klucza`: przycisk wysyłki `disabled`, tekst „Ustaw klucz Joe w profilu”, link do `/profil/`.
  - `test_wyslij_ok`: z kluczem i bajtami próbki → 302, zgłoszenie istnieje; formularz miał `data-potwierdz` z „poza firmę” i „30 dniach”.
  - `test_wyslij_inny_plik`: komunikat „To nie jest ten sam plik co w analizie.”, brak zgłoszenia.
  - `test_podwojne_klikniecie` *(Review Focus 4)*: dwa POST-y → jedno zgłoszenie, drugi z „Już wysłano — poczekaj na wynik.”.
  - `test_historia_odswiezanie`: zgłoszenie `trwa` → `every 5s`; `zakonczone` → brak; widać „złośliwy”, link `https://jbxcloud.joesecurity.org/analysis/123`, nazwę analityka.
  - `test_checkbox_przy_uploadzie`: upload z `do_joe=on` → przekierowanie na `?sekcja=joe`, zgłoszenie utworzone; bez checkboxa → brak zgłoszenia.
  - `test_checkbox_bez_klucza`: upload z `do_joe=on` bez klucza → analiza utworzona, sekcja Joe pokazuje „Ustaw klucz Joe w profilu.” raz (drugie wejście już bez komunikatu).
  - `test_endpointy_wymagaja_logowania` i `test_joe_wyslij_get_405`.
  - `test_csp_bez_inline`: strona sekcji Joe bez `on*=`, `style="`, `<script>` inline.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja.  **Step 4:** Run `.venv/bin/pytest -q` → PASS.
- [ ] **Step 5:** Commit `"Sekcja Joe Sandbox: wysyłka z ponownym wgraniem, historia, checkbox przy uploadzie"`.

---

### Task 5: Docker, dokumentacja, test na prawdziwym koncie

**Files:**
- Modify: `docker-compose.yml`, `.env.example`, `README.md`, `NOTES.md`

- [ ] **Step 1:** Compose: `web` — `JOE_KLUCZ_PUBLICZNY`, `JOE_LIMIT_DZIENNY`; `worker` — `JOE_KLUCZ_PUBLICZNY`, `JOE_KLUCZ_PRYWATNY`, `JOE_API_URL`; `.env.example` z opisem i komendą `docker compose run --rm worker python manage.py joe_generuj_klucze`.
- [ ] **Step 2:** Wygeneruj parę kluczy i dopisz do lokalnego `.env` (bez wypisywania prywatnego); `docker compose up -d --build`; sprawdź: `docker compose exec web env` nie zawiera `JOE_KLUCZ_PRYWATNY`; `docker compose exec redis redis-cli -a … CONFIG GET save` → pusty.
- [ ] **Step 3: Test z użytkownikiem (prawdziwy klucz Joe):** użytkownik wpisuje swój klucz w `https://localhost/profil/` → stan „działa”; wysyłka `phishing_klasyczny.eml` i prywatnego `.msg` → status przechodzi do `trwa`/`zakonczone`, link otwiera analizę w Joe (Live Interaction). Zanotuj, czy `.msg` jest przyjmowany i czy pola `detection`/`score` mają oczekiwane nazwy — rozbieżności poprawić z testem.
- [ ] **Step 4:** README (konfiguracja kluczy, profil, sekcja Joe), NOTES (stan, RTIR jako źródło oryginału na później). Usuń dane testowe. Commit `"Joe Sandbox: konfiguracja Dockera i dokumentacja"`.
