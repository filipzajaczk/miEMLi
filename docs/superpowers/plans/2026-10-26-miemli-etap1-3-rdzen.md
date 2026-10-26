# miemli — Etapy 1–3: szkielet, rdzeń parsowania, ekran analizy — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Działające narzędzie w Dockerze, w którym zalogowany analityk wgrywa ręcznie `.eml`/`.msg`, a miemli pokazuje bezpieczny podgląd wiadomości, nagłówki, ścieżkę Received, załączniki (z archiwami i zagnieżdżonymi mailami), linki i tabelę IOC z relacjami — bez integracji z API (te w kolejnych planach).

**Architecture:** Czysty pakiet Pythona `mailcore` (parsowanie + analiza, bez Django, bez sieci) oraz projekt Django `miemli` z aplikacją `analizy` (modele, widoki, szablony htmx). `docker compose`: caddy (TLS `internal`) → web (gunicorn) + postgres + redis + worker (rqworker, na razie bez zadań).

**Tech Stack:** Python 3.14, Django 6.0, htmx 2.0.4 (vendorowany), PostgreSQL 17, Redis 7, django-rq, gunicorn, whitenoise, dj-database-url, extract-msg, nh3, beautifulsoup4, pyzipper, py7zr, rarfile, zxing-cpp, Pillow, pytest, pytest-django.

**Spec:** `docs/superpowers/specs/2026-10-26-miemli-design.md`

**Zakres tego planu:** etapy 1–3 ze specyfikacji (§11). Etapy 4–5 (GTI, Censys, Joe) i 6–7 (RTIR, raport, szlify) dostaną osobne plany, pisane po zobaczeniu realnych odpowiedzi API (spec §12). W tym planie **nie** budujemy: profilu z kluczem Joe, wzbogacenia, sekcji Raport, pól werdyktu w UI.

## Global Constraints

- Python 3.14; pakiety tylko w `.venv` (`python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements-dev.txt`). Systemowy pip jest zablokowany.
- `requirements.txt` (runtime) i `requirements-dev.txt` (`-r requirements.txt` + narzędzia testowe); wersje przypięte (`==`) do najnowszych dostępnych w chwili instalacji.
- Sekrety tylko w `.env` / zmiennych środowiskowych; w repo wyłącznie `.env.example` z pustymi wartościami.
- Cały interfejs, komunikaty błędów i ostrzeżenia parsowania po polsku.
- Paleta Nord ciemny: tło `#2e3440`, tło2 `#2a2f3a`, karta `#353c4a`, tekst `#e5e9f0`, wyciszony `#8892a6`, linie `#3f4656`, akcent `#88c0d0`, OK `#a3be8c`, ostrzeżenie `#ebcb8b`, źle `#d08770` (wzór: `docs/superpowers/mockups/02-uklad.html`).
- Układ ekranu analizy: wariant C makiety (nawigacja sekcji po lewej, treść na środku, stały panel IOC po prawej), pełna tabela IOC jako sekcja.
- Limity: maks. plik wejściowy **50 MB**, maks. głębokość zagnieżdżeń **5**, maks. łącznie rozpakowane **200 MB**.
- Załączniki nigdy nie trafiają na dysk: upload Django tylko przez `MemoryFileUploadHandler`, rozpakowywanie w pamięci, oryginał nie jest zapisywany w bazie.
- IOC zawsze wyświetlane rozbrojone (`hxxp`, `[.]`), w bazie przechowywane surowe.
- Podgląd HTML: osobny endpoint z nagłówkiem `Content-Security-Policy: default-src 'none'; img-src data:; style-src 'unsafe-inline'`, osadzany w `<iframe sandbox>` (bez żadnych `allow-*`).
- Wszystkie widoki poza logowaniem wymagają zalogowania; konta zakłada admin w `/admin/`.
- Kod `mailcore/` nie importuje Django ani nie wykonuje połączeń sieciowych.
- Identyfikatory w kodzie po polsku bez znaków diakrytycznych (`Wiadomosc`, `zalaczniki`), jak w specyfikacji.
- Małe commity, wiadomości opisowe, każdy kończy się linią `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Mail z krzywym kodowaniem** (treść w `windows-1250` bez deklaracji `charset`, nagłówek z nieprawidłowym encoded-word) → treść czytelna, ostrzeżenie `KODOWANIE`, brak wyjątku. Test: Task 3.
2. **Mail bez treści albo bez `Authentication-Results`/`Received`** (np. tylko załącznik, zapis z Outlooka bez nagłówków transportowych) → sekcje pokazują „brak danych”, nic nie wybucha. Testy: Task 6 i Task 12.
3. **Złośliwe archiwa** (zip bomba, archiwum w archiwum 7 poziomów, uszkodzony zip) → przerwane rozpakowanie z ostrzeżeniem, reszta analizy zostaje. Testy: Task 5.
4. **HTML próbujący wyjść z podglądu** (`<script>`, `<img src="http://…">`, `href="javascript:…"`, `style="background:url(http://…)"`, `<meta http-equiv="refresh">`) → nic nie wykonuje się ani nie ładuje. Testy: Task 9 i Task 12 (nagłówek CSP).
5. **Ten sam plik wgrany dwa razy** oraz **ten sam plik w różnych ticketach** → deduplikacja wg (ticket, SHA256). Test: Task 11.

---

## Struktura plików

```
requirements.txt, requirements-dev.txt, pytest.ini, manage.py
.env.example, Dockerfile, docker-compose.yml, Caddyfile, docker/entrypoint.sh
miemli/            settings.py, urls.py, wsgi.py
mailcore/
  model.py         dataclassy: Wiadomosc, Zalacznik, Ostrzezenie, Limity, wyjątki
  parsuj.py        parsuj(): wykrycie typu, rekurencja, limity
  eml.py           .eml → Wiadomosc (jeden poziom)
  msg.py           .msg → Wiadomosc (jeden poziom)
  archiwa.py       rozpakowywanie zip/7z/rar, hasła, budżet
  analiza/
    __init__.py    analizuj() → WynikAnalizy
    uwierzytelnienie.py, received.py, podszywanie.py, linki.py, qr.py, ioc.py
  rozbrajanie.py   rozbroj()
  html_bezpieczny.py  bezpieczny_html()
  serializacja.py  do_json()
analizy/           aplikacja Django: models.py, uslugi.py, views.py, urls.py, forms.py, admin.py
templates/         base.html, registration/login.html, analizy/*.html, analizy/sekcje/*.html
static/            css/nord.css, js/htmx.min.js
tests/
  conftest.py      fabryki maili (EmailMessage) wspólne dla testów
  mailcore/…       testy jednostkowe
  analizy/…        testy Django
  samples/         generuj_probki.py, *.eml + *.expected.json, msg/ (próbki .msg), private/ (gitignore)
```

---

### Task 1: Szkielet Django, logowanie, styl Nord

**Files:**
- Create: `requirements.txt`, `requirements-dev.txt`, `pytest.ini`, `manage.py`, `miemli/{__init__,settings,urls,wsgi}.py`, `analizy/{__init__,apps}.py`, `templates/base.html`, `templates/registration/login.html`, `templates/analizy/lista.html`, `static/css/nord.css`, `static/js/htmx.min.js`, `analizy/views.py`, `analizy/urls.py`, `NOTES.md`
- Test: `tests/analizy/test_logowanie.py`

**Interfaces:**
- Produces: URL name `analizy:lista` (`/`), `login` (`/logowanie/`), `logout` (`/wyloguj/`), `admin:index` (`/admin/`); `templates/base.html` z blokami `{% block tytul %}`, `{% block pasek %}`, `{% block tresc %}`; ładuje `nord.css` i `htmx.min.js`.

- [ ] **Step 1: venv i zależności.** Utwórz `.venv`, zapisz w `requirements.txt` wszystkie pakiety runtime ze „Tech Stack” (Django, django-rq, gunicorn, whitenoise, dj-database-url, psycopg[binary], extract-msg, nh3, beautifulsoup4, pyzipper, py7zr, rarfile, zxing-cpp, Pillow), w `requirements-dev.txt` `-r requirements.txt`, pytest, pytest-django. Zainstaluj, przypnij wersje z `pip freeze`. Jeśli któryś pakiet nie ma wheela dla 3.14 — zatrzymaj się i zgłoś.

- [ ] **Step 2: Napisz failing testy**

```python
# tests/analizy/test_logowanie.py
import pytest
from django.urls import reverse

def test_lista_wymaga_logowania(client):
    r = client.get(reverse("analizy:lista"))
    assert r.status_code == 302
    assert r.url.startswith(reverse("login"))

@pytest.mark.django_db
def test_strona_logowania_po_polsku(client):
    r = client.get(reverse("login"))
    assert r.status_code == 200
    assert "Zaloguj" in r.content.decode()

@pytest.mark.django_db
def test_zalogowany_widzi_liste(client, django_user_model):
    u = django_user_model.objects.create_user("anna", password="x" * 12)
    client.force_login(u)
    r = client.get(reverse("analizy:lista"))
    assert r.status_code == 200
    assert "miemli" in r.content.decode()
```

`pytest.ini`: `DJANGO_SETTINGS_MODULE = miemli.settings`, `testpaths = tests`, `pythonpath = .`.

- [ ] **Step 3:** Run `pytest tests/analizy/test_logowanie.py -v` → FAIL (brak projektu).

- [ ] **Step 4: Settings.** Konfiguracja wyłącznie ze zmiennych środowiskowych:
  - `SECRET_KEY` (wymagany),
  - `DEBUG` (domyślnie `False`),
  - `ALLOWED_HOSTS` i `CSRF_TRUSTED_ORIGINS` (listy po przecinku),
  - `DATABASE_URL` przez dj-database-url, domyślnie `sqlite:///db.sqlite3`,
  - `REDIS_URL`,
  - `MIEMLI_IGNOROWANE_DOMENY` (lista po przecinku, trafia do `settings.MIEMLI_IGNOROWANE_DOMENY: frozenset[str]`),
  - `SECURE_COOKIES` (domyślnie `True`) steruje `SESSION_COOKIE_SECURE` i `CSRF_COOKIE_SECURE`.

  Stałe:
  - `SESSION_COOKIE_HTTPONLY=True`, `SECURE_PROXY_SSL_HEADER=("HTTP_X_FORWARDED_PROTO","https")`,
  - `LANGUAGE_CODE="pl"`, `TIME_ZONE="Europe/Warsaw"`,
  - `LOGIN_URL="login"`, `LOGIN_REDIRECT_URL="analizy:lista"`,
  - `FILE_UPLOAD_HANDLERS=["django.core.files.uploadhandler.MemoryFileUploadHandler"]`,
  - `FILE_UPLOAD_MAX_MEMORY_SIZE` i `DATA_UPLOAD_MAX_MEMORY_SIZE` = 50 MB,
  - whitenoise w middleware, `RQ_QUEUES = {"default": {"URL": REDIS_URL}}`.

  Plik `conftest.py` w katalogu głównym repo ustawia `os.environ.setdefault("SECRET_KEY", "test")` i `os.environ.setdefault("SECURE_COOKIES", "0")` przed załadowaniem settings.

- [ ] **Step 5: Widoki i szablony.**
  - `lista` z `@login_required` (na razie pusta tabela „Ostatnie analizy”).
  - `LoginView` z szablonem po polsku (przycisk „Zaloguj”), `LogoutView`.
  - `base.html` z paskiem górnym „miemli” i linkiem „Wyloguj”.
  - `nord.css` z tokenami kolorów z Global Constraints jako zmienne CSS na `:root` i stylami bazowymi (typografia `Inter`/system-ui, mono `JetBrains Mono`/ui-monospace, przyciski `.btn`/`.btn.primary`, odznaki `.b.ok/.warn/.bad`) przeniesionymi z makiety.
  - Pobierz `https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js` do `static/js/`.

- [ ] **Step 6:** Run `pytest -v` → PASS. Run `python manage.py check` → `System check identified no issues`.

- [ ] **Step 7:** Utwórz `NOTES.md` (sekcje „Stan” i „Następna sesja”). Commit: `git add -A && git commit -m "Szkielet Django: logowanie, admin, styl Nord"`.

---

### Task 2: Docker compose (caddy, web, worker, postgres, redis)

**Files:**
- Create: `Dockerfile`, `docker/entrypoint.sh`, `docker-compose.yml`, `Caddyfile`, `.env.example`, `.dockerignore`

**Interfaces:**
- Consumes: settings z Task 1 (zmienne środowiskowe).
- Produces: `docker compose up -d` → `https://localhost/` (cert z wewnętrznego CA Caddy = self-signed z punktu widzenia przeglądarki).

- [ ] **Step 1: Dockerfile.**
  - Obraz bazowy `python:3.14-slim`.
  - `apt-get install --no-install-recommends unar` (narzędzie dla `rarfile`).
  - Użytkownik nie-root, instalacja z `requirements.txt`, `collectstatic` w buildzie.
  - `CMD gunicorn miemli.wsgi -b 0.0.0.0:8000 --workers 3 --timeout 60`.
  - `entrypoint.sh` uruchamia `python manage.py migrate --noinput` tylko gdy `RUN_MIGRATIONS=1`, potem `exec "$@"`.

- [ ] **Step 2: docker-compose.yml.** Usługi:
  - `caddy:2` (porty 80/443, `Caddyfile`, wolumeny `caddy_data`, `caddy_config`),
  - `web` (`RUN_MIGRATIONS=1`, `env_file: .env`),
  - `worker` (ten sam obraz, `command: python manage.py rqworker default`),
  - `postgres:17` (wolumen `pgdata`, healthcheck `pg_isready`),
  - `redis:7`.

  `web` i `worker` z `depends_on` z `condition: service_healthy` dla postgresa. Tylko caddy wystawia porty.

- [ ] **Step 3: Caddyfile.** `{$MIEMLI_HOST:localhost} { tls internal; request_body { max_size 60MB }; reverse_proxy web:8000 }`. Komentarz w pliku, jak podmienić na certyfikat z firmowego CA (`tls /certs/cert.pem /certs/key.pem`).

- [ ] **Step 4:** `.env.example` ze wszystkimi zmiennymi z Task 1 oraz `POSTGRES_PASSWORD`, `MIEMLI_HOST`, z pustymi wartościami. `DATABASE_URL=postgres://miemli:${POSTGRES_PASSWORD}@postgres/miemli` jako przykład.

- [ ] **Step 5: Weryfikacja.** Skopiuj `.env.example` → `.env`, uzupełnij lokalne wartości testowe i uruchom `docker compose up -d --build`. Następnie:
  - `docker compose exec web python manage.py createsuperuser`,
  - `curl -sk -o /dev/null -w '%{http_code}' https://localhost/` → `302`,
  - `docker compose logs worker` zawiera `Listening on default`.

- [ ] **Step 6:** Commit: `git add Dockerfile docker docker-compose.yml Caddyfile .env.example .dockerignore && git commit -m "Docker compose: caddy, web, worker, postgres, redis"`.

---

### Task 3: Model danych mailcore i parser `.eml`

**Files:**
- Create: `mailcore/__init__.py`, `mailcore/model.py`, `mailcore/eml.py`, `mailcore/parsuj.py`, `tests/conftest.py`
- Test: `tests/mailcore/test_eml.py`, `tests/mailcore/test_parsuj.py`

**Interfaces:**
- Produces (`mailcore/model.py`):

```python
@dataclass
class Ostrzezenie:
    kod: str      # KODOWANIE | NAGLOWEK | LIMIT_ROZMIAR | LIMIT_GLEBOKOSC | LIMIT_ROZPAKOWANIE
                  # | ZASZYFROWANE | ARCHIWUM_USZKODZONE | BRAK_NARZEDZIA | MSG_BEZ_NAGLOWKOW
    opis: str     # po polsku, dla człowieka

@dataclass
class Zalacznik:
    nazwa: str
    typ_mime: str
    rozmiar: int
    md5: str; sha1: str; sha256: str
    dane: bytes = field(repr=False)
    content_id: str | None = None
    inline: bool = False
    zaszyfrowany: bool = False
    dzieci: list["Zalacznik"] = field(default_factory=list)      # zawartość archiwum
    wiadomosc: "Wiadomosc | None" = None                          # zagnieżdżony mail

@dataclass
class Wiadomosc:
    id: str                       # "0" = główna, "0.1" = pierwsza zagnieżdżona w niej, itd.
    naglowki: list[tuple[str, str]]   # w kolejności z pliku, wartości zdekodowane
    temat: str | None
    od: str | None                # surowa wartość From
    do: list[str]
    data: datetime | None
    tekst: str | None
    html: str | None
    zalaczniki: list[Zalacznik]
    ostrzezenia: list[Ostrzezenie]
    def naglowek(self, nazwa: str) -> str | None: ...        # pierwsze wystąpienie, bez względu na wielkość liter
    def naglowki_wszystkie(self, nazwa: str) -> list[str]: ...

@dataclass(frozen=True)
class Limity:
    max_rozmiar: int = 50 * 1024 * 1024
    max_glebokosc: int = 5
    max_rozpakowane: int = 200 * 1024 * 1024

class BladParsowania(Exception): ...
class NieobslugiwanyPlik(BladParsowania): ...
class PlikZaDuzy(BladParsowania): ...

def zalacznik_z_danych(nazwa: str, typ_mime: str, dane: bytes, **kw) -> Zalacznik  # liczy hashe
```

- Produces (`mailcore/eml.py`): `parsuj_eml(dane: bytes, id: str) -> Wiadomosc` — jeden poziom; zagnieżdżone `message/rfc822` i załączniki `.eml` zwraca jako `Zalacznik` z surowymi bajtami (rekurencją zajmuje się `parsuj`).
- Produces (`mailcore/parsuj.py`): `parsuj(dane: bytes, nazwa: str, limity: Limity = Limity()) -> Wiadomosc` — rzuca `PlikZaDuzy` (> `max_rozmiar`), `NieobslugiwanyPlik`; wykrywa typ po zawartości (magic OLE `D0 CF 11 E0 A1 B1 1A E1` → msg, w przeciwnym razie eml, jeśli pierwsza niepusta linia ma postać `Nazwa: wartość`); rekurencyjnie parsuje załączniki będące wiadomościami (`typ_mime == "message/rfc822"` lub rozszerzenie `.eml`/`.msg`), ustawiając `zalacznik.wiadomosc` z id `"<rodzic>.<n>"` (n liczone od 1 w obrębie rodzica); powyżej `max_glebokosc` nie schodzi głębiej i dodaje `LIMIT_GLEBOKOSC`. Wywołanie `archiwa` dochodzi w Task 5.
- Produces (`tests/conftest.py`): fixture `zbuduj_mail` — fabryka `(**pola) -> bytes` oparta na `email.message.EmailMessage` (temat, od, do, tekst, html, załączniki `[(nazwa, typ_mime, bajty)]`, dodatkowe nagłówki `[(nazwa, wartość)]`).

- [ ] **Step 1: Failing testy** (`tests/mailcore/test_eml.py`):
  - `test_podstawowe_pola`: mail z tematem „Zaległa płatność”, From `Księgowość <a@x.pl>`, tekstem i HTML → `w.temat == "Zaległa płatność"`, `w.od` zawiera `a@x.pl`, `w.tekst` i `w.html` niepuste, `w.id == "0"`, `w.ostrzezenia == []`.
  - `test_temat_encoded_word`: nagłówek `Subject: =?utf-8?B?WmHFvMOzxYLEhw==?=` → `w.temat == "Zażółć"`.
  - `test_cp1250_bez_charset`: surowe bajty maila `text/plain` bez `charset`, treść `"Zażółć gęślą jaźń".encode("cp1250")` → `"Zażółć gęślą jaźń" in w.tekst` i `[o.kod for o in w.ostrzezenia] == ["KODOWANIE"]`.
  - `test_zepsuty_naglowek`: `Subject: =?utf-8?B?!!!niepoprawne?=` → brak wyjątku, `w.temat` niepusty, `"NAGLOWEK"` w kodach ostrzeżeń.
  - `test_zalacznik_hashe`: załącznik `faktura.pdf` z bajtami `b"%PDF-1.4 test"` → `sha256 == hashlib.sha256(b"%PDF-1.4 test").hexdigest()`, `rozmiar == 13`, `typ_mime == "application/pdf"`.
  - `test_inline_cid`: obraz `image/png` z `Content-ID: <logo1>` i `Content-Disposition: inline` → `content_id == "logo1"`, `inline is True`.
  - `test_mail_bez_tresci`: mail tylko z załącznikiem → `w.tekst is None and w.html is None`.

  `tests/mailcore/test_parsuj.py`:
  - `test_za_duzy`: `parsuj(b"x" * 11, "a.eml", Limity(max_rozmiar=10))` → `PlikZaDuzy`.
  - `test_nie_mail`: `parsuj(b"\x89PNG\r\n\x1a\n...", "a.eml")` → `NieobslugiwanyPlik`.
  - `test_zagniezdzony_eml`: mail zewnętrzny z załącznikiem `message/rfc822` (mail wewnętrzny z tematem „Wewnętrzny”) → `w.zalaczniki[0].wiadomosc.temat == "Wewnętrzny"` i `.id == "0.1"`.
  - `test_limit_glebokosci`: 7 poziomów mail-w-mailu, `Limity(max_glebokosc=5)` → schodząc po `zalaczniki[0].wiadomosc` istnieje dokładnie 5 poziomów zagnieżdżonych (id `"0.1.1.1.1.1"` istnieje, głębszego brak) i ostrzeżenie `LIMIT_GLEBOKOSC` na najgłębszej sparsowanej wiadomości.

- [ ] **Step 2:** Run `pytest tests/mailcore -v` → FAIL.

- [ ] **Step 3: Implementacja.**
  - `email.message_from_bytes(dane, policy=email.policy.default)`. Wyjątki przy dekodowaniu pojedynczego nagłówka łapane: wartość surowa + ostrzeżenie `NAGLOWEK`.
  - Dekodowanie części tekstowych:
    1. zadeklarowany charset,
    2. brak deklaracji: `utf-8`,
    3. potem `windows-1250` + `KODOWANIE`,
    4. na końcu `latin-1` z `errors="replace"` + `KODOWANIE`.
  - Pierwsza część `text/plain` i pierwsza `text/html` niebędące załącznikami stają się `tekst`/`html`.
  - `data` przez `email.utils.parsedate_to_datetime`; błąd → `None` + `NAGLOWEK`.

- [ ] **Step 4:** Run `pytest tests/mailcore -v` → PASS.

- [ ] **Step 5:** Commit `"mailcore: model danych i parser .eml z rekurencją i limitami"`.

---

### Task 4: Parser `.msg`

**Prerequisite:** próbki `.msg`. Dwa źródła:
- **nie-wrażliwa próbka do repo**, np. mail testowy wysłany do siebie z obrazkiem inline i załącznikiem PDF, zapisany w Outlooku jako `.msg`, trafia do `tests/samples/msg/`;
- **próbki prywatne** trafiają do `tests/samples/private/`.

Jeśli w chwili realizacji nie ma żadnej próbki `.msg`, zatrzymaj się i poproś o nią — tego taska nie da się zweryfikować bez prawdziwego pliku z Outlooka.

**Files:**
- Create: `mailcore/msg.py`; Modify: `mailcore/parsuj.py`
- Test: `tests/mailcore/test_msg.py`

**Interfaces:**
- Consumes: `Wiadomosc`, `Zalacznik`, `zalacznik_z_danych`, `Ostrzezenie` z Task 3.
- Produces: `parsuj_msg(dane: bytes, id: str) -> Wiadomosc` — ten sam kontrakt co `parsuj_eml`; osadzone wiadomości `.msg` zwraca jako `Zalacznik` z bajtami i `typ_mime="application/vnd.ms-outlook"` (rekurencję robi `parsuj`).

- [ ] **Step 1: Failing testy** (parametryzowane po wszystkich `tests/samples/msg/*.msg` i `tests/samples/private/*.msg`; `pytest.skip`, gdy brak plików):
  - `test_msg_parsuje_sie`: `parsuj(dane, nazwa)` nie rzuca, `w.temat` niepusty, `w.tekst or w.html`.
  - `test_msg_naglowki_transportowe`: jeśli plik ma nagłówki transportowe (`PR_TRANSPORT_MESSAGE_HEADERS`), `w.naglowek("Received")` nie jest `None`; jeśli nie ma → ostrzeżenie `MSG_BEZ_NAGLOWKOW` i `w.naglowki` zbudowane z właściwości MAPI (From, To, Subject, Date).
  - `test_msg_zalaczniki_maja_hashe`: każdy załącznik ma 64-znakowy `sha256` zgodny z `hashlib.sha256(z.dane)`.
  - Dla próbki w `tests/samples/msg/` dopisz konkretne asercje o jej temacie i nazwach załączników.

- [ ] **Step 2:** Run → FAIL.

- [ ] **Step 3:**
  - Implementacja na `extract_msg` (otwarcie z bajtów; jeśli biblioteka wymaga ścieżki, użyj `io.BytesIO` — **nie** pliku tymczasowego).
  - Nagłówki transportowe parsuj przez `email.parser.HeaderParser`, żeby `naglowek()` działało jak dla eml.
  - `htmlBody` (bajty) dekoduj jak w Task 3.
  - Dla RTF-only bez HTML/tekstu ustaw `tekst` z wersji tekstowej, jeśli `extract_msg` ją daje, w przeciwnym razie `None`.
  - W `parsuj.py` podłącz gałąź OLE.

- [ ] **Step 4:** Run `pytest tests/mailcore/test_msg.py -v` → PASS (bez skipów, gdy jest próbka).

- [ ] **Step 5:** Commit `"mailcore: parser .msg"` (próbki z `private/` nie są dodawane — sprawdź `git status`).

---

### Task 5: Archiwa (zip, 7z, rar), hasła, budżet rozpakowania

**Files:**
- Create: `mailcore/archiwa.py`; Modify: `mailcore/parsuj.py`
- Test: `tests/mailcore/test_archiwa.py`

**Interfaces:**
- Consumes: `Zalacznik`, `zalacznik_z_danych`, `Ostrzezenie`, `Limity`.
- Produces:

```python
class Budzet:                       # współdzielony przez całe parsowanie jednego pliku
    def __init__(self, limit_bajtow: int): ...
    def pobierz(self, n: int) -> bool: ...   # False = przekroczono

def hasla_z_tekstu(tekst: str | None) -> list[str]   # zawsze kończy się "infected"
def jest_archiwum(z: Zalacznik) -> bool              # po magic bytes: zip PK\x03\x04, 7z 37 7A BC AF 27 1C, rar Rar!\x1a\x07
def rozpakuj(z: Zalacznik, hasla: list[str], budzet: Budzet) -> list[Ostrzezenie]
    # wypełnia z.dzieci; ustawia z.zaszyfrowany=True, jeśli żadne hasło nie pasuje
```

- `parsuj` po zbudowaniu wiadomości: dla każdego załącznika (rekurencyjnie w `dzieci`) — archiwum → `rozpakuj` z hasłami z `tekst` + `html` (tekst wyciągnięty z HTML) tej wiadomości; dziecko będące mailem → parsowanie rekurencyjne; dziecko-archiwum → kolejny poziom. Każdy poziom (mail lub archiwum) liczy się do `max_glebokosc`.

- [ ] **Step 1: Failing testy** (archiwa budowane w teście w pamięci: `pyzipper`, `py7zr`; rar — pomiń test, gdy `rarfile.tool_setup()` rzuca, i oznacz go `BRAK_NARZEDZIA`):
  - `test_hasla_z_tekstu`: `"Hasło do pliku: Faktura2026!"` → `["Faktura2026!", "infected"]`; `"password=abc123"` → zawiera `"abc123"`; `None` → `["infected"]`.
  - `test_zip_rozpakowany`: zip z `faktura.exe` (`b"MZ..."`) → `z.dzieci[0].nazwa == "faktura.exe"`, poprawny `sha256`.
  - `test_zip_aes_haslo_z_tresci`: zip AES z hasłem `Faktura2026!`, mail z treścią `Hasło: Faktura2026!` → przez `parsuj` dziecko obecne, `zaszyfrowany is False`.
  - `test_zip_nieznane_haslo`: hasło `xyz` → `zaszyfrowany is True`, `dzieci == []`, ostrzeżenie `ZASZYFROWANE`.
  - `test_7z`: archiwum 7z z jednym plikiem → dziecko obecne.
  - `test_zip_bomba`: zip z plikiem 10 MB zer, `Budzet(1024 * 1024)` → ostrzeżenie `LIMIT_ROZPAKOWANIE`, brak wyjątku (sprawdzaj rozmiar przy czytaniu strumieniowo w kawałkach, nie ufaj `file_size` z nagłówka).
  - `test_zip_uszkodzony`: `b"PK\x03\x04" + b"\x00" * 50` → ostrzeżenie `ARCHIWUM_USZKODZONE`.
  - `test_eml_w_zipie`: zip zawierający `zgloszenie.eml` → `z.dzieci[0].wiadomosc.temat` ustawiony.
  - `test_zip_w_zipie_limit_glebokosci`: 7 zagnieżdżonych zipów → ostrzeżenie `LIMIT_GLEBOKOSC`.

- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3:** Implementacja.
  - Wzorce haseł: `(?:hasło|haslo|password|passwd|pass|pwd|kod)\s*[:=\-–]?\s*(\S+)`, bez rozróżniania wielkości liter, końcowe `.,;` obcięte.
  - Rar przez `rarfile` z `io.BytesIO`.
- [ ] **Step 4:** Run `pytest tests/mailcore -v` → PASS.
- [ ] **Step 5:** Commit `"mailcore: rozpakowywanie archiwów z hasłami i limitami"`.

---

### Task 6: Analiza nagłówków — uwierzytelnienie, Received, podszywanie

**Files:**
- Create: `mailcore/analiza/__init__.py` (puste na razie), `mailcore/analiza/uwierzytelnienie.py`, `mailcore/analiza/received.py`, `mailcore/analiza/podszywanie.py`
- Test: `tests/mailcore/analiza/test_naglowki.py`

**Interfaces:**

```python
@dataclass
class Uwierzytelnienie:
    spf: str | None; dkim: str | None; dmarc: str | None   # małe litery: pass/fail/softfail/neutral/none/temperror/permerror
def sprawdz_uwierzytelnienie(w: Wiadomosc) -> Uwierzytelnienie   # z pierwszego (najwyższego) Authentication-Results

@dataclass
class Hop:
    od: str | None; przez: str | None; ip: str | None; czas: datetime | None
def sciezka_received(w: Wiadomosc) -> list[Hop]                  # najstarszy pierwszy

@dataclass
class Sygnal:
    kod: str; opis: str     # REPLY_TO_INNA_DOMENA | RETURN_PATH_INNA_DOMENA | NAZWA_Z_INNYM_ADRESEM | DARMOWA_POCZTA
DARMOWE_DOMENY: frozenset[str]  # gmail.com, googlemail.com, outlook.com, hotmail.com, live.com, yahoo.com, icloud.com,
                                # proton.me, protonmail.com, wp.pl, o2.pl, onet.pl, op.pl, interia.pl, gazeta.pl, poczta.fm, tlen.pl
def wykryj_podszywanie(w: Wiadomosc) -> list[Sygnal]
```

- [ ] **Step 1: Failing testy:**
  - `test_auth_results`: `Authentication-Results: mx.firma.pl; spf=fail smtp.mailfrom=x.com; dkim=pass header.d=x.com; dmarc=fail` → `Uwierzytelnienie("fail","pass","fail")`.
  - `test_auth_tylko_pierwszy_naglowek`: dwa nagłówki (górny `spf=pass`, dolny `spf=fail`) → `spf == "pass"`.
  - `test_auth_brak`: brak nagłówka → wszystkie pola `None`.
  - `test_received_kolejnosc_i_ip`: dwa `Received` (górny `from mx1 (mx1 [10.0.0.1]) by mx2; Tue, 24 Oct 2026 09:14:00 +0200`, dolny `from evil.com (unknown [185.243.115.20]) by mx1; Tue, 24 Oct 2026 09:13:58 +0200`) → `[h.ip for h in hopy] == ["185.243.115.20", "10.0.0.1"]`, `hopy[0].od == "evil.com"`, `hopy[0].czas` to tz-aware datetime.
  - `test_received_brak_i_smieci`: brak nagłówków → `[]`; `Received: garbage` → jeden `Hop` z polami `None`, bez wyjątku.
  - `test_reply_to_inna_domena`: From `ksiegowosc@pko-platnosci.com`, Reply-To `pko.rozliczenia@gmail.com` → kody zawierają `REPLY_TO_INNA_DOMENA` i `DARMOWA_POCZTA`.
  - `test_nazwa_z_innym_adresem`: From `"bok@pko.pl" <x@evil.com>` → `NAZWA_Z_INNYM_ADRESEM`.
  - `test_czysty_mail_bez_sygnalow`: From/Reply-To/Return-Path w tej samej domenie `firma.pl`, nazwa `Jan Kowalski` → `[]`.
  - Porównanie domen bez względu na wielkość liter; subdomena tej samej domeny (`mail.firma.pl` vs `firma.pl`) nie jest sygnałem.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja (regex na `Received`: `from\s+(\S+)`, `by\s+(\S+)`, IP w `[...]`, data po ostatnim `;`).  **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `"mailcore: analiza SPF/DKIM/DMARC, Received i podszywania"`.

---

### Task 7: Linki (niezgodność tekstu, SafeLinks, Proofpoint) i kody QR

**Files:**
- Create: `mailcore/analiza/linki.py`, `mailcore/analiza/qr.py`
- Test: `tests/mailcore/analiza/test_linki.py`, `tests/mailcore/analiza/test_qr.py`

**Interfaces:**

```python
@dataclass
class Link:
    url: str                    # surowy z maila
    docelowy: str               # po rozpakowaniu przekierowań (== url, gdy brak)
    tekst: str | None           # tekst kotwicy (tylko html)
    niezgodny: bool             # tekst wygląda jak adres/domena, a host docelowy jest inny
    zrodlo: str                 # "html" | "tekst"
def rozpakuj_przekierowanie(url: str) -> str | None
def wyciagnij_linki(w: Wiadomosc) -> list[Link]     # bez duplikatów po (url, tekst); http/https/hxxp tylko
def tekst_z_html(html: str) -> str                  # używane też przez archiwa do haseł
def odczytaj_qr(dane: bytes) -> list[str]           # zxing-cpp + Pillow; nieczytelny obraz → []
```

- [ ] **Step 1: Failing testy:**
  - `test_safelinks`: `https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.com%2Flogin&data=05` → `"https://evil.com/login"`.
  - `test_proofpoint_v2`: `https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.com_login&d=DwMF` → `"https://evil.com/login"`.
  - `test_proofpoint_v3`: `https://urldefense.com/v3/__https://evil.com/login__;!!ABC!xyz$` → `"https://evil.com/login"`.
  - `test_zwykly_url_bez_przekierowania`: `rozpakuj_przekierowanie("https://pko.pl/")` → `None`.
  - `test_niezgodny_tekst`: HTML `<a href="https://evil.com/x">pko.pl</a>` → jeden `Link` z `niezgodny=True`, `tekst == "pko.pl"`.
  - `test_zgodny_tekst`: `<a href="https://www.pko.pl/x">pko.pl</a>` → `niezgodny=False`; `<a href="https://evil.com">Kliknij tutaj</a>` → `niezgodny=False` (tekst nie wygląda jak adres).
  - `test_url_z_tekstu`: tekst `"Wejdź na https://evil.com/fv?id=1."` → `url == "https://evil.com/fv?id=1"` (bez końcowej kropki), `zrodlo == "tekst"`.
  - `test_niezgodnosc_po_rozpakowaniu`: kotwica `pko.pl` z hrefem SafeLinks na evil.com → `niezgodny=True`.
  - `test_qr`: obraz PNG wygenerowany w teście z biblioteki `segno` lub `qrcode` (dodaj do `requirements-dev.txt`) z treścią `https://evil.com/qr` → `odczytaj_qr(png) == ["https://evil.com/qr"]`; `odczytaj_qr(b"nie obraz") == []`.
- [ ] **Step 2:** Run → FAIL.
- [ ] **Step 3: Implementacja.**
  - HTML parsujemy BeautifulSoup z `html.parser`.
  - Proofpoint v3: część między `__` a `__;`. Znaki `*` w tej części są zakodowane w segmencie po `;` i dekodujemy je zgodnie z publicznym algorytmem Proofpoint (`urldecoder` v3).
- [ ] **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `"mailcore: linki z rozpakowaniem przekierowań i odczyt QR"`.

---

### Task 8: Budowa IOC z relacjami, `analizuj()`, rozbrajanie, serializacja

**Files:**
- Create: `mailcore/analiza/ioc.py`, `mailcore/rozbrajanie.py`, `mailcore/serializacja.py`; Modify: `mailcore/analiza/__init__.py`
- Test: `tests/mailcore/analiza/test_ioc.py`, `tests/mailcore/test_rozbrajanie.py`, `tests/mailcore/test_serializacja.py`

**Interfaces:**

```python
@dataclass
class IOC:
    id: int                      # kolejny numer w obrębie analizy, od 1
    typ: str                     # "plik" | "url" | "domena" | "ip" | "email"
    wartosc: str                 # plik: sha256; reszta: znormalizowana (domena/email małymi literami)
    rodzic_id: int | None
    zrodlo: str                  # "naglowek" | "tresc" | "zalacznik" | "qr"
    etykieta: str | None = None  # plik: nazwa; url: tekst kotwicy
    hashe: dict[str, str] | None = None   # plik: {"md5","sha1","sha256"}

@dataclass
class AnalizaWiadomosci:
    uwierzytelnienie: Uwierzytelnienie; received: list[Hop]; sygnaly: list[Sygnal]; linki: list[Link]

@dataclass
class WynikAnalizy:
    wiadomosci: dict[str, AnalizaWiadomosci]   # klucz = Wiadomosc.id
    ioc: list[IOC]

def zbuduj_ioc(w: Wiadomosc, wiadomosci: dict[str, AnalizaWiadomosci], ignorowane_domeny: frozenset[str]) -> list[IOC]
def analizuj(w: Wiadomosc, ignorowane_domeny: frozenset[str] = frozenset()) -> WynikAnalizy
def rozbroj(typ: str, wartosc: str) -> str
def do_json(w: Wiadomosc, wynik: WynikAnalizy) -> dict    # bez Zalacznik.dane; klucz html_bezpieczny dochodzi w Task 9
```

Reguły budowy (decyzje, których nie ma w specyfikacji):
- **Drzewo pochodzenia:**
  - plik → jego dzieci z archiwum (`plik` z rodzicem = archiwum);
  - plik-mail → IOC zagnieżdżonej wiadomości z rodzicem = ten plik;
  - url → `domena` jego hosta (lub `ip`, gdy host to IP) z rodzicem = url;
  - QR z obrazka → `url` z `zrodlo="qr"` i rodzicem = obrazek.
- **Adresy email jako IOC** tylko z `From`, `Reply-To`, `Return-Path`, `Sender`, nigdy z `To`/`Cc` (to ofiary). Domena adresu staje się `domena` z rodzicem = email.
- **IP z `Received`** (`zrodlo="naglowek"`) oraz publiczne IPv4 z treści tekstowej.
- Domen „gołych” z tekstu nie wyciągamy (zbyt wiele fałszywych trafień typu `faktura.pdf`). Domeny pochodzą tylko z URL-i i adresów.
- **Pomijane:**
  - IP prywatne, loopback, link-local i zarezerwowane (`ipaddress.ip_address(x).is_global is False`);
  - domeny z `ignorowane_domeny` razem z subdomenami, a także adresy email i URL-e w tych domenach.
- **Deduplikacja po `(typ, wartosc)`** w całej analizie: pierwsze wystąpienie wyznacza rodzica. Kolejność: wiadomość główna (nagłówki, potem linki, potem załączniki), następnie zagnieżdżone.
- Dla `url` w `wartosc` trafia `Link.docelowy`.
- **`rozbroj`:**
  - `http`→`hxxp`, `https`→`hxxps`, `.` w hoście → `[.]`;
  - email: `@` bez zmian, `.` w domenie → `[.]`;
  - ip: `.` → `[.]`;
  - plik bez zmian.

- [ ] **Step 1: Failing testy:**
  - `test_drzewo_zip_exe`: mail z `faktura.zip` zawierającym `faktura.exe` → IOC `plik` exe ma `rodzic_id` == id IOC zip.
  - `test_url_i_domena`: link `https://evil.com/login` → IOC `url` oraz `domena "evil.com"` z rodzicem = url.
  - `test_email_nadawcy_bez_odbiorcow`: From `a@evil.com`, To `jan@firma.pl` → jest `email "a@evil.com"`, nie ma `jan@firma.pl`.
  - `test_ip_prywatne_pominiete`: Received z `10.0.0.1` i `185.243.115.20` → tylko `185.243.115.20`.
  - `test_ignorowane_domeny`: `ignorowane_domeny={"firma.pl"}`, link `https://intranet.firma.pl/x` → brak IOC dla tego linku.
  - `test_deduplikacja`: dwa linki do tej samej domeny → jedna `domena`.
  - `test_ioc_zagniezdzonego_maila`: link w mailu wewnętrznym → rodzic jego `url` to IOC `plik` z `.eml`.
  - `test_qr_jako_url`: obraz inline z QR `https://evil.com/qr` → `url` z `zrodlo == "qr"`.
  - `test_rozbroj`: `rozbroj("url","https://evil.com/a.b")` → `"hxxps://evil[.]com/a.b"`; `rozbroj("ip","1.2.3.4")` → `"1[.]2[.]3[.]4"`; `rozbroj("email","a@evil.com")` → `"a@evil[.]com"`.
  - `test_do_json_bez_bajtow`: `json.dumps(do_json(w, wynik))` działa, w wyniku brak klucza `dane`, są klucze `wiadomosc` i `analiza` oraz `ioc`.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja.  **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `"mailcore: IOC z relacjami, analizuj(), rozbrajanie, serializacja"`.

---

### Task 9: Bezpieczny HTML podglądu

**Files:**
- Create: `mailcore/html_bezpieczny.py`; Modify: `mailcore/serializacja.py` — każda wiadomość w `do_json` dostaje klucz `html_bezpieczny` (wynik `bezpieczny_html` albo `None`), surowy `html` nie jest zapisywany
- Test: `tests/mailcore/test_html_bezpieczny.py`

**Interfaces:**
- Produces: `bezpieczny_html(html: str, zalaczniki: list[Zalacznik], max_obraz: int = 2 * 1024 * 1024) -> str`
- Kroki:
  1. BeautifulSoup:
     - każde `<a>` zamienia na `<span class="link" title="<rozbrojony docelowy url>">` z zachowanym tekstem;
     - `src="cid:X"` zamienia na `data:<mime>;base64,…` dla załącznika z `content_id == X`, o ile to `image/*` i ≤ `max_obraz`;
     - każde inne `src`, `srcset`, `background` i `<link>` usuwa;
     - `<meta>`, `<base>`, `<form>`, `<iframe>`, `<object>`, `<embed>` usuwa;
     - w atrybutach `style` usuwa deklaracje zawierające `url(`.
  2. `nh3.clean` z allowlistą tagów formatujących tekst i tabel, atrybutami `style`, `title`, `class`, `src` (tylko schemat `data`), `alt`, `width`, `height`, `colspan`, `rowspan`, `align`.

- [ ] **Step 1: Failing testy** — wynik nie zawiera:
  - `<script` (wejście `<script>alert(1)</script>`),
  - `http://track.evil.com` (wejście `<img src="http://track.evil.com/p.gif">`),
  - `javascript:` (wejście `<a href="javascript:alert(1)">x</a>`),
  - `url(` (wejście `<div style="background:url(http://evil.com/a.png);color:red">`), przy czym `color:red` zostaje,
  - `http-equiv` (wejście `<meta http-equiv="refresh" content="0;url=http://evil.com">`),
  - `onerror` (wejście `<img src=x onerror=alert(1)>`).

  Pozytywne:
  - `<a href="https://evil.com/x">pko.pl</a>` → zawiera `pko.pl` oraz `title="hxxps://evil[.]com/x"` i nie zawiera `href`;
  - obraz `cid:logo1` z załącznikiem PNG → zawiera `src="data:image/png;base64,`.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja.  **Step 4:** Run → PASS.
- [ ] **Step 5:** Commit `"mailcore: bezpieczny HTML podglądu"`.

---

### Task 10: Korpus próbek i test regresyjny

**Files:**
- Create: `tests/samples/generuj_probki.py`, `tests/samples/*.eml` + `*.expected.json` (wygenerowane), `tests/mailcore/test_korpus.py`, `tests/samples/README.md`

**Interfaces:**
- Consumes: `parsuj`, `analizuj`.
- Format `<próbka>.expected.json`:
  ```json
  {"ioc": [["typ", "wartosc"], ...],
   "uwierzytelnienie": {"spf": "...", "dkim": "...", "dmarc": "..."},
   "sygnaly": ["KOD", ...],
   "ostrzezenia": ["KOD", ...]}
  ```
  - `ioc` porównywane jako zbiór z dokładną równością (wykrywa szum);
  - `uwierzytelnienie` i `sygnaly` dotyczą wiadomości `"0"`;
  - `ostrzezenia` to kody ze wszystkich poziomów (zbiór);
  - brak klucza = nie sprawdzaj.

- [ ] **Step 1:** `generuj_probki.py` zapisuje 8 syntetycznych `.eml` (zmyślone domeny: `pko-platnosci.com`, `evil.example`):
  - `phishing_klasyczny` (SPF/DMARC fail, Reply-To gmail, link z niezgodnym tekstem),
  - `zip_exe`,
  - `zip_aes_haslo_w_tresci`,
  - `mail_w_mailu`,
  - `safelinks`,
  - `qr_inline`,
  - `cp1250_bez_charset`,
  - `tylko_zalacznik_bez_naglowkow_auth`.

  Plików oczekiwanych **nie generuj automatycznie z wyniku analizy**: wpisz je ręcznie wg tego, co próbka zawiera (inaczej test niczego nie sprawdza).
- [ ] **Step 2:** `test_korpus.py` parametryzowany po `tests/samples/**/*.eml|*.msg` (także `private/`), pomija pliki bez `.expected.json`. Run → PASS dla wszystkich; każda rozbieżność to błąd w kodzie albo w oczekiwaniu — wyjaśnij, nie dopasowuj na ślepo.
- [ ] **Step 3:** `tests/samples/README.md`: jak dodać próbkę (plik + `.expected.json`), że prywatne idą do `private/` (gitignore).
- [ ] **Step 4:** Commit `"Korpus syntetycznych próbek i test regresyjny"`.

---

### Task 11: Modele Django, usługa tworzenia analizy, upload i lista

**Files:**
- Create: `analizy/models.py`, `analizy/migrations/0001_initial.py` (makemigrations), `analizy/uslugi.py`, `analizy/forms.py`, `analizy/admin.py`, `templates/analizy/lista.html` (rozbudowa); Modify: `analizy/views.py`, `analizy/urls.py`
- Test: `tests/analizy/test_uslugi.py`, `tests/analizy/test_upload.py`

**Interfaces:**
- Consumes: `parsuj`, `analizuj`, `do_json`, `BladParsowania`, `NieobslugiwanyPlik`, `PlikZaDuzy`, `settings.MIEMLI_IGNOROWANE_DOMENY`.
- Produces:

```python
class Analiza(models.Model):
    ticket_id = models.IntegerField(null=True, blank=True)
    attachment_id = models.IntegerField(null=True, blank=True)
    sha256 = models.CharField(max_length=64, db_index=True)
    nazwa_pliku = models.CharField(max_length=255)
    wynik = models.JSONField()                       # do_json()
    werdykt = models.CharField(max_length=20, blank=True, choices=[("phishing","Phishing"),("spam","Spam"),("czysty","Czysty"),("do_weryfikacji","Do weryfikacji")])
    notatka = models.TextField(blank=True)
    utworzyl = models.ForeignKey(User, on_delete=models.PROTECT)
    utworzono = models.DateTimeField(auto_now_add=True)

class IOC(models.Model):
    analiza = models.ForeignKey(Analiza, on_delete=models.CASCADE, related_name="ioc")
    numer = models.IntegerField()                    # mailcore IOC.id
    typ, wartosc (TextField), etykieta (null), zrodlo, hashe (JSONField null)
    rodzic = models.ForeignKey("self", null=True, on_delete=models.CASCADE, related_name="dzieci")
    class Meta: unique_together = [("analiza", "typ", "wartosc")]; ordering = ["numer"]

class Zdarzenie(models.Model):
    uzytkownik = FK(User, PROTECT); analiza = FK(Analiza, null=True, CASCADE)
    typ = CharField(max_length=30)                   # na razie: "utworzenie", "otwarcie"
    szczegoly = JSONField(default=dict); czas = DateTimeField(auto_now_add=True)

def utworz_lub_otworz(dane: bytes, nazwa: str, uzytkownik, ticket_id: int | None = None,
                      attachment_id: int | None = None) -> tuple[Analiza, bool]   # (analiza, utworzona)
```

- `utworz_lub_otworz`:
  - deduplikacja wg `(ticket_id, sha256)`, gdzie `ticket_id=None` dla ręcznego uploadu też jest kluczem;
  - przy tworzeniu: `parsuj` → `analizuj(ignorowane_domeny=settings.MIEMLI_IGNOROWANE_DOMENY)` → zapis `Analiza` + `IOC` (rodzice mapowani przez `numer`) + `Zdarzenie("utworzenie")` w jednej transakcji;
  - wyjątki `BladParsowania` przepuszcza wyżej.
- Widoki:
  - `lista`: 50 ostatnich analiz (data, plik, ticket, kto) i formularz uploadu;
  - `POST /analiza/upload/` (`analizy:upload`): sukces → redirect do `analizy:szczegoly` (`/analiza/<id>/`, widok z Task 12, tu wystarczy stub);
  - błędy → ponowne wyświetlenie listy z komunikatem:
    - `NieobslugiwanyPlik` → „Plik nie jest prawidłową wiadomością .eml ani .msg.”,
    - `PlikZaDuzy` → „Plik jest większy niż 50 MB.”,
    - inny wyjątek → „Nie udało się przeanalizować pliku.” (wyjątek do logu przez `logger.exception` bez treści pliku).
- Admin: rejestracja `Analiza` (tylko odczyt) i `Zdarzenie`.

- [ ] **Step 1: Failing testy:**
  - `test_tworzy_analize_i_ioc`: próbka `zip_exe.eml` z korpusu → `utworzona is True`, `analiza.ioc.count() > 0`, IOC exe ma `rodzic` = IOC zip, istnieje `Zdarzenie(typ="utworzenie")`.
  - `test_deduplikacja_ten_sam_ticket`: dwa wywołania z `ticket_id=1` i tymi samymi bajtami → ten sam `pk`, drugi raz `utworzona is False`.
  - `test_inny_ticket_nowa_analiza`: `ticket_id=1` potem `ticket_id=2` → różne `pk`.
  - `test_upload_wymaga_logowania`: `POST` bez sesji → 302 na logowanie.
  - `test_upload_ok`: zalogowany `POST` z próbką → 302 na `/analiza/<pk>/`.
  - `test_upload_nie_mail`: plik PNG → 200 i komunikat „Plik nie jest prawidłową wiadomością”.
  - `test_brak_oryginalu_w_bazie`: po uploadzie `Analiza.objects.get().wynik` w postaci `json.dumps` nie zawiera base64 treści załącznika `.exe` (szukaj fragmentu `base64.b64encode(dane_exe)[:40]`).
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja + `makemigrations analizy`.  **Step 4:** Run `pytest -v` → PASS.
- [ ] **Step 5:** Commit `"Modele analizy, deduplikacja, upload i lista analiz"`.

---

### Task 12: Ekran analizy (układ C), sekcje htmx, podgląd w iframe

**Files:**
- Create: `templates/analizy/szczegoly.html`, `templates/analizy/sekcje/{wiadomosc,naglowki,received,zalaczniki,linki,ioc}.html`, `templates/analizy/_panel_ioc.html`, `analizy/templatetags/miemli.py`; Modify: `analizy/views.py`, `analizy/urls.py`, `static/css/nord.css`
- Test: `tests/analizy/test_szczegoly.py`

**Interfaces:**
- Consumes: `Analiza`, `IOC`, `Zdarzenie`, `rozbroj`, struktura `Analiza.wynik` z `do_json`.
- Produces:
  - `analizy:szczegoly` `/analiza/<pk>/?sekcja=<s>&wiadomosc=<id>`, gdzie `s` ∈ `wiadomosc` (domyślna), `naglowki`, `received`, `zalaczniki`, `linki`, `ioc`, a `wiadomosc` domyślnie `"0"`. Dla `HX-Request` zwraca tylko fragment sekcji, w przeciwnym razie całą stronę. Nieznana sekcja lub nieistniejące id wiadomości → 404.
  - `analizy:podglad` `/analiza/<pk>/podglad/<wiadomosc_id>/` zwraca zapisany bezpieczny HTML z nagłówkiem CSP z Global Constraints oraz `X-Frame-Options: SAMEORIGIN` (`@xframe_options_sameorigin`).
  - Filtr szablonu `{{ ioc|rozbrojony }}`.
- Układ według makiety, wariant C:
  - **Pasek górny:** nazwa pliku i ticket, jeśli jest.
  - **Nawigacja z licznikami:** nagłówki, hopy, załączniki, linki, IOC. Klik → `hx-get` z `hx-target` na środek i `hx-push-url`.
  - **Przełącznik wiadomości:** gdy są zagnieżdżone, lista „Wiadomość główna / zagnieżdżona 0.1 …”.
  - **Sekcja Wiadomość:**
    - temat, Od, Reply-To, Do, data;
    - odznaki SPF/DKIM/DMARC (`pass` → `.ok`, `fail`/`softfail` → `.bad`, inne → `.warn`, brak → „brak danych”);
    - sygnały podszywania jako odznaki `.warn`;
    - ostrzeżenia parsowania;
    - `<iframe sandbox src="…/podglad/…">`, albo tekst w `<pre>`, gdy nie ma HTML, albo „Wiadomość nie ma treści”.
  - **Nagłówki:** tabela nazwa/wartość.
  - **Received:** tabela (lp., od, przez, IP rozbrojone, czas, opóźnienie względem poprzedniego hopa w sekundach) albo „Brak nagłówków Received”.
  - **Załączniki:** drzewo (nazwa, typ, rozmiar, SHA256, znacznik „zaszyfrowane”, link do zagnieżdżonej wiadomości).
  - **Linki:** tabela (tekst, URL docelowy rozbrojony, oryginalny jeśli różny, odznaka „niezgodny tekst”).
  - **IOC:** pełna tabela z wariantu B — typ, wartość rozbrojona z wcięciem wg drzewa (`└`), etykieta, źródło. Kolumny GTI/Censys/Joe w tym planie nie istnieją.
  - **Prawy panel:** skrót IOC (typ + wartość rozbrojona); klik → sekcja IOC.
- Pierwsze wejście danego użytkownika w danej sesji na analizę zapisuje `Zdarzenie("otwarcie")`. Deduplikacja przez klucz w `request.session`.

- [ ] **Step 1: Failing testy** (na analizach z próbek korpusu, przez `utworz_lub_otworz`):
  - `test_szczegoly_pelna_strona`: 200, zawiera temat próbki `phishing_klasyczny`, `SPF`, `sandbox`, nie zawiera `allow-scripts`.
  - `test_sekcja_htmx_fragment`: `?sekcja=ioc` z nagłówkiem `HX-Request: true` → nie zawiera `<html`, zawiera `pko-platnosci[.]com`.
  - `test_ioc_rozbrojone`: pełna strona `?sekcja=ioc` nie zawiera `https://` dla URL-i IOC i zawiera `hxxps://`.
  - `test_podglad_csp`: odpowiedź `podglad` ma `Content-Security-Policy` == wartość z Global Constraints i `X-Frame-Options == "SAMEORIGIN"`.
  - `test_podglad_bez_skryptow`: analiza z maila z `<script>alert(1)</script>` → treść podglądu bez `<script`.
  - `test_mail_bez_tresci_i_naglowkow`: próbka `tylko_zalacznik_bez_naglowkow_auth`, sekcje `wiadomosc` i `received` → 200, zawierają „brak danych” / „Brak nagłówków Received”.
  - `test_zagniezdzona_wiadomosc`: próbka `mail_w_mailu`, `?wiadomosc=0.1` → temat wewnętrznego maila; `?wiadomosc=9.9` → 404.
  - `test_nieznana_sekcja_404`: `?sekcja=xyz` → 404.
  - `test_cudza_sesja_wymaga_logowania`: bez logowania → 302.
  - `test_zdarzenie_otwarcia_raz_na_sesje`: dwa GET-y → jedno `Zdarzenie(typ="otwarcie")`.
- [ ] **Step 2:** Run → FAIL.  **Step 3:** Implementacja.  **Step 4:** Run `pytest -v` → PASS.
- [ ] **Step 5: Weryfikacja wizualna.**
  - Uruchom `python manage.py runserver` z `DEBUG=1 SECURE_COOKIES=0`.
  - Wgraj `phishing_klasyczny.eml` i `mail_w_mailu.eml`.
  - Porównaj z `docs/superpowers/mockups/02-uklad.html`.
  - Sprawdź w DevTools, że karta podglądu nie wykonuje żadnych żądań sieciowych.
- [ ] **Step 6:** Commit `"Ekran analizy: układ C, sekcje htmx, bezpieczny podgląd"`.

---

### Task 13: Weryfikacja end-to-end w Dockerze i notatki

**Files:**
- Modify: `README.md`, `NOTES.md`

- [ ] **Step 1:** `docker compose up -d --build`. W przeglądarce pod `https://localhost/` przejdź całą ścieżkę: zaloguj się, wgraj próbki z korpusu, a jeśli są, także prywatne `.msg`/`.eml`; przejrzyj wszystkie sekcje. `docker compose logs web` nie zawiera tracebacków ani treści maili.
- [ ] **Step 2:** Run `pytest -v` w venv → wszystkie PASS. Zapisz liczbę testów i ewentualne skipy (np. rar bez narzędzia).
- [ ] **Step 3:** `README.md`: krótki opis, uruchomienie dev (venv, `runserver`), uruchomienie w Dockerze (`.env` z `.env.example`, `createsuperuser`), podmiana certyfikatu na firmowe CA. `NOTES.md`: stan po etapach 1–3, znane ograniczenia, następna sesja = plan etapów 4–5 (GTI, Censys, Joe).
- [ ] **Step 4:** Commit `"README i NOTES po etapach 1–3"`, potem `git push`.
