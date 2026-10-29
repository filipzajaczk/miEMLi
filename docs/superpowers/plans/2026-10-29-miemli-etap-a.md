# miemli — Etap A — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Werdykt analityka (ekran + lista z filtrem), zmiana hasła, audyt tylko dla admina, „IOC” → „Artefakty” w interfejsie, podgląd HTML z przyciskami i ramkami obrazów zewnętrznych (osobny commit), pakiet poprawek z przeglądów.

**Architecture:** Zmiany w istniejącej aplikacji Django `analizy` (widoki, szablony, htmx), w `mailcore` (podgląd HTML, artefakty IPv6), `integracje` (InvalidURL, limit czasu Joe), `piaskownica` (OOM) i kliencie sandboxa (walidacja drzewa). Bez nowych usług.

**Tech Stack:** Django 6.1, htmx 2.0.4, pytest, Playwright (weryfikacja ręczna).

**Spec:** `docs/superpowers/specs/2026-10-29-miemli-etap-a-interfejs-konto-design.md`

## Global Constraints

- Teksty interfejsu po polsku, dokładnie jak w specyfikacji (opisy typów audytu §3, komunikaty §2).
- CSP bez inline: żadnych `on*=`, `style="…"` ani `<script>` inline w stronach aplikacji (podgląd maila ma własną CSP).
- Każdy POST z CSRF; widoki z `@login_required`; audyt dodatkowo `is_staff`.
- Zmiana nazwy „IOC” → „Artefakty” tylko w interfejsie — modele, URL-e, nazwy w kodzie bez zmian.
- Podgląd HTML (Task 6) w **osobnym commicie** niezawierającym innych zmian.
- Commity kończą się `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Zwykły analityk zgaduje adres `/audyt/` lub filtruje go parametrami** → 403, brak danych w odpowiedzi. Test: Task 3.
2. **Zmiana hasła z błędnym obecnym hasłem / niezgodnym powtórzeniem / krótkim hasłem** → komunikat, hasło bez zmian, brak zdarzenia. Test: Task 2.
3. **POST werdyktu z wartością spoza listy** (np. `"<script>"`) → 400, werdykt bez zmian. Test: Task 1.
4. **Lista analiz z bardzo dużym `wynik`** → lista nie odczytuje pola `wynik` (test liczy zapytania/pola). Test: Task 5.
5. **Obraz zewnętrzny z adresem zawierającym dane ofiary w ścieżce/parametrach** → w ramce wyłącznie host. Test: Task 6.

---

### Task 1: Werdykt analityka

**Files:** Create `templates/analizy/_werdykt.html`, `tests/analizy/test_werdykt.py`; Modify `analizy/views.py`, `analizy/urls.py`, `templates/analizy/szczegoly.html`, `templates/analizy/lista.html`, `analizy/templatetags/miemli.py`, `static/css/nord.css`

**Interfaces:**
- `analizy:werdykt` `POST /analiza/<pk>/werdykt/` (pole `werdykt` ∈ `""` ∪ kody `Analiza.WERDYKTY`) → fragment `_werdykt.html` (200); wartość spoza listy → 400. Zdarzenie tylko przy faktycznej zmianie.
- `_werdykt.html`: `<form hx-post=… hx-trigger="change" hx-swap="outerHTML">` z `<select name="werdykt">` (bez JS inline).
- Filtry szablonu: `klasa_werdyktu_analityka(kod) -> str` (`phishing`→`bad`, `spam`→`warn`, `czysty`→`ok`, `do_weryfikacji`→`neutral`), `opis_werdyktu_analityka(kod) -> str` (etykiety z `WERDYKTY`, pusty → „—”).
- Lista: `?werdykt=brak|phishing|spam|czysty|do_weryfikacji`; linki filtrów nad tabelą, aktywny oznaczony klasą `on`.

- [ ] **Step 1: Failing testy:** `test_ustawienie_werdyktu` (POST `phishing` → 200, `analiza.werdykt == "phishing"`, zdarzenie `werdykt` z `{"z": "", "na": "phishing"}`); `test_ten_sam_werdykt_bez_zdarzenia`; `test_zly_werdykt_400` *(Review Focus 3)*; `test_werdykt_wymaga_logowania` (302) i `test_get_405`; `test_przelacznik_na_ekranie` (strona analizy zawiera `hx-trigger="change"` i aktualną wartość `selected`); `test_kolumna_na_liscie` (odznaka `class="b bad"` „Phishing”); `test_filtr_listy` (`?werdykt=phishing` pokazuje tylko analizy z phishingiem, `?werdykt=brak` tylko bez werdyktu, `?werdykt=xyz` wszystkie).
- [ ] **Step 2:** Run → FAIL. **Step 3:** Implementacja. **Step 4:** Run `.venv/bin/pytest -q` → PASS.
- [ ] **Step 5:** Commit `"Werdykt analityka: przełącznik na ekranie analizy, kolumna i filtr na liście"`.

---

### Task 2: Zmiana hasła

**Files:** Modify `analizy/profil.py`, `templates/analizy/profil.html`, `miemli/urls.py`; Test `tests/analizy/test_haslo.py`

**Interfaces:**
- `haslo` `POST /profil/haslo/` — `PasswordChangeForm`; sukces → 302 na `profil`, flaga w sesji `haslo_zmienione` pokazana raz jako „Hasło zostało zmienione.”; błędy → strona profilu (200) z błędami formularza. Dekoratory `sensitive_post_parameters("old_password", "new_password1", "new_password2")`, `login_required`, `require_POST`.

- [ ] **Step 1: Failing testy:** `test_zmiana_hasla` (stare działa przed, nowe po; komunikat; `Zdarzenie(typ="haslo_zmienione")` bez haseł w `szczegoly`); `test_inne_sesje_wylogowane` (drugi klient zalogowany tym samym kontem po zmianie → 302 na logowanie; bieżący klient nadal zalogowany); błędne dane *(Review Focus 2)* — złe obecne hasło, niezgodne powtórzenie, `"krotkie123"` → 200, hasło niezmienione, brak zdarzenia; `test_haslo_wymaga_logowania`; `test_parametry_wrazliwe` (RequestFactory: `request.sensitive_post_parameters` zawiera trzy pola).
- [ ] **Step 2–4:** FAIL → implementacja → PASS (`.venv/bin/pytest -q`).
- [ ] **Step 5:** Commit `"Zmiana hasła w profilu"`.

---

### Task 3: Audyt tylko dla administratora

**Files:** Create `analizy/audyt.py`, `templates/analizy/audyt.html`, `tests/analizy/test_audyt.py`; Modify `miemli/urls.py`, `templates/base.html`

**Interfaces:**
- `audyt` `GET /audyt/` — `login_required`; `not is_staff` → `HttpResponseForbidden` + `logger.warning("Odmowa dostępu do audytu: %s", username)`.
- Filtry GET: `uzytkownik` (id), `typ`, `od`, `do` (`YYYY-MM-DD`, włącznie; błędny format ignorowany). `Paginator` 50, `?strona=`.
- `OPISY_ZDARZEN: dict[str, str]` w `analizy/audyt.py` — dokładnie wg spec §3.
- Link „Audyt” w pasku tylko dla `is_staff`.

- [ ] **Step 1: Failing testy:** `test_audyt_dla_admina` (200, widać „Zmiana werdyktu”, nazwę użytkownika, link do analizy); `test_audyt_zwykly_uzytkownik_403` *(Review Focus 1)* (także z parametrami filtrów; odpowiedź nie zawiera nazw innych użytkowników; `caplog` WARNING); `test_audyt_wymaga_logowania`; `test_filtry` (typ, użytkownik, zakres dat); `test_paginacja` (60 zdarzeń → 50 na stronie 1, 10 na 2); `test_link_tylko_dla_admina`; `test_usunieta_analiza` (zdarzenie `usuniecie` bez linku, ze szczegółami pliku).
- [ ] **Step 2–4:** FAIL → implementacja → PASS.
- [ ] **Step 5:** Commit `"Audyt w aplikacji — tylko dla administratora"`.

---

### Task 4: „IOC” → „Artefakty” w interfejsie

**Files:** Modify `analizy/prezentacja.py` (`SEKCJE`), `templates/analizy/sekcje/ioc.html`, `templates/analizy/_panel_ioc.html`, `templates/analizy/szczegoly.html`, `analizy/models.py` (`verbose_name` — bez migracji pól; jeśli Django wygeneruje migrację opcji Meta, dodać ją), testy z oczekiwanym tekstem

- [ ] **Step 1: Failing test** `test_nazwa_artefakty`: menu sekcji zawiera „Artefakty”, nagłówek sekcji „Artefakty”, panel „Artefakty · N”, pusta lista „Nie znaleziono artefaktów.”; strony aplikacji (lista, analiza, sekcja `ioc`) nie zawierają słowa „IOC” w widocznym tekście (sprawdź tekst po usunięciu tagów).
- [ ] **Step 2–4:** FAIL → implementacja → PASS.
- [ ] **Step 5:** Commit `"Interfejs: „IOC” → „Artefakty”"`.

---

### Task 5: Poprawki z przeglądów

**Files:** Modify `analizy/models.py` (+ migracja schematu i migracja danych), `analizy/uslugi.py`, `analizy/views.py` (lista), `templates/analizy/lista.html`, `static/js/miemli.js`, `analizy/templatetags/miemli.py`, `templates/analizy/_szczegoly_ioc.html`, `mailcore/analiza/ioc.py`, `integracje/wspolne.py`, `integracje/joe.py`, `analizy/joe_zadania.py`, `piaskownica/serwer.py`, `analizy/piaskownica_klient.py`, `tests/integracje/test_nagrania.py`; testy w istniejących plikach testów odpowiednich modułów

**Interfaces / decyzje:**
- `Analiza.temat_wiadomosci = CharField(max_length=500, blank=True, default="")`; migracja danych wypełnia z `wynik["wiadomosc"]["temat"]` (obcięte do 500); `utworz_lub_otworz` ustawia przy tworzeniu; lista: `.defer("wynik")`, szablon używa `temat_wiadomosci`.
- `miemli.js`: zbiór otwartych wierszy (`data-cel`) aktualizowany przez obsługę kliknięcia; po zdarzeniu htmx `htmx:oobAfterSwap` dla `#tabela-ioc-cialo` ponowne rozwinięcie (`htmx.ajax` + klasa `otwarty`) wierszy ze zbioru.
- `wiek`/`nowa_domena`: `dni < 0` → `""` / `False`.
- Filtr `rozbroj_tekst(s)`: `http`→`hxxp` (bez względu na wielkość liter), wzorzec `\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b` (i) → kropki na `[.]`; użyty dla `nazwy` i `tagi` w szczegółach GTI.
- `mailcore/analiza/ioc.py`: host URL będący adresem IP (v4 lub v6) niepublicznym → brak artefaktu.
- `integracje/wspolne.wykonaj` i `integracje/joe._wykonaj`: `httpx.InvalidURL`/`httpx.UnsupportedProtocol`/`ValueError` przy budowie żądania → `blad` „Nieprawidłowy adres.”, `ponawiac=False`.
- Joe: łączny limit czasu odczytu (`CZAS_CALKOWITY_WYSYLKI = 120`, `CZAS_CALKOWITY = 40` s) sprawdzany w pętli odczytu → `niedostepny` „Joe niedostępny.”, `ponawiac=True`; `odrzucony` z komunikatem klucza w `_wyslij`/`_sprawdz` → `ProfilAnalityka.joe_klucz_stan="odrzucony"`.
- `piaskownica/serwer.py`: `kod == -SIGKILL` bez przekroczenia czasu i bez przepełnienia wyjścia → `pamiec`; `-SIGXCPU` → `czas`.
- `piaskownica_klient.waliduj_wynik`: rekurencyjna walidacja `wiadomosc` (id str; naglowki lista par str; temat/od/tekst/html_bezpieczny str|None; do lista str; zalaczniki lista dict z `nazwa` str, `sha256` 64 hex, `rozmiar` int, `dzieci` lista, `wiadomosc` dict|None; `obrazki` lista dict; głębokość ≤ 10) oraz `analiza` (dict: klucz str → dict z listami `received`, `sygnaly`, `linki`).
- `test_nagrania._klucze`: wartości bez otaczających `"`/`'`.

- [ ] **Step 1: Failing testy** — po jednym na punkt §6 specyfikacji: `test_lista_bez_pola_wynik` *(Review Focus 4: `django_assert_max_num_queries` + `CaptureQueriesContext`, w SQL listy brak kolumny `wynik`)*, `test_migracja_tematu` (analiza utworzona przed migracją — przez funkcję migracji wywołaną bezpośrednio), `test_wiek_przyszlosc`, `test_rozbroj_tekst` i `test_szczegoly_gti_rozbrojone`, `test_url_ipv6_prywatny`, `test_invalid_url_gti_i_censys`, `test_joe_odrzucony_klucz_zmienia_stan`, `test_joe_limit_calkowity` (strumień kapiący bajtami z podmienionym zegarem), `test_sigkill_to_pamiec`, `test_walidacja_drzewa` (parametryzacja zepsutych pól i głębokości 11), `test_nagrania_cudzyslowy`. Punkt „otwarte wiersze” — weryfikacja w przeglądarce (Task 7).
- [ ] **Step 2–4:** FAIL → implementacja → PASS (`.venv/bin/pytest -q`).
- [ ] **Step 5:** Commit `"Poprawki z przeglądów: lista bez pola wynik, wiek domeny, rozbrajanie danych GTI, IPv6, błędne adresy, limity Joe, OOM parsera, walidacja drzewa"`.

---

### Task 6: Podgląd HTML — przyciski i obrazy zewnętrzne (OSOBNY COMMIT)

**Files:** Modify `mailcore/html_bezpieczny.py`, `analizy/views.py` (`SZABLON_PODGLADU`: styl `.obraz-zewnetrzny`); Test `tests/mailcore/test_html_bezpieczny.py`

**Interfaces:** `bezpieczny_html` — `<a>` → `<span class="link" style="…">` (styl oryginału, filtrowany przez nh3), `<img src="http(s)://host/…">` → `<span class="obraz-zewnetrzny">[obraz zewnętrzny: <rozbroj("domena", host)>]</span>`.

- [ ] **Step 1: Failing testy:** `test_przycisk_zachowuje_styl` (`<a href="https://evil.example/p" style="background-color:#d40511;color:#fff;padding:14px">Zapłać</a>` → `background-color` i `padding` w wyniku, brak `href`); `test_styl_przycisku_bez_url` (`style="background:url(http://x)"` → brak `url(`); `test_obraz_zewnetrzny` (`<img src="https://dhl-paczka.example/logo.png?u=jan.kowalski">` → `[obraz zewnętrzny: dhl-paczka[.]example]`, brak `logo.png` i `jan.kowalski`) *(Review Focus 5)*; `test_obraz_cid_bez_zmian`.
- [ ] **Step 2–4:** FAIL → implementacja → PASS.
- [ ] **Step 5:** Commit wyłącznie tych plików: `"Podgląd HTML: wygląd przycisków i ramki obrazów zewnętrznych"` (do wycofania przez `git revert <hash>`).

---

### Task 7: Weryfikacja w przeglądarce, dokumentacja

**Files:** Modify `README.md`, `NOTES.md`

- [ ] **Step 1:** Docker `up -d --build`; Playwright (lokalny `runserver` z `PIASKOWNICA_URL=` i `DEBUG=1`, jeśli certyfikat HTTPS blokuje przeglądarkę): werdykt zmieniany na ekranie i widoczny na liście z filtrem; zmiana hasła i wylogowanie drugiej sesji; `/audyt/` z konta admina i zwykłego; podgląd `dhl.eml` (przycisk, ramka obrazu); otwarty wiersz szczegółów nie zwija się podczas odpytywania.
- [ ] **Step 2:** README (werdykt, audyt dla admina, zmiana hasła), NOTES (stan, etap B i C). Usuń dane testowe. Commit `"Etap A: dokumentacja"`.
