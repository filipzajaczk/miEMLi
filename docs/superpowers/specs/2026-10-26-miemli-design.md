# miemli — specyfikacja projektu

Data: 2026-10-26
Status: do przeglądu

## 1. Cel

Wewnętrzne narzędzie webowe dla zespołu CSIRT (~7 osób) do analizy podejrzanych wiadomości
`.eml` / `.msg` dołączanych do incydentów w RTIR. Analityk klika link przy załączniku w tickecie
RTIR, miemli pobiera plik, wyświetla wiadomość w czytelnej formie, wyciąga IOC z relacjami
„skąd pochodzi”, wzbogaca je danymi z GTI, Censys i Joe Sandbox, a na koniec wysyła raport
z powrotem do ticketu.

**Kryteria sukcesu**

- Od kliknięcia w RTIR do czytelnej wiadomości z listą IOC: kilka sekund.
- Analityk nie musi ręcznie kopiować hashy/URL-i do GTI, Censys ani Joe.
- Osoba patrząca na ticket widzi podsumowanie analizy w komentarzu i IOC w polach RTIR,
  bez ponownego przechodzenia analizy.

## 2. Zakres

**W zakresie**

- Analizowane są wyłącznie załączniki `.eml` / `.msg` z ticketu RTIR. Sam mail zgłoszeniowy
  (który wpłynął na skrzynkę) nie jest analizowany.
- Zagnieżdżone wiadomości (`.eml`/`.msg` w analizowanym pliku) są rozpakowywane rekurencyjnie.
- Analiza:
  - nagłówki uwierzytelnienia: SPF, DKIM, DMARC z `Authentication-Results`,
  - ścieżka `Received` (serwery, IP, czasy) w tabeli,
  - wykrywanie podszywania: niezgodność `From` / `Reply-To` / `Return-Path`, nazwa wyświetlana
    niezgodna z adresem,
  - URL-e z treści, w tym niezgodność tekstu linku z `href` oraz rozpakowanie przekierowań
    (Microsoft SafeLinks, Proofpoint URL Defense),
  - załączniki: MD5/SHA1/SHA256, rozpakowywanie archiwów (zip, 7z, rar, w tym na hasło),
  - domeny i IP z treści i nagłówków,
  - kody QR w obrazkach.
- Widok relacji IOC w obrębie jednej wiadomości (drzewo pochodzenia).
- Automatyczne lookupy: GTI, Censys, Joe (wyszukiwanie po hashu).
- Ręczne akcje: wysyłka pliku/URL-a do Joe Sandbox (Live Interaction), odświeżenie wzbogacenia.
- Raport do RTIR: Comment + Custom Fields IOC.
- Lokalne konta użytkowników, audyt akcji.
- Interfejs i raport wyłącznie po polsku.

**Poza zakresem (świadomie)**

- Eksport IOC do CSV/schowka.
- Korelacja między incydentami — robi to RTIR na polach IOC.
- Graf wizualny w stylu Maltego.
- Automatyczny werdykt / scoring — werdykt ustala analityk ręcznie.
- Wysyłka plików do GTI (brak licencji Private Scanning). Moduł GTI ma umożliwić dodanie
  „wyślij prywatnie” po dokupieniu licencji bez przebudowy.
- LDAP/AD/SSO.
- Automatyczne odświeżanie wzbogacenia.

## 3. Środowisko i ograniczenia

- Serwer w sieci firmowej, dostęp analityków przez VPN. miemli i RTIR widzą się w sieci.
- RTIR 6.0.3 — wbudowane REST2 API z tokenami.
- Joe Sandbox Cloud Pro z Live Interaction; każdy analityk ma własne konto Joe.
- GTI (Google Threat Intelligence) — bez Private Scanning.
- Censys — płatne API.
- Monitory: szerokie oraz 27″. Interfejs nie jest optymalizowany pod laptopy/mobile.
- Python, Docker (`docker compose`).

## 4. Architektura

```
 Przeglądarka analityka (VPN)
        │  HTTPS
        ▼
 ┌─────────────── docker compose ───────────────────────┐
 │  caddy (TLS: self-signed → docelowo firmowe CA)      │
 │     │                                                │
 │     ▼                                                │
 │  web  (Django + htmx, gunicorn)  ───┐                │
 │     │                               │ kolejka zadań  │
 │     ▼                               ▼                │
 │  postgres  ◄──────────────────  worker (RQ)          │
 │                                     │                │
 │                 redis ◄─────────────┘                │
 └─────────────────────────────────────┬────────────────┘
                                       │ HTTPS (wychodzące)
             RTIR REST2 · GTI · Censys · Joe Sandbox Cloud
```

**Stack**: Django (auth, sesje, CSRF, admin, ORM, migracje) + htmx (dynamiczne fragmenty bez SPA),
PostgreSQL, Redis + RQ (worker do zapytań API), gunicorn, Caddy jako reverse proxy z TLS.
Styl wyłącznie własnym CSS-em, bez frameworka UI.

**Kluczowe biblioteki**: `email` (stdlib) i `extract-msg` do parsowania, `nh3` do sanityzacji HTML,
`zxing-cpp` do QR, `py7zr` i `rarfile` do archiwów, `httpx` jako klient HTTP,
`cryptography` (Fernet) do szyfrowania kluczy Joe, `pytest` + `respx` do testów.

### 4.1 Moduły

| Moduł | Odpowiedzialność | Zależności |
|---|---|---|
| `parsing` | `.eml`/`.msg` → jednolity obiekt `Wiadomosc` (nagłówki, treść tekst/HTML, załączniki, wiadomości zagnieżdżone, ostrzeżenia parsowania) | tylko biblioteki, **bez Django** |
| `analysis` | SPF/DKIM/DMARC, Received, podszywanie, linki, archiwa, QR → lista IOC z relacjami i źródłem | `parsing`, **bez Django** |
| `integrations.gti` / `.censys` / `.joe` / `.rtir` | cienkie klienty API, jednolity format wyniku, obsługa limitów i błędów | `httpx` |
| `enrichment` | zadania workera: lookupy IOC, cache, odświeżanie | integracje, baza |
| `reporting` | budowa komentarza RTIR, mapowanie IOC na Custom Fields | `integrations.rtir` |
| `web` | widoki, szablony, htmx, konta, profil (klucz Joe), audyt | wszystko powyżej |

`parsing` i `analysis` są czystymi funkcjami: plik na wejściu, dane na wyjściu. Testowalne
bez Django, bazy i API.

## 5. Przepływ danych

1. **Wejście z RTIR**. Szablon RTIR dodaje przy każdym załączniku `.eml`/`.msg` link
   `https://<miemli>/analiza/nowa?ticket=<id>&attachment=<id>`. Niezalogowany użytkownik trafia
   na logowanie i wraca pod ten adres.
2. **Pobranie i deduplikacja**. `web` pobiera załącznik przez REST2 (token serwisowy z `.env`),
   liczy SHA256. Ten sam plik z tego samego ticketu → otwarcie istniejącej analizy. Ten sam plik
   w innym tickecie → nowa analiza. Parsowanie i analiza działają synchronicznie. Zapis do bazy:
   analiza, wynik parsowania (JSON), IOC z relacjami, kto i kiedy. Oryginał nie jest przechowywany.
3. **Automatyczne wzbogacenie (w tle)**. Dla każdego IOC zadania lookupu:
   - GTI: hashe, URL-e, domeny, IP,
   - Censys: IP,
   - Joe: wyszukiwanie po hashu (wspólny klucz z `.env`).

   Cache per IOC i dostawca: 24 h. Komórki tabeli IOC w stanie „oczekuje” są odpytywane przez htmx
   co 2 s, odpytywanie wyłącza się, gdy wszystkie wyniki są gotowe.
4. **Akcje ręczne**.
   - **JOE** (plik lub URL): wysyłka kluczem API zalogowanego użytkownika, otwarcie sesji
     Live Interaction w nowej karcie (jbxcloud), status/werdykt Joe dociągany później.
   - **Szczegóły IOC**: rozwinięcie z danymi GTI/Censys/Joe i linkami „otwórz w narzędziu”.
   - **Odśwież wzbogacenie**: ponowne lookupy z pominięciem cache.
5. **Raport do RTIR**. Sekcja „Raport”:
   - checkboxy przy IOC (domyślnie zaznaczone),
   - werdykt: phishing / spam / czysty / do weryfikacji,
   - notatka analityka,
   - podgląd raportu.

   „Wyślij do RTIR” dodaje **Comment** (nigdy Correspond) z podsumowaniem i linkiem do analizy
   oraz dopisuje zaznaczone IOC do Custom Fields RTIR (IP, Domain, Hash). Każda wysyłka jest
   zapisywana (kto, kiedy, treść, IOC). Ponowna wysyłka tworzy nowy komentarz.

## 6. Model danych

| Tabela | Zawartość |
|---|---|
| `Uzytkownik` | wbudowany model Django + profil: zaszyfrowany klucz API Joe (Fernet, klucz w `.env`) |
| `Analiza` | ticket RTIR, ID załącznika, SHA256, nazwa pliku, wynik parsowania (JSON), werdykt, notatka, utworzył, utworzono |
| `IOC` | analiza, typ (plik / url / domena / ip / email), wartość, rodzic (FK do `IOC`), źródło (nagłówek / treść / załącznik / QR), hashe dla plików |
| `Wzbogacenie` | IOC (typ + wartość), dostawca (gti / censys / joe), status, skrót wyniku, surowa odpowiedź (JSON), link do narzędzia, czas. Pełni rolę cache. |
| `ZgloszenieJoe` | użytkownik, IOC, ID analizy Joe, URL sesji, status, czas |
| `RaportRTIR` | analiza, użytkownik, czas, treść, wysłane IOC, status (wysłany / częściowo / błąd) |
| `Zdarzenie` | dziennik audytu: otwarcie analizy, akcje JOE, wysyłka raportu |

Analizy są przechowywane bezterminowo. Polityka retencji może zostać dodana później.

## 7. Bezpieczeństwo

- **Podgląd HTML maila**:
  - sanityzacja `nh3`,
  - wyświetlanie w `<iframe sandbox>` bez `allow-scripts`, CSP `default-src 'none'`,
  - zewnętrzne zasoby (obrazki, CSS, fonty) zablokowane — brak tracking pixeli,
  - obrazki `cid:` osadzone w mailu wyświetlane (serwowane przez miemli),
  - linki nieklikalne, prawdziwy adres widoczny po najechaniu.
- **IOC zawsze „rozbrojone”** w UI i raporcie (`hxxp`, `[.]`).
- **Załączniki tylko w pamięci**: nigdy nie są zapisywane na dysk ani wykonywane. Do Joe
  wysyłane prosto z pamięci.
- **Limity**:
  - maks. rozmiar pliku 50 MB,
  - maks. głębokość zagnieżdżeń 5 (mail w mailu, archiwum w archiwum),
  - limit łącznego rozmiaru po rozpakowaniu (ochrona przed zip bombą).
- **Archiwa na hasło**: próby haseł wyciągniętych z treści maila oraz `infected`.
- **Sekrety** (token RTIR, GTI, Censys, wspólny Joe, klucz Fernet, `SECRET_KEY`) tylko w `.env`.
- **Konta lokalne** zakładane przez administratora w panelu Django. Wszystkie widoki wymagają
  zalogowania. Ciasteczka sesji z `Secure` i `HttpOnly`.
- **TLS**: Caddy z certyfikatem self-signed na start, docelowo z wewnętrznego CA (podmiana
  certyfikatu, bez zmian w aplikacji).

## 8. Interfejs

- **Paleta**: Nord ciemny (Polar Night `#2e3440` jako tło, Frost `#88c0d0` jako akcent, Aurora
  dla statusów: `#a3be8c` OK, `#ebcb8b` ostrzeżenie, `#d08770` źle). Minimalistyczny, dużo
  powietrza.
- **Układ ekranu analizy** (makieta: `docs/superpowers/mockups/02-uklad.html`, wariant C):
  - pasek górny: logo, ticket RTIR + nazwa pliku, „Odśwież wzbogacenie”, „Wyślij do RTIR”,
  - lewa kolumna: nawigacja sekcji — Wiadomość, Nagłówki, Received, Załączniki, Linki,
    **IOC** (pełna tabela z wariantu B), Raport,
  - środek: zawartość wybranej sekcji,
  - prawy panel (stały): skrót IOC z wynikami wzbogacenia; klik otwiera szczegóły.
- **Tabela IOC**: typ, wartość (drzewo pochodzenia), GTI, Censys, Joe, akcje (JOE, szczegóły).
- **Inne ekrany**: logowanie, profil (klucz Joe), ręczny upload (awaryjnie), lista ostatnich
  analiz.

## 9. Obsługa błędów

Zasada: awaria jednego elementu nie blokuje reszty. Wiadomość i IOC są widoczne zawsze,
nawet gdy wszystkie API są niedostępne.

- **RTIR niedostępny / zły token**: komunikat, „Spróbuj ponownie”, awaryjny ręczny upload.
- **Plik nie jest `.eml`/`.msg` lub jest uszkodzony**: czytelny komunikat, bez stack trace.
- **Parsowanie „najlepszej próby”**: problemy (zepsute nagłówki, nieznane kodowanie, np.
  niezadeklarowany `windows-1250`) trafiają do listy ostrzeżeń, reszta jest przetwarzana.
- **Przekroczony limit**: ostrzeżenie „przerwano rozpakowywanie: …”, dotychczasowe wyniki zostają.
- **Archiwum z nieznanym hasłem**: IOC pliku z oznaczeniem „zaszyfrowane, hasło nieznane”,
  dostępny przycisk JOE.
- **Statusy wzbogacenia**: `oczekuje` · `gotowe` · `brak danych` · `błąd` · `limit` ·
  `nieskonfigurowane`.
  - 429: ponowienia z rosnącym odstępem, potem `limit` + „ponów”.
  - Timeout/5xx: 2–3 próby, potem `błąd`.
  - „Brak danych” nie jest błędem i jest cache'owany.
- **JOE bez klucza w profilu**: przycisk nieaktywny z podpowiedzią. Odrzucenie przez Joe:
  komunikat + wpis w audycie.
- **Wysyłka do RTIR**: przy błędzie raport zostaje jako szkic z „wyślij ponownie”. Przy
  częściowym sukcesie (komentarz tak, Custom Fields nie) dokładna informacja, co się udało.
- **Logi**: strukturalne, do stdout, bez treści maili i bez sekretów.

## 10. Testy

- **`parsing` / `analysis`**: pytest, TDD.
  - Zbiór próbek w `tests/samples/`: każda próbka + plik z oczekiwanym wynikiem (IOC,
    SPF/DKIM/DMARC, ostrzeżenia).
  - Próbki syntetyczne (zip w mailu, mail w mailu, archiwum na hasło, QR, SafeLinks,
    krzywe kodowania) w repo.
  - Prawdziwe zanonimizowane próbki od zespołu w `tests/samples/private/` — w `.gitignore`,
    nigdy w repo.
- **Integracje**: mocki odpowiedzi (`respx`), bez prawdziwych zapytań. Osobny, ręcznie
  uruchamiany smoke test na prawdziwych kluczach.
- **Web**: testy widoków Django (logowanie, uprawnienia, flow RTIR na mocku, budowa raportu).
- **Bezpieczeństwo HTML**: testy, że skrypty, zewnętrzne zasoby i `javascript:` są blokowane.

## 11. Kolejność budowy

1. **Szkielet**: Django, `docker compose` (web, postgres, redis, worker, caddy self-signed),
   logowanie, admin, pusta strona w stylu Nord.
2. **Rdzeń parsowania**: `.eml`/`.msg`, zagnieżdżenia, archiwa, wszystkie IOC z relacjami.
   Same testy, bez UI.
3. **Ekran analizy z ręcznym uploadem**: układ C, podgląd maila, nagłówki, Received, tabela IOC.
   Od tego momentu narzędzie jest używalne.
4. **GTI**, potem **Censys**: worker, cache, dociąganie wyników przez htmx.
5. **Joe**: lookup, wysyłka kluczem użytkownika, Live Interaction.
6. **RTIR**: link z ticketu, pobieranie załącznika, raport i Custom Fields.
7. **Szlify**: odświeżanie wzbogacenia, audyt, dopracowanie wyglądu.

Każdy etap kończy się działającym stanem, commitem i wpisem w `NOTES.md`.

## 12. Otwarte kwestie (do rozstrzygnięcia w trakcie)

- Dokładne pola zwracane przez API GTI, Censys i Joe do pokazania w skrócie — ustalimy na
  etapach 4–5 na podstawie realnych odpowiedzi.
- Nazwy i typy Custom Fields IOC w Waszej instancji RTIR — sprawdzimy na etapie 6.
- Sposób osadzenia linku w RTIR 6 (callback w szablonie vs. konfiguracja) — etap 6.
