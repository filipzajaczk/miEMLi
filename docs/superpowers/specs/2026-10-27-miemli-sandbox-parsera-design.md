# miemli — sandbox parsera — specyfikacja

Data: 2026-10-27
Status: do przeglądu
Rozszerza: `docs/superpowers/specs/2026-10-26-miemli-design.md` (§4, §7). W razie sprzeczności ten
dokument ma pierwszeństwo dla przetwarzania plików od atakującego.

## 1. Cel

Pliki `.eml`/`.msg` mogą być przygotowane przez zaawansowanego atakującego (APT), który celuje w błędy
pamięci natywnych bibliotek (dekodery obrazów, rozpakowywacze) albo w przeglądarkę analityka.
Celem jest, aby przejęcie kodu przetwarzającego wrogi plik nie dawało dostępu do sekretów, bazy,
sieci ani kolejnych analiz, a przeglądarka analityka nie dostawała bajtów od atakującego.

**Kryteria sukcesu**

- Proces `web` nie wykonuje żadnego kodu dekodującego dane z analizowanego pliku.
- Kontener `parser` nie ma sieci (poza połączeniem od `web`), sekretów, bazy ani Redisa.
- Każdy plik jest przetwarzany w świeżym procesie z twardymi limitami; awaria procesu nie wpływa na
  kolejne analizy.
- Obrazki trafiające do przeglądarki analityka są generowane przez miemli (PNG), nie przez atakującego.
- Na produkcji parser działa w gVisor (`runsc`); brak gVisor jest widocznie sygnalizowany.

## 2. Zakres

**W zakresie**: kontener `parser` (gVisor), proces na plik z limitami, przekodowanie obrazków, klient
i walidacja odpowiedzi w `web`, obsługa przerwanych analiz, instrukcja instalacji gVisor.

**Poza zakresem**: integracja z Joe Sandbox (decyzja 2026-10-27: do Joe trafia cały oryginalny mail,
wysyłany przez worker bez parsowania — sandbox jej nie blokuje), RTIR, własny profil seccomp.

## 3. Ustalenia

- Produkcja: osobna maszyna wirtualna z możliwością instalacji gVisor (`runsc`).
- Obrazki z treści maila (cid) są przekodowywane w sandboxie do PNG (opcja A).
- Architektura: stała usługa `parser` + proces potomny na każdy plik (podejście 1). Odrzucone:
  parser jako worker Redisa (dostęp do wspólnego brokera), kontener na plik (wymaga gniazda Dockera
  w `web`, czyli roota na hoście).

## 4. Komponenty

```
 przeglądarka ──HTTPS──► caddy ──► web ──HTTP──► parser (gVisor/runsc)
                                    │             sieć „piaskownica”: tylko web ↔ parser
                                    ▼
                            postgres / redis / worker
```

### 4.1 Pakiet `piaskownica/`

| Element | Odpowiedzialność |
|---|---|
| `piaskownica/zadanie.py` (`python -m piaskownica.zadanie`) | proces potomny: stdin = bajty pliku, argumenty = nazwa i limity; ustawia limity systemowe; `parsuj` → `analizuj` → przekodowanie obrazków → `do_json`; stdout = JSON |
| `piaskownica/obrazki.py` | rozpoznanie formatu po sygnaturze, raport obrazków (§8.1), przekodowanie do PNG |
| `piaskownica/serwer.py` | serwer HTTP: `POST /analizuj`, `GET /zdrowie`; uruchamia proces potomny, pilnuje czasu, równoległości i kolejki |
| `piaskownica/gvisor.py` | wykrycie, czy proces działa w gVisor |

### 4.2 Kontener `parser`

- Osobny, odchudzony obraz: Python, `mailcore`, `piaskownica`, biblioteki parsujące, `unar`.
  Bez Django, klienta bazy i narzędzi sieciowych. Obraz bazowy przypięty do digestu.
- `runtime: ${PARSER_RUNTIME:-runc}` (produkcja: `runsc`).
- Tylko sieć `piaskownica` (`internal: true`, członkowie: `web`, `parser`).
- Użytkownik UID 65534, `read_only: true`, `tmpfs /tmp` 300 MB `noexec,nosuid,nodev`,
  `cap_drop: [ALL]`, `no-new-privileges`, `mem_limit: 2.5g`, `pids_limit: 64`.
- Brak zmiennych środowiskowych z sekretami.

### 4.3 Zmiany w `web`

- `analizy/piaskownica_klient.py`: `analizuj_w_piaskownicy(dane: bytes, nazwa: str) -> dict` — wysyła
  plik do parsera, waliduje odpowiedź, zwraca wynik albo rzuca `AnalizaPrzerwana(powod)` /
  `PiaskownicaNiedostepna`.
- `analizy/uslugi.py` używa klienta zamiast lokalnych `parsuj`/`analizuj`.
- Ustawienia: `PIASKOWNICA_URL` (domyślnie `http://parser:8000`); w testach tryb „w procesie”
  (bez HTTP, ten sam kod co proces potomny), wybierany ustawieniem.
- `web` dołącza do sieci `piaskownica` (obok `wewnetrzna`).

## 5. Przepływ danych

1. `web` przyjmuje plik (pamięć), liczy SHA256, deduplikacja — bez zmian.
2. `web` → `POST {PIASKOWNICA_URL}/analizuj`, ciało = bajty pliku, nagłówki: nazwa pliku
   (URL-encoded), limity z ustawień `web`.
3. Parser uruchamia proces potomny (osobny interpreter, bez dziedziczonego stanu), przekazuje bajty
   przez stdin, odbiera JSON ze stdout.
4. `web` waliduje odpowiedź (§7) i zapisuje analizę, IOC oraz planuje wzbogacenie — jak dotąd.
5. Odpowiedź parsera: `200` z `{"status": "ok", "wynik": {...}}` albo `200` z
   `{"status": "przerwana", "powod": "czas" | "pamiec" | "awaria" | "nieobslugiwany" | "za_duzy"}`;
   `503` gdy kolejka pełna.

## 6. Limity i awarie

**Proces potomny** (limity systemowe `resource.setrlimit`): pamięć adresowa 1 GB, CPU 30 s,
otwarte pliki 64, rozmiar zapisywanych plików 300 MB (RAR w `/tmp`), zrzuty pamięci 0.
Limit czasu rzeczywistego 60 s — po nim proces jest zabijany (`SIGKILL`). Pliki tymczasowe procesu
są usuwane po zakończeniu.

**Serwer parsera**: maks. 2 procesy równolegle, kolejka maks. 8 żądań (dalej `503`).

| Sytuacja | Komunikat dla analityka | Zapis |
|---|---|---|
| Limit czasu | „Analiza przerwana: przekroczony czas. Plik może być złośliwy lub uszkodzony — przeanalizuj go w Joe Sandbox.” | `Zdarzenie(typ="analiza_przerwana", szczegoly={sha256, plik, powod})` |
| Limit pamięci | jw. — „przekroczony limit pamięci” | jw. |
| Proces padł (sygnał / kod ≠ 0 bez JSON) | jw. — „parser przerwał pracę” | jw. + `logger.warning` w `web` |
| Parser niedostępny / `503` | „Sandbox analizy niedostępny — spróbuj za chwilę.” | log |
| Odpowiedź niepoprawna | „Nieprawidłowy wynik analizy.” | zdarzenie `analiza_przerwana` z powodem `nieprawidlowa_odpowiedz` + log |
| Nie mail / za duży | jak dotąd | jak dotąd |

Przy przerwanej analizie nie powstaje `Analiza` w bazie.

## 7. Walidacja odpowiedzi w `web`

Wynik parsera jest niezaufany:

- maks. 20 MB treści odpowiedzi, poprawny JSON;
- klucze `wiadomosc`, `analiza`, `ioc` o oczekiwanych typach; maks. 5000 IOC; każdy IOC ma
  `typ` ∈ {plik, url, domena, ip, email}, `wartosc` (str, ≤ 8192 znaki), `id` (int), `rodzic_id`
  (int lub null, wskazujący wcześniejszy IOC);
- dotychczasowe zabezpieczenia wyświetlania zostają (escapowanie, ponowne czyszczenie HTML, CSP).

## 8. Obrazki

- Wejście: tylko PNG, JPEG, GIF, BMP (Pillow z ograniczoną listą formatów); inne → pominięte.
- Wyjście: PNG, maks. 1600 px szerokości (proporcjonalnie), maks. 2 MB po zakodowaniu, maks. 20
  obrazków na wiadomość; GIF — pierwsza klatka.
- Obrazek pominięty → w podglądzie ramka „obrazek pominięty” (tekst, bez bajtów).
- Do `html_bezpieczny` trafiają wyłącznie przekodowane PNG jako `data:image/png;base64,…`.

### 8.1 Raport obrazków

Nietypowy obrazek bywa śladem próby exploita, dlatego każdy obrazek z wiadomości (załącznik
`image/*` lub osadzony `cid:`, także w zagnieżdżonych wiadomościach) dostaje wpis w raporcie, a
nietypowe są wyraźnie oznaczone. Oryginalnych bajtów nie przechowujemy — do ponownego zbadania
służy SHA256 (IOC typu plik) i wysyłka całego maila do Joe Sandbox.

**Rozpoznanie formatu** — własnym kodem po sygnaturze bajtów, *bez* dekodowania (żeby nie uruchamiać
dekodera nieobsługiwanego formatu): PNG, JPEG, GIF, BMP, TIFF, WebP, SVG, EPS/PostScript, ICO, PSD,
JPEG 2000, AVIF/HEIC (`ftyp`), nieznany.

**Wpis raportu** (w wyniku parsera, per wiadomość, klucz `obrazki`):

```json
{"nazwa": "logo.png", "sha256": "…", "rozmiar": 48211, "content_id": "logo1",
 "mime_zadeklarowany": "image/png", "format_wykryty": "TIFF",
 "szerokosc": 120, "wysokosc": 40, "klatki": 1,
 "status": "przekodowany" | "pominiety",
 "uwagi": [{"kod": "…", "opis": "…"}]}
```

`szerokosc`/`wysokosc`/`klatki` tylko dla formatów dozwolonych (odczyt nagłówka przez Pillow), dla
pozostałych `null`.

**Kody uwag** (każdy obrazek może mieć kilka):

| Kod | Kiedy | Status |
|---|---|---|
| `FORMAT_NIEOBSLUGIWANY` | wykryty format spoza PNG/JPEG/GIF/BMP (np. TIFF, WebP, SVG, EPS) | pominięty |
| `FORMAT_NIEZGODNY` | wykryty format ≠ zadeklarowany MIME / rozszerzenie (np. `logo.png` będący TIFF-em) | wg formatu |
| `ZA_DUZO_PIKSELI` | > 20 Mpx | pominięty |
| `ZA_DUZY_PLIK` | > 10 MB przed dekodowaniem | pominięty |
| `NIETYPOWE_WYMIARY` | bok > 10 000 px lub proporcje > 50:1 | wg pozostałych |
| `ANIMACJA` | GIF z wieloma klatkami (pokazana pierwsza; liczba klatek w `klatki`) | przekodowany |
| `USZKODZONY` | błąd dekodowania nagłówka lub pikseli | pominięty |
| `LIMIT_LICZBY` | ponad 20 obrazków w wiadomości | pominięty |
| `PRZESKALOWANY` | szerszy niż 1600 px — pokazano pomniejszony | przekodowany |

**Wyświetlanie:**

- Sekcja „Wiadomość”: pod listą załączników ramka **„Obrazki (N)”** — nazwa, wykryty format, wymiary,
  rozmiar, status; uwagi jako odznaki. Uwagi oznaczające podejrzenie (`FORMAT_NIEOBSLUGIWANY`,
  `FORMAT_NIEZGODNY`, `ZA_DUZO_PIKSELI`, `ZA_DUZY_PLIK`, `NIETYPOWE_WYMIARY`, `USZKODZONY`)
  w kolorze ostrzegawczym; `ANIMACJA`, `PRZESKALOWANY`, `LIMIT_LICZBY` neutralne.
- Gdy wiadomość ma choć jeden podejrzany obrazek — ostrzeżenie na górze sekcji „Wiadomość”:
  „Nietypowe obrazki w wiadomości (N) — szczegóły poniżej; rozważ analizę w Joe Sandbox.”
- Tabela IOC: przy IOC pliku-obrazka z uwagą podejrzaną odznaka z kodem uwagi (np. „format niezgodny:
  TIFF”); w rozwinięciu szczegółów pełny wpis raportu.
- Ramka „obrazek pominięty” w podglądzie zawiera powód (np. „obrazek pominięty: format TIFF”).

## 9. gVisor

- `piaskownica/gvisor.py`: wykrycie po `/proc/version` / `dmesg` charakterystycznych dla gVisor.
- `GET /zdrowie` → `{"gvisor": bool, "wersja": "..."}`.
- `web`: przy starcie i w panelu admina (komunikat) ostrzeżenie, gdy `PARSER_WYMAGA_GVISOR=1`
  (produkcja), a parser zgłasza `gvisor: false`.

## 10. Logi

Parser loguje wyłącznie: SHA256, rozmiar, czas trwania, status, powód przerwania. Nigdy treści,
nagłówków ani nazw plików.

## 11. Testy

- Proces potomny na próbkach korpusu — wynik zgodny z oczekiwaniami testu korpusu.
- Limity na prawdziwych procesach: zjadanie pamięci → `pamiec`; pętla → `czas`; awaria procesu
  (tryb testowy wymuszający `os.abort()`) → `awaria`.
- Serwer: równoległość 2, kolejka 8, `503` przy przepełnieniu, statusy odpowiedzi.
- `web`: walidacja (zły JSON, brak kluczy, za duża odpowiedź, za dużo IOC, zły `rodzic_id`),
  komunikaty i zdarzenie `analiza_przerwana`, parser niedostępny.
- `web` nie parsuje lokalnie: podmieniony `mailcore.parsuj.parsuj` rzuca wyjątek, upload działa.
- Obrazki: cid PNG/JPEG/GIF → PNG o innych bajtach niż oryginał; TIFF/WebP/SVG → pominięte.
- Raport obrazków: każdy kod uwagi z §8.1 na dedykowanej próbce (TIFF z rozszerzeniem `.png`,
  animowany GIF, obraz 30 Mpx, pasek 20000×10 px, uszkodzony PNG, 25 obrazków, SVG); rozpoznanie
  formatu nie wywołuje dekodera dla formatów nieobsługiwanych; wyświetlanie odznak i ostrzeżenia.
- Ręcznie w Dockerze: z `parser` brak internetu, Postgresa i Redisa; `/zdrowie`; upload próbek.

## 12. Kolejność budowy

1. `piaskownica/zadanie.py` + `obrazki.py` (limity, przekodowanie, raport obrazków).
2. `piaskownica/serwer.py` (`/analizuj`, `/zdrowie`, kolejka).
3. Obraz i kontener `parser`, sieć `piaskownica`, `PARSER_RUNTIME`.
4. Klient w `web`, walidacja, przełączenie uploadu, `analiza_przerwana`.
5. Ostrzeżenie o braku gVisor, README (instalacja `runsc`), test całości w Dockerze.

## 13. Instalacja gVisor na serwerze produkcyjnym

1. Instalacja z oficjalnego repozytorium gVisor (`apt install runsc`), `sudo runsc install`,
   restart Dockera.
2. `.env`: `PARSER_RUNTIME=runsc`, `PARSER_WYMAGA_GVISOR=1`.
3. `docker compose up -d --build`, sprawdzenie `/zdrowie` lub panelu admina.
