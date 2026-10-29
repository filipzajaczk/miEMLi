# miemli — etap B: oś czasu nagłówków i wyszukiwarka analiz — specyfikacja

Data: 2026-10-29
Status: zatwierdzona w rozmowie (dwie sekcje), do przeglądu pliku
Rozszerza: `docs/superpowers/specs/2026-10-26-miemli-design.md` i specyfikację etapu A.

Cel: (1) w kilka sekund zobaczyć, skąd mail naprawdę przyszedł i czy ścieżka wygląda na sfałszowaną;
(2) odpowiedzieć na pytanie „czy ten artefakt już był u nas?” — powiązać nowe zgłoszenie z wcześniejszymi.

Decyzje użytkownika: kraj/ASN IP wyłącznie z istniejących wyników GTI/Censys (bez lokalnej bazy GeoIP);
wyszukiwarka + automatyczne odznaki „widziane wcześniej” przy artefaktach.

## 1. Oś czasu nagłówków

### 1.1 Przeskoki (sekcja „Received”)

Kolejność bez zmian (najstarszy pierwszy). Kolumny: #, Od, Przez, IP + kraj/ASN, Czas, Opóźnienie, Uwagi.

- **Kraj/ASN:** z `Wzbogacenie` dla artefaktu typu `ip` o tej wartości — pierwszeństwo GTI (`kraj`, `asn`,
  `wlasciciel`), uzupełnienie z Censys (`kraj`, `asn`). Brak wyniku → „…” podczas wzbogacania, „—” gdy
  dostawca nie zna IP. IP niepubliczne → „sieć wewnętrzna”. Komórki odświeżane tym samym odpytywaniem htmx
  co tabela artefaktów (fragment OOB `#os-czasu-cialo`).
- **Anomalie** (liczone w `mailcore`, lista `uwagi` przy przeskoku; kod + opis po polsku):

| Kod | Warunek | Klasa |
|---|---|---|
| `CZAS_WSTECZ` | czas przeskoku wcześniejszy od poprzedniego o > 5 min | `bad` |
| `DLUGI_POSTOJ` | opóźnienie względem poprzedniego przeskoku > 1 h | `warn` |
| `CZAS_W_PRZYSZLOSCI` | czas przeskoku późniejszy niż chwila analizy + 15 min | `bad` |
| `BRAK_CZASU` | przeskok bez czytelnego czasu | `neutral` |
| `BRAK_IP` | przeskok bez IP | `neutral` |

- Na poziomie wiadomości: sygnał `DATA_ODLEGLA` (`warn`), gdy `Date` różni się od czasu pierwszego
  przeskoku o > 24 h (w którąkolwiek stronę).

### 1.2 Blok „Klient i przekazanie” (nad tabelą przeskoków)

- `X-Mailer`, `User-Agent`, `X-Originating-IP` (IP z krajem jak wyżej; wartość niepubliczna — bez kraju).
  Wartości przycięte do 300 znaków, wyświetlane jako tekst.
- **ARC:** dla każdego ogniwa `i` (1..n, maks. 50) z `ARC-Authentication-Results`: wyniki `spf`, `dkim`,
  `dmarc` (jak w uwierzytelnieniu głównym) i serwer (`authserv-id`). Kompletność łańcucha: dla każdego `i`
  są wszystkie trzy nagłówki (`ARC-Seal`, `ARC-Message-Signature`, `ARC-Authentication-Results`), numery
  ciągłe od 1, `cv=` w `ARC-Seal`. Adnotacja stała: „Wyniki deklarowane przez serwery pośredniczące —
  podpisy ARC nie są weryfikowane kryptograficznie.” (parser nie ma sieci/DNS).
- Brak wszystkich danych → blok się nie wyświetla.

### 1.3 Gdzie i jak

- `mailcore/analiza/received.py`: anomalie przeskoków + `DATA_ODLEGLA`; nowy moduł
  `mailcore/analiza/klient.py` (X-Mailer/User-Agent/X-Originating-IP, ARC). Wyniki w `AnalizaWiadomosci`
  (nowe pola `klient`, `arc`; `Hop.uwagi`), serializowane jak reszta analizy.
- Walidacja odpowiedzi parsera (`waliduj_wynik`) obejmuje nowe pola (typy, długości, liczba ogniw ≤ 50).
- Analizy utworzone przed zmianą: brak nowych pól → oś czasu bez uwag i bez bloku klienta (bez błędów).

## 2. Wyszukiwarka

### 2.1 Pole i wyniki

- Pole „Szukaj” w pasku każdej strony (`GET /szukaj/?q=`), `login_required`, tylko odczyt.
- Wejście: przycięte, maks. 2048 znaków, „uzbrojenie” wartości rozbrojonych (`hxxp`→`http`, `[.]`/`(.)`/`[dot]`→`.`,
  `[@]`/`[at]`→`@`, `[:]`→`:`).
- Rozpoznanie (pierwsze pasujące):

| Wejście | Dopasowanie |
|---|---|
| 32/40/64 znaki hex | artefakt `plik` z `hashe.md5`/`hashe.sha1`/`wartosc` (sha256); `Analiza.sha256` (cały plik) |
| IPv4/IPv6 | artefakt `ip` dokładnie (postać kanoniczna `ipaddress`) |
| adres e-mail | artefakt `email` dokładnie (małe litery) |
| `http(s)://…` | artefakt `url` dokładnie + domena hosta jak niżej |
| domena (`a.b`, bez spacji) | artefakt `domena` == d lub kończący się na `.d` (małe litery, IDNA) |
| inny tekst, ≥ 3 znaki | `temat_wiadomosci`, `nazwa_pliku`, `notatka` — fragment bez wielkości liter |
| < 3 znaki | komunikat „Wpisz co najmniej 3 znaki.” |

- Wynik: analizy (bez duplikatów), najnowsze pierwsze, maks. 200 (+ informacja „pokazano 200 najnowszych”).
  Kolumny jak na liście analiz + „Dopasowanie” (np. „domena: login.evil[.]com”, „temat”, „plik .eml”) —
  wartości rozbrojone. Lista nie ładuje pola `wynik`.
- Zapytanie nie trafia do audytu ani logów aplikacji.

### 2.2 Odznaki „w N innych analizach”

- W tabeli artefaktów i w panelu bocznym: szara odznaka „w N innych analizach” (N ≥ 1) przy artefaktach,
  których (typ, wartość) występuje w innych analizach; link do `/szukaj/?q=<wartość>`.
- Liczenie jednym zapytaniem na stronę: `IOC.skrot` (sha256 z `"typ:wartosc"`, indeks) — grupowanie po
  `skrot`, `COUNT(DISTINCT analiza)` z wykluczeniem bieżącej analizy.
- `IOC.skrot` ustawiany przy tworzeniu artefaktów; migracja uzupełnia istniejące (w Pythonie, partiami,
  tylko pola `pk`, `typ`, `wartosc`).

## 3. Testy

TDD: każdy kod anomalii i próg (wartości tuż poniżej/powyżej), `DATA_ODLEGLA`, klient/ARC (łańcuch pełny,
niepełny, nieciągły, > 50 ogniw, brak nagłówków), walidacja nowych pól, kraj z GTI/Censys/brak/IP prywatne,
stare analizy bez nowych pól; wyszukiwarka — każdy typ wejścia, wartości rozbrojone, subdomeny (i brak
fałszywych dopasowań typu `notevil.com` dla `evil.com`), limit 200, < 3 znaki, wymagane logowanie, brak
`wynik` w SQL wyników; odznaki — liczba zapytań stała, wykluczenie bieżącej analizy, migracja `skrot`.
Weryfikacja w przeglądarce i końcowy przegląd całej gałęzi.
