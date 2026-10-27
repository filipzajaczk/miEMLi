# miemli — integracja z Joe Sandbox — specyfikacja

Data: 2026-10-27
Status: do przeglądu
Rozszerza: `docs/superpowers/specs/2026-10-26-miemli-design.md`. Zastępuje wcześniejsze ustalenia
o Joe (wysyłka pojedynczych plików/URL-i) — obowiązuje decyzja z 2026-10-27: do Joe trafia **cały
oryginalny mail** (`.eml`/`.msg`).

## 1. Cel

Analityk jednym przyciskiem wysyła cały analizowany mail do Joe Sandbox Cloud (swoim kontem, z Live
Interaction) i w miemli widzi status oraz werdykt Joe z linkiem do analizy. Bez przechowywania
oryginałów i bez ujawnienia kluczy Joe nawet przy przejęciu `web` lub bazy.

## 2. Zakres

**W zakresie**: profil analityka z kluczem Joe (szyfrowanie asymetryczne), klient API Joe, wysyłka
i śledzenie w workerze, sekcja „Joe Sandbox” w analizie, checkbox przy uploadzie, limity, audyt.

**Poza zakresem**: RTIR (odłożony; tu tylko punkt zaczepienia „źródło oryginału”), filtrowanie ruchu
wychodzącego workera do konkretnych hostów (zapisane w `NOTES.md` na później).

## 3. Ustalenia

- Źródło oryginału (bez przechowywania): **checkbox „Wyślij też do Joe Sandbox” przy uploadzie** oraz
  **ponowne wgranie pliku** przy wysyłce z sekcji Joe (weryfikacja SHA256). Później: pobranie z RTIR.
- Klucze Joe: **per analityk**, szyfrowane **kluczem publicznym**, którego prywatną parę ma wyłącznie
  worker.
- API Joe (biblioteka `jbxapi` od Joe Security): `POST https://jbxcloud.joesecurity.org/api/v2/submission/new`,
  klucz w polu formularza `apikey`; status przez `/v2/submission/info` i `/v2/analysis/info`;
  informacje o koncie `/v2/account/info`.
- Stałe parametry wysyłki:

| Parametr | Wartość |
|---|---|
| `live-interaction` | `1` |
| `internet-access` | `1` |
| `url-reputation` | `0` |
| `delete-after-days` | `30` |
| `accept-tac` | `1` |
| `comments` | `miemli, analiza #<id>` |
| `systems` | brak (wybór Joe) |

- Czy konto Joe Pro przyjmuje `.eml`/`.msg` jako próbkę — weryfikacja ręczna na prawdziwym koncie (§10).

## 4. Komponenty

### 4.1 Interfejs

- Menu analizy: wyróżniona pozycja „Analizuj w JOE” otwiera **sekcję „Joe Sandbox”** (`?sekcja=joe`):
  - formularz „Wyślij cały mail do Joe Sandbox” z polem pliku (ponowne wgranie) i potwierdzeniem;
  - historia wysyłek analizy: analityk, czas, status, werdykt i wynik Joe, link „Otwórz w Joe ↗”.
- Formularz uploadu: checkbox „Wyślij też do Joe Sandbox”.
- Okno potwierdzenia (przed każdą wysyłką, `data-potwierdz`): „Mail (z treścią i załącznikami) zostanie
  wysłany do chmury Joe Sandbox, poza firmę, i usunięty tam po 30 dniach. Kontynuować?”
- Strona **`/profil/`**: klucz Joe — „ustawiony, kończy się na …XXXX” / „nieustawiony”, stan weryfikacji
  („działa” / „odrzucony” / „sprawdzanie…”), formularz zmiany, przycisk usunięcia. Link do profilu
  w pasku górnym.
- Brak klucza → przycisk wysyłki nieaktywny z podpowiedzią „Ustaw klucz Joe w profilu”.

### 4.2 Backend

| Element | Odpowiedzialność |
|---|---|
| `integracje/joe.py` | klient: `wyslij`, `stan_zgloszenia`, `info_konta`; walidacja i limit odpowiedzi |
| `analizy/klucze_joe.py` | `zaszyfruj_klucz(uzytkownik_id, klucz)` / `odszyfruj_klucz(uzytkownik_id, szyfrogram)`, `zaszyfruj_plik(zgloszenie_id, dane)` / `odszyfruj_plik(zgloszenie_id, szyfrogram)` (PyNaCl `SealedBox`) |
| `analizy/models.py` | `ProfilAnalityka`, `ZgloszenieJoe` |
| `analizy/joe_zadania.py` | `zlec_wysylke(...)` (web), zadania workera `wyslij_do_joe`, `sprawdz_joe`, `sprawdz_klucz_joe` |
| `analizy/management/commands/joe_generuj_klucze.py` | wypisuje nową parę kluczy (base64) do wklejenia do `.env` |

**Modele**

- `ProfilAnalityka`: `uzytkownik` (1:1), `joe_klucz_szyfr` (bytes/base64, null), `joe_klucz_koncowka`
  (4 znaki), `joe_klucz_stan` (`nieznany` | `sprawdzanie` | `dziala` | `odrzucony`), `joe_klucz_zmieniono`.
- `ZgloszenieJoe`: `analiza` (FK), `uzytkownik` (FK), `utworzono`, `status`
  (`zlecone` | `wyslane` | `w_kolejce` | `trwa` | `zakonczone` | `blad` | `limit` | `czas_minal`),
  `id_zgloszenia` (str, null), `webid` (str, null), `werdykt` (`zlosliwy` | `podejrzany` | `czysty` |
  `nieznany`, null), `wynik` (int, null), `blad` (text), `sprawdzono` (datetime, null).
  Link do analizy wyliczany: `https://jbxcloud.joesecurity.org/analysis/<webid>`.

**Konfiguracja**: `web` — `JOE_KLUCZ_PUBLICZNY`; worker — `JOE_KLUCZ_PRYWATNY` (i publiczny);
`JOE_LIMIT_DZIENNY` (domyślnie 20), `JOE_API_URL` (domyślnie `https://jbxcloud.joesecurity.org/api`).

## 5. Przepływ danych

1. **Zlecenie (web)** — z sekcji Joe (ponowne wgranie) albo z uploadu (checkbox):
   - SHA256 wgranego pliku == `Analiza.sha256`, inaczej „To nie jest ten sam plik co w analizie.”;
   - analityk ma klucz Joe (`joe_klucz_szyfr` ustawiony), inaczej „Ustaw klucz Joe w profilu.”;
   - brak zgłoszenia tego analityka dla tej analizy w ostatnich 10 min, inaczej „Już wysłano — poczekaj
     na wynik.”;
   - liczba zgłoszeń analityka od północy < `JOE_LIMIT_DZIENNY`, inaczej „Osiągnięto dzienny limit
     wysyłek do Joe.”;
   - `ZgloszenieJoe(status="zlecone")`, `Zdarzenie(typ="joe_wyslanie")`;
   - plik szyfrowany `zaszyfruj_plik(zgloszenie.id, dane)` → do kolejki trafia wyłącznie szyfrogram
     (base64), zadanie z `result_ttl=0`, `failure_ttl=0`.
2. **Wysyłka (worker)** `wyslij_do_joe(zgloszenie_id, szyfrogram, proba=0)`: odszyfrowanie pliku
   i klucza Joe analityka (w pamięci), `POST submission/new` z parametrami §3, plik jako
   `analiza-<id>.eml` lub `.msg` (rozszerzenie z oryginalnej nazwy, tylko te dwa); zapis
   `id_zgloszenia`, status `wyslane`, zaplanowanie `sprawdz_joe` za 30 s.
3. **Śledzenie (worker)** `sprawdz_joe(zgloszenie_id)` co 30 s, maks. 2 h od wysyłki:
   `submission/info` → pierwsza analiza (`webid`) → `analysis/info` → status (`submitted`→`w_kolejce`,
   `running`→`trwa`, `finished`→`zakonczone`) i po zakończeniu werdykt (`detection`:
   `malicious`→`zlosliwy`, `suspicious`→`podejrzany`, `clean`→`czysty`, inne→`nieznany`) oraz `score`.
   Po 2 h bez zakończenia → `czas_minal` (link zostaje).
4. **Ekran**: sekcja Joe odświeżana fragmentem htmx co 5 s tylko, gdy jest zgłoszenie w statusach
   `zlecone`/`wyslane`/`w_kolejce`/`trwa`.
5. **Sprawdzenie klucza**: po zapisie klucza w profilu `sprawdz_klucz_joe(uzytkownik_id)` w workerze
   (`account/info`) → `joe_klucz_stan` `dziala`/`odrzucony`.

## 6. Błędy

| Sytuacja | Status / komunikat | Ponowienia |
|---|---|---|
| 401/403 | `blad`: „Klucz Joe odrzucony — sprawdź go w profilu.” | brak |
| 429 / limit konta | `limit`: „Wyczerpany limit Joe.” | po 60 s, 300 s |
| Sieć, timeout, 5xx | `blad`: „Joe niedostępny.” | po 30 s, 120 s |
| Joe odrzuca plik (błąd w odpowiedzi) | `blad`: „Joe nie przyjął pliku: <komunikat Joe, max 200 znaków>” | brak |
| Szyfrogram klucza nie pasuje (wymiana pary, inny użytkownik) | `blad`: „Ustaw ponownie klucz Joe w profilu.”, `joe_klucz_stan=odrzucony` | brak |
| Szyfrogram pliku nie pasuje | `blad`: „Błąd wewnętrzny wysyłki.” | brak |

## 7. Bezpieczeństwo

- **SealedBox (X25519 + XSalsa20-Poly1305)**: `web` ma tylko klucz publiczny; prywatny wyłącznie
  w środowisku workera. Para generowana komendą (nic nie zapisuje na dysk).
- **Powiązanie szyfrogramów**: tekst jawny klucza = `"<uzytkownik_id>:<klucz>"`, pliku =
  `"<zgloszenie_id>:" + bajty`; worker odrzuca szyfrogram z innym identyfikatorem.
- **Klucz analityka**: edycja tylko własnego (POST + CSRF), `type="password"`, `autocomplete="off"`,
  walidacja `^[A-Za-z0-9]{20,128}$`; nigdy nie wraca do przeglądarki ani logów; w bazie szyfrogram
  i 4 ostatnie znaki; audyt `joe_klucz_ustawiony` / `joe_klucz_usuniety` bez wartości.
- **Odpowiedzi Joe** niezaufane: maks. 1 MB (odczyt strumieniowy), walidacja typów; `webid`
  i `id_zgloszenia` tylko `^[A-Za-z0-9_-]{1,64}$`; link budowany przez miemli z `webid`.
- **Limity**: duplikat 10 min, `JOE_LIMIT_DZIENNY` na analityka.
- **Redis**: `--save "" --appendonly no` (brak zrzutów na dysk); zadania z `result_ttl=0`,
  `failure_ttl=0`.
- **Logi**: ID zgłoszenia, status, kod HTTP — nigdy klucza, pliku ani nazwy pliku.
- **Ryzyko zaakceptowane**: mail trafia do chmury Joe (potwierdzenie + usunięcie po 30 dniach);
  worker ma ogólny dostęp do internetu (proxy wychodzące — później).

## 8. Punkt zaczepienia RTIR

`zlec_wysylke(analiza, uzytkownik, dane: bytes)` przyjmuje bajty od dowolnego źródła. Przy integracji
z RTIR dojdzie źródło „pobierz z RTIR po `ticket_id`/`attachment_id`” (w workerze), bez zmian
w szyfrowaniu, zadaniach i historii.

## 9. Testy

- Szyfrowanie: round-trip; `web` bez klucza prywatnego nie odszyfrowuje; obcy identyfikator odrzucony;
  wymiana pary → „ustaw ponownie”.
- Klient Joe (`respx`): `apikey` w treści formularza (nie w nagłówku); parametry dokładnie wg §3; nazwa
  pliku `analiza-<id>.eml`; 200/401/403/429/5xx/nie-JSON; odpowiedź > 1 MB odrzucona; zły `webid`
  odrzucony.
- Zadania: wysyłka → śledzenie → `zakonczone` z werdyktem; ponowienia; `czas_minal` po 2 h; zadanie
  w kolejce zawiera wyłącznie szyfrogram (brak bajtów maila w argumentach).
- Widoki: profil (zapis, brak wyświetlania klucza, tylko własny), sekcja Joe (inny SHA256, brak klucza,
  duplikat, limit dzienny), checkbox przy uploadzie, potwierdzenie, historia i odświeżanie, audyt, logi
  bez klucza i nazwy pliku.
- Ręcznie na prawdziwym koncie: `.eml` z korpusu i prywatny `.msg`; otwarcie Live Interaction z linku.

## 10. Kolejność budowy

1. Szyfrowanie, `joe_generuj_klucze`, `ProfilAnalityka`, strona profilu.
2. Klient `integracje/joe.py`.
3. `ZgloszenieJoe`, zadania workera, Redis bez zapisu na dysk.
4. Sekcja „Joe Sandbox”, checkbox przy uploadzie.
5. Docker (`.env` dla web i workera), README, test na prawdziwym koncie.
