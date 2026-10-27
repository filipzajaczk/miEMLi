# NOTES

## Stan

- 2026-10-26: specyfikacja (`docs/superpowers/specs/2026-10-26-miemli-design.md`) i plan etapów 1–3
  (`docs/superpowers/plans/2026-10-26-miemli-etap1-3-rdzen.md`). Realizacja na branchu `etap-1-3`.
- Etapy 1–3 zrobione:
  - szkielet Django, logowanie, admin, styl Nord;
  - `docker compose` (caddy z `tls internal`, web, worker, postgres, redis);
  - parser `.eml`/`.msg` z rekurencją (mail w mailu), archiwa zip/7z/rar (hasła z treści, limity);
  - analiza SPF/DKIM/DMARC, Received, podszywanie, linki (SafeLinks, Proofpoint), QR;
  - IOC z relacjami, rozbrajanie, bezpieczny podgląd HTML (iframe sandbox + CSP);
  - ekran analizy w układzie C, ręczny upload, deduplikacja.
- Testy: 240 (pytest); testy Django przechodzą też na Postgresie. Próbka `.msg` jest prywatna (`tests/samples/private/`) — na innej maszynie testy `.msg` są pomijane.

- Etap 4 zrobiony: wzbogacenie IOC w GTI i Censys przez worker RQ (cache 24 h,
  ponowienia, odpytywanie htmx co 2 s), kolumny GTI/Censys/JOE, rozwijane szczegóły, „Odśwież
  wzbogacenie”, `manage.py sprawdz_api`. JOE = tylko link do strony Joe Sandbox.
- Censys: z `CENSYS_ORG_ID` obecny token dostaje 403 — usunąć zmienną z `.env` albo poprosić
  administratora Censys o rolę „API Access” w organizacji.

- 2026-10-27: utwardzenie: Pillow tylko PNG/JPEG/GIF/BMP + twardy limit pikseli, CSP bez inline,
  `sandbox` w CSP podglądu, ponowne czyszczenie HTML przy wyświetlaniu, kontenery read-only bez
  capabilities, sieci bez internetu dla web/postgres/redis, hasło Redisa, RQ na JSON, klucze API tylko
  w workerze, obraz bazowy przypięty do digestu, pip-audit (0 podatności).
- 2026-10-27: sandbox parsera: kontener `parser` (sieć `piaskownica`, bez sekretów/bazy/internetu,
  UID 65534, read-only), proces na plik z limitami, przekodowanie obrazków do PNG, raport nietypowych
  obrazków, walidacja odpowiedzi w web, zdarzenie `analiza_przerwana`, baner o braku gVisor.
- Do zrobienia na serwerze produkcyjnym: instalacja gVisor, `PARSER_RUNTIME=runsc`, `PARSER_WYMAGA_GVISOR=1`.

## Na później (2026-10-27)

- RTIR odłożony na później (decyzja użytkownika) — najpierw integracja z Joe Sandbox.
- Proxy wychodzące dla workera: zawęzić ruch do GTI, Censys i Joe (dziś worker ma ogólny dostęp do internetu).

## Odłożone drobiazgi z przeglądu sandboxa (2026-10-27)

- Drzewo `wiadomosc` z parsera walidowane tylko płytko — przejęty parser może wywołać błąd 500 jednej analizy.
- OOM-kill kontenera parsera raportowany jako „czas”, nie „pamięć”.
- Kolejka 8 w parserze praktycznie nieosiągalna (3 workery gunicorna, timeout klienta 90 s).
- Parser widzi `web:8000` bezpośrednio (strona logowania z pominięciem Caddy) — rozważyć limit prób logowania.
- Sprzątanie procesów w kontenerze parsera zabija też sesje `docker compose exec parser …` (diagnostyka).

## Znane ograniczenia

- RAR: brak automatycznego testu prawdziwego archiwum RAR (nie mamy narzędzia do jego utworzenia);
  w Dockerze jest `unar`, lokalnie `unrar`.
- Limity: 1000 plików na archiwum, 1000 części na wiadomość, 500 linków, 20 haseł, QR z max 20 obrazów ≤ 20 Mpx.
- Hasła do archiwów wykrywane tylko w formie z separatorem („Hasło: X”, „password=X”).
- Porównanie domen (podszywanie, niezgodne linki) bez pełnej listy Public Suffix.

## Następna sesja

- Następny: etapy 6–7 — integracja z RTIR (link z ticketu, pobieranie załącznika przez REST2,
  raport jako Comment, Custom Fields). Potem Joe Sandbox (sekcja „ODŁOŻONE” poniżej).
- Do decyzji / drobne poprawki zgłoszone 2026-10-26:
  - Fałszywy IOC z tekstu linku: adres widoczny jako tekst `<a>` (np. „https://www.pko.pl/weryfikacja”)
    trafia do IOC, choć prawdziwy cel jest inny — do raportu RTIR trafiłaby domena banku.
    Propozycja: tekst linku pokazywać w sekcji Linki, ale nie dodawać do IOC.
  - Podgląd HTML: (1) zachować wygląd przycisków (kolory/tło z `<a>` na zastępczy `<span>`),
    (2) w miejscu zablokowanego zewnętrznego obrazka ramka z jego domeną (podpowiedź IOC).
  - Odłożone drobiazgi z przeglądu etapu 4: kolizje łańcuchów ponowień (podwójny „Odśwież” = 2× limit),
    odpytywanie zwija otwarty wiersz szczegółów, przyszła `creation_date` → „-3 dni”, nazwy/tagi z GTI
    nierozbrajane, `httpx.InvalidURL` w workerze, brak sprzątania tabeli `Wzbogacenie`.
- Plik demonstracyjny „wszystko na czerwono”: `/home/kali/Desktop/fifi/czerwony.eml` (poza repo, EICAR).

### DECYZJA 2026-10-27: do Joe wysyłamy CAŁY mail (.eml/.msg), nie pojedyncze pliki

- Joe sam otwiera załączniki i linki z maila, więc nie trzeba wyodrębniać plików ani przechowywać bajtów.
- Przepływ docelowy: analityk klika „Analizuj w JOE” (wyróżniona pozycja w menu analizy) → web zleca
  zadanie → worker pobiera oryginał z RTIR (ręczny upload: prośba o ponowne wgranie, weryfikacja SHA256)
  → worker wysyła plik do Joe kluczem analityka (bez parsowania) → link do Live Interaction.
- Do czasu integracji „Analizuj w JOE” otwiera tylko stronę Joe Sandbox. Kolumna JOE w tabeli IOC usunięta.
- Do sprawdzenia przy integracji: czy konto Joe Pro przyjmuje .eml/.msg jako próbkę.

### ODŁOŻONE: Joe Sandbox — robimy na samym końcu projektu (decyzja 2026-10-26)

- Pełna integracja z Joe (lookup po hashu, wysyłka pliku/URL-a kluczem użytkownika, Live Interaction,
  klucz Joe w profilu) przesunięta na koniec, po RTIR. Powód: brak dobrego rozwiązania dla bajtów
  załączników (poniżej).
- Do tego czasu w aplikacji przycisk JOE jest **zwykłym linkiem** otwierającym stronę Joe Sandbox
  w nowej karcie — bez wysyłania czegokolwiek i bez API.
- Wracając do tematu: przeczytać tę sekcję, sekcję poniżej oraz spec §5 pkt 4 i §6 (`ZgloszenieJoe`).

### Do decyzji przy integracji Joe Sandbox: skąd wziąć bajty załącznika

Załączniki żyją tylko w RAM przez czas jednego żądania; w bazie są hashe i metadane, nie zawartość.
Przycisk JOE klikany jest później, w osobnym żądaniu — bajtów już nie ma.

- Analizy z RTIR: po kliknięciu JOE pobrać plik ponownie z RTIR (REST2), sparsować i wybrać
  załącznik po SHA256. Zgodne ze specyfikacją („źródłem prawdy zostaje RTIR”).
- Ręczny upload: do wyboru — (a) poprosić o ponowne wgranie pliku przy kliknięciu JOE,
  (b) trzymać oryginał krótko (np. 24 h), zaszyfrowany, w bazie lub Redisie.
- Rekomendacja: RTIR → ponowne pobranie; ręczny upload → (a), żeby nigdzie nie przechowywać załączników.

## Odłożone drobiazgi z przeglądu

- Lista analiz ładuje cały JSON wyniku (wydajność przy wielu obrazkach inline).
- URL z prywatnym hostem IPv6 trafia do IOC.
- Deduplikacja nie jest atomowa przy dwóch równoczesnych uploadach.
- CSP podglądu bez dyrektywy `sandbox` (ochrona przy bezpośrednim otwarciu `/podglad/`).
