# miemli — etap A: werdykt, hasło, audyt, „Artefakty”, podgląd HTML, poprawki — specyfikacja

Data: 2026-10-29
Status: zatwierdzona w rozmowie (dwie sekcje), do przeglądu pliku
Rozszerza: `docs/superpowers/specs/2026-10-26-miemli-design.md` i późniejsze specyfikacje.

Plan rozbudowy (2026-10-29): etap A (ten dokument) → etap B: oś czasu nagłówków + wyszukiwarka
analiz → etap C: proxy wychodzące workera (tinyproxy; zmierzony koszt: ~2–5 MB RAM). RTIR — później.

## 1. Werdykt analityka

- Ekran analizy, pasek górny: przełącznik werdyktu `—` (brak) / phishing / spam / czysty /
  do weryfikacji (wartości modelu `Analiza.WERDYKTY` + pusty). Zmiana zapisywana od razu (htmx, bez
  przeładowania strony); `Zdarzenie(typ="werdykt", szczegoly={"z": stary, "na": nowy})`.
- Ustawić może każdy zalogowany analityk; ostatnia zmiana wygrywa.
- Lista analiz: kolumna „Werdykt” z odznaką (`phishing` → `bad`, `spam` → `warn`, `czysty` → `ok`,
  `do_weryfikacji` → `neutral`, brak → „—”) oraz filtr nad tabelą: Wszystkie / Bez werdyktu / Phishing /
  Spam / Czysty / Do weryfikacji (`?werdykt=` z wartościami `brak` i kodami werdyktów; nieznana
  wartość = wszystkie).

## 2. Zmiana hasła

- Profil (`/profil/`): sekcja „Zmiana hasła” — obecne hasło, nowe hasło, powtórzenie; walidatory
  z `AUTH_PASSWORD_VALIDATORS` (min. 12 znaków, podobieństwo do loginu, popularne hasła).
- Po zmianie: bieżąca sesja zostaje (`update_session_auth_hash`), pozostałe sesje konta tracą ważność;
  komunikat „Hasło zostało zmienione.”; `Zdarzenie(typ="haslo_zmienione")` bez treści haseł.
- Pola haseł ukryte w raportach błędów (`sensitive_post_parameters`).

## 3. Audyt (tylko administrator)

- Strona `/audyt/` dostępna tylko dla `is_staff`; dla innych 403 i `logger.warning` (użytkownik, bez
  szczegółów). Link „Audyt” w pasku tylko dla `is_staff`.
- Tabela: czas, użytkownik, typ (po polsku), analiza (link, gdy istnieje), szczegóły.
- Filtry: użytkownik, typ, data od/do. Paginacja po 50, najnowsze pierwsze. Tylko podgląd.
- Opisy typów: `utworzenie` „Utworzenie analizy”, `otwarcie` „Otwarcie analizy”, `odswiezenie`
  „Odświeżenie wzbogacenia”, `notatka` „Zmiana komentarza”, `usuniecie` „Usunięcie analizy”,
  `analiza_przerwana` „Analiza przerwana (sandbox)”, `werdykt` „Zmiana werdyktu”, `joe_wyslanie`
  „Wysyłka do Joe Sandbox”, `joe_klucz_ustawiony` „Ustawienie klucza Joe”, `joe_klucz_usuniety`
  „Usunięcie klucza Joe”, `haslo_zmienione` „Zmiana hasła”; nieznany typ — surowy kod.

## 4. „IOC” → „Artefakty”

Wyłącznie w interfejsie (menu sekcji, nagłówek sekcji, panel boczny, komunikaty pustej listy, dymek
przycisku „Odśwież”, nazwy w panelu admina). Kod, modele, URL-e i baza bez zmian.

## 5. Podgląd HTML (osobny commit, łatwy do wycofania)

- `<a>` → `<span class="link">` zachowuje atrybut `style` (przez istniejącą allowlistę właściwości CSS
  nh3); nadal brak `href`, dymek z rozbrojonym adresem.
- `<img>` z `src` `http(s)://…` → `<span class="obraz-zewnetrzny">[obraz zewnętrzny: <host rozbrojony>]</span>`
  — tylko host, bez ścieżki i parametrów. Inne `src` (niebędące `cid:`) — usuwane jak dotąd.
- Szablon podglądu: styl `.obraz-zewnetrzny` (ramka przerywana jak `.obrazek-pominiety`).

## 6. Poprawki z przeglądów

1. `Analiza.temat_wiadomosci` (CharField 500, puste dozwolone) wypełniane przy tworzeniu i migracją
   danych dla istniejących analiz; lista analiz nie ładuje pola `wynik`.
2. Odpytywanie co 2 s zachowuje otwarte wiersze szczegółów artefaktów (po podmianie tabeli otwarte
   wiersze są ponownie rozwijane).
3. `wiek` / `nowa_domena`: data z przyszłości → brak wieku, brak ostrzeżenia „nowa domena”.
4. Nazwy plików i tagi z GTI w szczegółach — rozbrojone (`http`→`hxxp`, kropki w nazwach
   domenopodobnych → `[.]`).
5. URL do niepublicznego adresu IPv6 nie jest artefaktem (jak IPv4).
6. `httpx.InvalidURL` (i inne błędy budowy żądania) w kliencie → status `blad` „Nieprawidłowy adres.”,
   bez wyjątku w workerze.
7. Joe: odpowiedź „Klucz Joe odrzucony” podczas wysyłki/śledzenia → `joe_klucz_stan="odrzucony"`.
8. Joe: łączny limit czasu odpowiedzi (wysyłka 120 s, pozostałe 40 s) → `niedostepny`, ponawialne.
9. Parser: zabicie procesu `SIGKILL` bez przekroczenia czasu (OOM) → `pamiec`, nie `czas`.
10. Walidacja odpowiedzi parsera obejmuje drzewo `wiadomosc` (typy pól, głębokość ≤ 10)
    i `analiza` (słownik słowników z listami `received`, `sygnaly`, `linki`).
11. Test nagrań zdejmuje cudzysłowy z wartości w `.env`.

Odłożone: wyścig przy równoczesnych uploadach, sprzątanie `Wzbogacenie`, kolizje ponowień, limit
prób logowania.

## 7. Testy

TDD dla każdego punktu; weryfikacja w przeglądarce: werdykt i filtr listy, zmiana hasła (druga sesja
wylogowana), audyt z konta admina i zwykłego, podgląd maila DHL (przycisk, ramka obrazu); końcowy
przegląd całej gałęzi.
