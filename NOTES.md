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
- Testy: 130 (pytest). Próbka `.msg` jest prywatna (`tests/samples/private/`) — na innej maszynie testy `.msg` są pomijane.

## Znane ograniczenia

- RAR: brak automatycznego testu prawdziwego archiwum RAR (nie mamy narzędzia do jego utworzenia);
  w Dockerze jest `unar`, lokalnie `unrar`.
- Hasła do archiwów wykrywane tylko w formie z separatorem („Hasło: X”, „password=X”).
- Porównanie domen (podszywanie, niezgodne linki) bez pełnej listy Public Suffix.

## Następna sesja

- Plan etapów 4–5: GTI, Censys, Joe Sandbox (worker RQ, cache 24 h, dociąganie wyników przez htmx,
  klucz Joe w profilu użytkownika). Najpierw sprawdzić realne odpowiedzi API.
- Potem etapy 6–7: integracja z RTIR (link z ticketu, raport jako Comment, Custom Fields).
