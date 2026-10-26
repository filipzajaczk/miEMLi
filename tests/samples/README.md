# Próbki testowe

Każda próbka to plik `.eml` lub `.msg` oraz obok `<ta sama nazwa>.expected.json`:

```json
{
  "ioc": [["typ", "wartosc"], ["plik", "nazwa_pliku.exe"]],
  "uwierzytelnienie": {"spf": "fail", "dkim": "pass", "dmarc": "fail"},
  "sygnaly": ["REPLY_TO_INNA_DOMENA"],
  "ostrzezenia": ["KODOWANIE"]
}
```

- `ioc` — dokładny zbiór (wykrywa szum). Pliki porównywane po nazwie, reszta po wartości.
- `uwierzytelnienie`, `sygnaly` — dla wiadomości głównej; `ostrzezenia` — ze wszystkich poziomów.
- Brak klucza = nie sprawdzaj.
- Oczekiwania wpisuj na podstawie zawartości próbki, **nie** kopiuj wyniku analizatora.

Syntetyczne próbki generuje `generuj_probki.py` (fikcyjne domeny `.example`).

**Prawdziwe zgłoszenia** (dane osób, firmy) wrzucaj wyłącznie do `private/` — katalog jest w
`.gitignore` i nigdy nie trafia do repo. Test korpusu i testy `.msg` biorą je pod uwagę lokalnie.
