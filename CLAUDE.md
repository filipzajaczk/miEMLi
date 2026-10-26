# miemli

Projekt jednoosobowy. Opis projektu: do uzupełnienia.

## Środowisko

- Kali Linux, Python 3.14. Systemowy pip jest zablokowany (PEP 668), więc pakiety instalujemy tylko w venv:
  ```bash
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -r requirements.txt
  ```
- GitHub przez SSH (`git@github.com:...`). `gh` CLI nie jest dostępne w repo Kali.

## Zasady

- Sekrety (np. klucz API VirusTotal) tylko w `.env` lub zmiennych środowiskowych, nigdy w kodzie ani w commitach.
- `.venv/`, `__pycache__/` i `.env` muszą być w `.gitignore`.
- Praca na `main`; osobny branch tylko dla większych lub ryzykownych zmian, potem `git merge` bez PR.
- Małe commity z opisowymi wiadomościami; push na koniec każdej sesji.
- Postęp i plan na kolejną sesję zapisujemy w `NOTES.md`.
