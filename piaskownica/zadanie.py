"""Proces potomny analizujący JEDEN plik: stdin = bajty, stdout = JSON. Uruchamiany przez serwer
dla każdego pliku osobno (python -E -s -m piaskownica.zadanie), z twardymi limitami systemowymi
ustawionymi przed załadowaniem jakiejkolwiek biblioteki parsującej."""

import argparse
import json
import os
import resource
import sys
from urllib.parse import unquote

MB = 1024 * 1024
LIMITY = {
    "AS": (1024 * MB, 1024 * MB),  # pamięć adresowa
    "CPU": (30, 31),  # sekundy CPU: miękki → SIGXCPU, twardy → SIGKILL
    "NOFILE": (64, 64),
    "FSIZE": (300 * MB, 300 * MB),  # zapis plików (RAR w /tmp)
    "CORE": (0, 0),
}
KOD_PAMIEC = 3
KOD_BLAD = 4


def niezrzucalny() -> None:
    """PR_SET_DUMPABLE=0: inne procesy tego samego UID nie mogą się podpiąć (ptrace)
    ani czytać /proc/<pid>/fd tego procesu."""
    import ctypes

    ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE


def ustaw_limity() -> None:
    for nazwa, (miekki, twardy) in LIMITY.items():
        resource.setrlimit(getattr(resource, f"RLIMIT_{nazwa}"), (miekki, twardy))


def analizuj_plik(dane: bytes, nazwa: str, ignorowane: frozenset[str] = frozenset(),
                  max_rozmiar: int = 50 * MB) -> dict:
    # import dopiero tutaj: w procesie potomnym limity są już ustawione
    from mailcore.analiza import analizuj
    from mailcore.model import Limity, NieobslugiwanyPlik, PlikZaDuzy
    from mailcore.parsuj import parsuj
    from mailcore.serializacja import do_json

    from .obrazki import przetworz_obrazki

    try:
        w = parsuj(dane, nazwa, Limity(max_rozmiar=max_rozmiar))
    except NieobslugiwanyPlik:
        return {"status": "przerwana", "powod": "nieobslugiwany"}
    except PlikZaDuzy:
        return {"status": "przerwana", "powod": "za_duzy"}
    wynik = analizuj(w, ignorowane)
    return {"status": "ok", "wynik": do_json(w, wynik, przetworz_obrazki(w))}


def _hak_testowy(hak: str) -> None:
    """Wymuszenie awarii w testach — działa wyłącznie przy PIASKOWNICA_TRYB_TESTOWY=1."""
    if hak == "limity":
        print(json.dumps({n: list(resource.getrlimit(getattr(resource, f"RLIMIT_{n}"))) for n in LIMITY}))
        sys.stdout.flush()
        os._exit(0)
    if hak == "pamiec":
        bytearray(2 * 1024 * MB)
    if hak == "abort":
        os.abort()
    if hak == "petla":
        while True:
            pass
    if hak == "demon":  # proces, który próbuje przeżyć zadanie
        pid = os.fork()
        if pid == 0:
            with open(os.environ["PIASKOWNICA_TEST_PLIK"], "w") as f:
                f.write(str(os.getpid()))
            import time
            time.sleep(60)
            os._exit(0)
        return
    if hak == "tmp":
        import tempfile
        with open(os.path.join(tempfile.gettempdir(), "pozostalosc.bin"), "wb") as f:
            f.write(b"x" * 1024)
        return
    if hak == "zalew":
        while True:
            sys.stdout.write("x" * 65536)
    if hak == "zagniezdzony":
        sys.stdout.write("[" * 100000 + "]" * 100000)
        sys.stdout.flush()
        os._exit(0)
    if hak == "dumpable":
        import ctypes
        print(json.dumps({"dumpable": ctypes.CDLL(None).prctl(3, 0, 0, 0, 0)}))  # PR_GET_DUMPABLE
        sys.stdout.flush()
        os._exit(0)
    if hak == "polowa":
        sys.stdout.write('{"status": "ok", "wyn')
        sys.stdout.flush()
        os._exit(0)


def main(argv: list[str] | None = None) -> int:
    niezrzucalny()
    ustaw_limity()
    parser = argparse.ArgumentParser()
    parser.add_argument("--nazwa", default="plik")
    parser.add_argument("--ignorowane", default="")
    parser.add_argument("--max-rozmiar", type=int, default=50 * MB)
    args = parser.parse_args(argv)
    hak = os.environ.get("PIASKOWNICA_TEST") if os.environ.get("PIASKOWNICA_TRYB_TESTOWY") == "1" else None
    try:
        dane = sys.stdin.buffer.read()
        if hak:
            _hak_testowy(hak)
        ignorowane = frozenset(d.strip().lower() for d in args.ignorowane.split(",") if d.strip())
        odpowiedz = analizuj_plik(dane, unquote(args.nazwa), ignorowane, args.max_rozmiar)
    except MemoryError:
        return KOD_PAMIEC
    except Exception:
        return KOD_BLAD
    sys.stdout.write(json.dumps(odpowiedz))
    return 0


if __name__ == "__main__":
    sys.exit(main())
