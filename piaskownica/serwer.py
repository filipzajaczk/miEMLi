"""Serwer sandboxa: przyjmuje plik, analizuje go w świeżym procesie potomnym z limitami, zwraca JSON.

Loguje wyłącznie SHA256, rozmiar, czas, status i powód — nigdy nazw plików ani treści.
"""

import ctypes
import hashlib
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .gvisor import w_gvisor
from .zadanie import KOD_PAMIEC

logger = logging.getLogger("piaskownica")

ROWNOLEGLE = 2
KOLEJKA = 8
MAKS_ZADANIE = 55 * 1024 * 1024
CZAS = 60  # sekundy czasu rzeczywistego na jeden plik
MAKS_WYJSCIE = 25 * 1024 * 1024  # odpowiedź procesu potomnego
KATALOG_TMP = tempfile.gettempdir()  # w każdym zadaniu osobny podkatalog, usuwany po zakończeniu
_AKTYWNE: set[int] = set()  # pid (= sesja) trwających procesów potomnych
_AKTYWNE_BLOKADA = threading.Lock()
KATALOG_APLIKACJI = Path(__file__).resolve().parent.parent
PRZEKAZYWANE_ZMIENNE = ("PATH", "PIASKOWNICA_TRYB_TESTOWY", "PIASKOWNICA_TEST")


def _srodowisko_procesu() -> dict[str, str]:
    return {k: os.environ[k] for k in PRZEKAZYWANE_ZMIENNE if k in os.environ}


def _procesy() -> dict[int, int]:
    """pid → identyfikator sesji, z /proc."""
    wynik = {}
    for wpis in os.listdir("/proc"):
        if not wpis.isdigit():
            continue
        try:
            with open(f"/proc/{wpis}/stat") as f:
                pola = f.read().rsplit(")", 1)[1].split()
            wynik[int(wpis)] = int(pola[3])
        except (OSError, IndexError, ValueError):
            continue
    return wynik


def _zabij(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _sprzatnij(procesy: dict[int, int], aktywne_sesje: set[int], zabij=_zabij, jestem_pid1: bool = False,
               sesja_zadania: int | None = None) -> None:
    """Po zadaniu nie może przeżyć żaden proces potomny (np. „demon” przejętego procesu).
    W kontenerze (serwer = PID 1) zabijamy wszystko poza sobą i sesjami trwających zadań — także procesy,
    które uciekły do nowej sesji. Poza kontenerem (testy) tylko sesję zakończonego zadania."""
    for pid, sesja in procesy.items():
        if pid == 1 or pid == os.getpid():
            continue
        if jestem_pid1 and sesja not in aktywne_sesje:
            zabij(pid)
        elif not jestem_pid1 and sesja_zadania is not None and sesja == sesja_zadania:
            zabij(pid)


def _uruchom(dane: bytes, argumenty: list[str], katalog_tmp: str) -> tuple[int | None, bytes, bool, bool]:
    """Zwraca (kod wyjścia, wyjście, przekroczony czas, przekroczony rozmiar wyjścia)."""
    srodowisko = _srodowisko_procesu() | {"TMPDIR": katalog_tmp}
    p = subprocess.Popen(
        [sys.executable, "-E", "-s", "-m", "piaskownica.zadanie", *argumenty],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        cwd=KATALOG_APLIKACJI, env=srodowisko, start_new_session=True,
    )
    with _AKTYWNE_BLOKADA:
        _AKTYWNE.add(p.pid)
    bufor = bytearray()
    za_duzo = threading.Event()

    def ubij():
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass

    def pisz():
        try:
            p.stdin.write(dane)
            p.stdin.close()
        except OSError:
            pass

    def czytaj():
        while kawalek := p.stdout.read1(65536):
            bufor.extend(kawalek)
            if len(bufor) > MAKS_WYJSCIE:
                za_duzo.set()
                ubij()
                return

    threading.Thread(target=pisz, daemon=True).start()
    czytnik = threading.Thread(target=czytaj, daemon=True)
    czytnik.start()
    przekroczony = False
    try:
        p.wait(timeout=CZAS)
    except subprocess.TimeoutExpired:
        przekroczony = True
        ubij()
        p.wait()
    finally:
        with _AKTYWNE_BLOKADA:
            _AKTYWNE.discard(p.pid)
            aktywne = set(_AKTYWNE)
        czytnik.join(timeout=2)  # „demon” może trzymać otwarte stdout — nie czekamy na niego
        _sprzatnij(_procesy(), aktywne, jestem_pid1=os.getpid() == 1, sesja_zadania=p.pid)
    return p.returncode, bytes(bufor[:MAKS_WYJSCIE]), przekroczony, za_duzo.is_set()


def uruchom_proces(dane: bytes, nazwa: str, ignorowane: str, max_rozmiar: int) -> dict:
    przerwana = lambda powod: {"status": "przerwana", "powod": powod}  # noqa: E731
    katalog_tmp = tempfile.mkdtemp(prefix="zadanie-", dir=KATALOG_TMP)
    try:
        kod, wyjscie, czas, za_duzo = _uruchom(
            dane, [f"--nazwa={nazwa}", f"--ignorowane={ignorowane}", f"--max-rozmiar={max_rozmiar}"], katalog_tmp)
    finally:
        shutil.rmtree(katalog_tmp, ignore_errors=True)
    if czas or kod in (-signal.SIGXCPU, -signal.SIGKILL) and not za_duzo:
        return przerwana("czas")
    if za_duzo:
        return przerwana("awaria")
    if kod == KOD_PAMIEC:
        return przerwana("pamiec")
    if kod != 0:
        return przerwana("awaria")
    try:
        odpowiedz = json.loads(wyjscie)
    except (ValueError, RecursionError):
        return przerwana("awaria")
    return odpowiedz if isinstance(odpowiedz, dict) else przerwana("awaria")


class _Obsluga(BaseHTTPRequestHandler):
    timeout = 30  # wolny nadawca nie zajmie miejsca w kolejce na zawsze
    server_version = "piaskownica"
    sys_version = ""

    def log_message(self, format, *args):  # domyślny log zawierałby ścieżki i adresy — niepotrzebne
        pass

    def _json(self, kod: int, tresc: dict | None = None) -> None:
        dane = json.dumps(tresc or {}).encode()
        self.send_response(kod)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(dane)))
        self.end_headers()
        self.wfile.write(dane)

    def do_GET(self):
        if self.path == "/zdrowie":
            return self._json(200, {"gvisor": w_gvisor(), "wersja": "1"})
        self._json(404)

    def do_POST(self):
        if self.path != "/analizuj":
            return self._json(404)
        dlugosc = int(self.headers.get("Content-Length") or 0)
        if dlugosc > MAKS_ZADANIE:
            self.close_connection = True
            return self._json(413)
        srv = self.server
        with srv.blokada:
            if srv.oczekujace >= KOLEJKA + ROWNOLEGLE:
                return self._json(503)
            srv.oczekujace += 1
        try:
            dane = self.rfile.read(dlugosc)
            with srv.semafor:
                start = time.monotonic()
                odpowiedz = uruchom_proces(
                    dane,
                    self.headers.get("X-Miemli-Nazwa", "plik"),
                    self.headers.get("X-Miemli-Ignorowane", ""),
                    int(self.headers.get("X-Miemli-Max-Rozmiar") or 50 * 1024 * 1024),
                )
                logger.info("analiza sha256=%s rozmiar=%d czas=%.2fs status=%s powod=%s",
                            hashlib.sha256(dane).hexdigest(), len(dane), time.monotonic() - start,
                            odpowiedz.get("status"), odpowiedz.get("powod", "-"))
        finally:
            with srv.blokada:
                srv.oczekujace -= 1
        self._json(200, odpowiedz)


def utworz_serwer(host: str, port: int) -> ThreadingHTTPServer:
    ctypes.CDLL(None, use_errno=True).prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE=0 — bez ptrace z procesów potomnych
    srv = ThreadingHTTPServer((host, port), _Obsluga)
    srv.semafor = threading.BoundedSemaphore(ROWNOLEGLE)
    srv.blokada = threading.Lock()
    srv.oczekujace = 0
    srv.daemon_threads = True
    return srv


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    logger.info("start, gvisor=%s", w_gvisor())
    utworz_serwer("0.0.0.0", 8000).serve_forever()
