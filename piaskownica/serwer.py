"""Serwer sandboxa: przyjmuje plik, analizuje go w świeżym procesie potomnym z limitami, zwraca JSON.

Loguje wyłącznie SHA256, rozmiar, czas, status i powód — nigdy nazw plików ani treści.
"""

import hashlib
import json
import logging
import os
import signal
import subprocess
import sys
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
KATALOG_APLIKACJI = Path(__file__).resolve().parent.parent
PRZEKAZYWANE_ZMIENNE = ("PATH", "PIASKOWNICA_TRYB_TESTOWY", "PIASKOWNICA_TEST")


def _srodowisko_procesu() -> dict[str, str]:
    return {k: os.environ[k] for k in PRZEKAZYWANE_ZMIENNE if k in os.environ}


def uruchom_proces(dane: bytes, nazwa: str, ignorowane: str, max_rozmiar: int) -> dict:
    przerwana = lambda powod: {"status": "przerwana", "powod": powod}  # noqa: E731
    try:
        p = subprocess.run(
            [sys.executable, "-E", "-s", "-m", "piaskownica.zadanie", "--nazwa", nazwa,
             "--ignorowane", ignorowane, "--max-rozmiar", str(max_rozmiar)],
            input=dane, capture_output=True, timeout=CZAS, cwd=KATALOG_APLIKACJI, env=_srodowisko_procesu(),
        )
    except subprocess.TimeoutExpired:
        return przerwana("czas")
    if p.returncode in (-signal.SIGXCPU, -signal.SIGKILL):
        return przerwana("czas")
    if p.returncode == KOD_PAMIEC:
        return przerwana("pamiec")
    if p.returncode != 0:
        return przerwana("awaria")
    try:
        odpowiedz = json.loads(p.stdout)
    except ValueError:
        return przerwana("awaria")
    return odpowiedz if isinstance(odpowiedz, dict) else przerwana("awaria")


class _Obsluga(BaseHTTPRequestHandler):
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
