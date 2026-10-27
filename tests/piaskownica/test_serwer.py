import json
import logging
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from piaskownica import serwer

PROBKI = Path(__file__).resolve().parents[1] / "samples"


@pytest.fixture
def adres(monkeypatch):
    monkeypatch.setenv("PIASKOWNICA_TRYB_TESTOWY", "1")
    monkeypatch.delenv("PIASKOWNICA_TEST", raising=False)
    srv = serwer.utworz_serwer("127.0.0.1", 0)
    watek = threading.Thread(target=srv.serve_forever, daemon=True)
    watek.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def wyslij(adres, dane: bytes, nazwa="a.eml"):
    zadanie = urllib.request.Request(f"{adres}/analizuj", data=dane, method="POST",
                                     headers={"X-Miemli-Nazwa": nazwa})
    try:
        with urllib.request.urlopen(zadanie, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, None


def test_analizuj_ok(adres):
    status, odp = wyslij(adres, (PROBKI / "zip_exe.eml").read_bytes())
    assert status == 200 and odp["status"] == "ok" and odp["wynik"]["ioc"]


def test_czas(adres, monkeypatch):
    monkeypatch.setattr(serwer, "CZAS", 3)
    monkeypatch.setenv("PIASKOWNICA_TEST", "petla")
    start = time.monotonic()
    assert wyslij(adres, b"x") == (200, {"status": "przerwana", "powod": "czas"})
    assert time.monotonic() - start < 10


@pytest.mark.parametrize("hak,powod", [("abort", "awaria"), ("polowa", "awaria"), ("pamiec", "pamiec")])
def test_awarie(adres, monkeypatch, hak, powod):
    monkeypatch.setenv("PIASKOWNICA_TEST", hak)
    assert wyslij(adres, b"x") == (200, {"status": "przerwana", "powod": powod})


def test_kolejka_503(adres, monkeypatch):
    monkeypatch.setattr(serwer, "ROWNOLEGLE", 1)
    monkeypatch.setattr(serwer, "KOLEJKA", 1)
    monkeypatch.setattr(serwer, "CZAS", 4)
    monkeypatch.setenv("PIASKOWNICA_TEST", "petla")
    srv_adres = adres
    wyniki = []
    watki = [threading.Thread(target=lambda: wyniki.append(wyslij(srv_adres, b"x")[0])) for _ in range(3)]
    for w in watki:
        w.start()
        time.sleep(0.2)
    for w in watki:
        w.join()
    assert 503 in wyniki


def test_413(adres, monkeypatch):
    monkeypatch.setattr(serwer, "MAKS_ZADANIE", 1000)
    assert wyslij(adres, b"x" * 2000)[0] == 413


def test_404(adres):
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(f"{adres}/inne", timeout=5)
    assert e.value.code == 404


def test_zdrowie(adres, monkeypatch):
    monkeypatch.setattr(serwer, "w_gvisor", lambda: False)
    with urllib.request.urlopen(f"{adres}/zdrowie", timeout=5) as r:
        assert json.loads(r.read()) == {"gvisor": False, "wersja": "1"}


def test_log_bez_nazw_i_tresci(adres, caplog):
    caplog.set_level(logging.DEBUG)
    wyslij(adres, (PROBKI / "zip_exe.eml").read_bytes(), nazwa="faktura_tajna.eml")
    tekst = caplog.text
    assert "sha256=" in tekst
    assert "faktura" not in tekst and "Faktura" not in tekst and "evil" not in tekst
