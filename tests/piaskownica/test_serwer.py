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


# --- z końcowego przeglądu ---

def test_proces_demon_zabity_po_zadaniu(adres, monkeypatch, tmp_path):
    """Przejęty proces potomny nie może zostawić procesu działającego po zakończeniu zadania."""
    znacznik = tmp_path / "demon.pid"
    monkeypatch.setenv("PIASKOWNICA_TEST", "demon")
    monkeypatch.setenv("PIASKOWNICA_TEST_PLIK", str(znacznik))
    monkeypatch.setattr(serwer, "PRZEKAZYWANE_ZMIENNE", serwer.PRZEKAZYWANE_ZMIENNE + ("PIASKOWNICA_TEST_PLIK",))
    wyslij(adres, b"x")
    pid = int(znacznik.read_text())
    time.sleep(0.3)
    import os
    assert not os.path.exists(f"/proc/{pid}") or open(f"/proc/{pid}/stat").read().split(") ")[1][0] == "Z"


def test_sprzatanie_pid1_zabija_obce_sesje():
    zabite = []
    procesy = {1: 1, 10: 10, 11: 10, 20: 20, 30: 30}  # pid → sesja
    serwer._sprzatnij(procesy, aktywne_sesje={20}, zabij=zabite.append, jestem_pid1=True)
    assert sorted(zabite) == [10, 11, 30]


def test_sprzatanie_poza_kontenerem_tylko_sesja_zadania():
    zabite = []
    procesy = {1: 1, 10: 10, 11: 10, 30: 30}
    serwer._sprzatnij(procesy, aktywne_sesje=set(), zabij=zabite.append, jestem_pid1=False, sesja_zadania=10)
    assert sorted(zabite) == [10, 11]


def test_osobny_tmp_dla_zadania_usuwany(adres, monkeypatch, tmp_path):
    monkeypatch.setattr(serwer, "KATALOG_TMP", str(tmp_path))
    monkeypatch.setenv("PIASKOWNICA_TEST", "tmp")
    wyslij(adres, b"x")
    assert list(tmp_path.iterdir()) == []


def test_zalew_wyjscia_przerwany(adres, monkeypatch):
    monkeypatch.setattr(serwer, "MAKS_WYJSCIE", 1024 * 1024)
    monkeypatch.setenv("PIASKOWNICA_TEST", "zalew")
    assert wyslij(adres, b"x") == (200, {"status": "przerwana", "powod": "awaria"})
    assert wyslij(adres, (PROBKI / "zip_exe.eml").read_bytes())[1]["status"] == "przerwana"  # nadal zalew
    monkeypatch.delenv("PIASKOWNICA_TEST")
    assert wyslij(adres, (PROBKI / "zip_exe.eml").read_bytes())[1]["status"] == "ok"  # serwer żyje


def test_nazwa_z_minusem(adres):
    status, odp = wyslij(adres, (PROBKI / "zip_exe.eml").read_bytes(), nazwa="-faktura.eml")
    assert odp["status"] == "ok"


def test_gleboko_zagniezdzony_json_z_procesu(adres, monkeypatch):
    monkeypatch.setenv("PIASKOWNICA_TEST", "zagniezdzony")
    assert wyslij(adres, b"x") == (200, {"status": "przerwana", "powod": "awaria"})


def test_proces_niezrzucalny(adres, monkeypatch):
    monkeypatch.setenv("PIASKOWNICA_TEST", "dumpable")
    assert wyslij(adres, b"x")[1] == {"dumpable": 0}
