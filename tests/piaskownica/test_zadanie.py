import json
import os
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
PROBKI = REPO / "tests" / "samples"
GB = 1024**3


def uruchom(dane: bytes, *argumenty: str, hak: str | None = None, tryb_testowy: bool = True):
    env = {"PATH": os.environ["PATH"]}
    if tryb_testowy:
        env["PIASKOWNICA_TRYB_TESTOWY"] = "1"
    if hak:
        env["PIASKOWNICA_TEST"] = hak
    return subprocess.run(
        [sys.executable, "-E", "-s", "-m", "piaskownica.zadanie", "--nazwa", "a.eml", *argumenty],
        input=dane, capture_output=True, timeout=90, cwd=REPO, env=env,
    )


def oczekiwane_ioc(nazwa):
    return {tuple(x) for x in json.loads((PROBKI / f"{nazwa}.expected.json").read_text())["ioc"]}


def ioc_z_wyniku(wynik):
    return {("plik", i["etykieta"]) if i["typ"] == "plik" else (i["typ"], i["wartosc"]) for i in wynik["ioc"]}


def test_korpus_przez_proces():
    for nazwa in ("phishing_klasyczny", "zip_aes_haslo_w_tresci"):
        p = uruchom((PROBKI / f"{nazwa}.eml").read_bytes())
        assert p.returncode == 0, p.stderr.decode()[-500:]
        odp = json.loads(p.stdout)
        assert odp["status"] == "ok"
        assert ioc_z_wyniku(odp["wynik"]) == oczekiwane_ioc(nazwa)


def test_nieobslugiwany():
    p = uruchom(b"\x89PNG\r\n\x1a\n\x00\x00")
    assert json.loads(p.stdout) == {"status": "przerwana", "powod": "nieobslugiwany"}


def test_za_duzy():
    p = uruchom((PROBKI / "zip_exe.eml").read_bytes(), "--max-rozmiar", "10")
    assert json.loads(p.stdout) == {"status": "przerwana", "powod": "za_duzy"}


def test_ignorowane_domeny():
    p = uruchom((PROBKI / "zip_exe.eml").read_bytes(), "--ignorowane", "evil.example")
    assert not any(i["typ"] == "domena" for i in json.loads(p.stdout)["wynik"]["ioc"])


def test_limity_ustawione():
    p = uruchom(b"", hak="limity")
    limity = json.loads(p.stdout)
    assert limity == {"AS": [GB, GB], "CPU": [30, 31], "NOFILE": [64, 64],
                      "FSIZE": [300 * 1024**2, 300 * 1024**2], "CORE": [0, 0]}


def test_pamiec():
    p = uruchom(b"", hak="pamiec")
    assert p.returncode == 3 and p.stdout == b""


def test_haki_wylaczone_bez_trybu_testowego():
    p = uruchom((PROBKI / "zip_exe.eml").read_bytes(), hak="abort", tryb_testowy=False)
    assert p.returncode == 0 and json.loads(p.stdout)["status"] == "ok"


def test_obrazki_w_wyniku():
    p = uruchom((PROBKI / "qr_inline.eml").read_bytes())
    wynik = json.loads(p.stdout)["wynik"]
    assert wynik["wiadomosc"]["obrazki"][0]["status"] == "przekodowany"
    assert "data:image/png;base64," in wynik["wiadomosc"]["html_bezpieczny"]
