import base64

import pytest
import respx

from integracje.gti import GUI, KlientGTI, id_url, skrot_gti

BAZA = "https://www.virustotal.com/api/v3"
EICAR = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def podepnij(nagranie, sciezka, nazwa):
    status, cialo = nagranie(nazwa)
    return respx.get(f"{BAZA}{sciezka}").respond(status, json=cialo)


@respx.mock
def test_eicar(nagranie):
    podepnij(nagranie, f"/files/{EICAR}", "gti_plik_eicar")
    w = KlientGTI("k").sprawdz("plik", EICAR)
    assert w.status == "gotowe"
    assert w.skrot["werdykt"] == "zlosliwy"
    assert w.skrot["ocena"] == 30
    assert w.skrot["wykrycia"] == [64, 67]
    assert w.link == f"{GUI}/file/{EICAR}"


@respx.mock
def test_nieznany_hash(nagranie):
    h = "0" * 63 + "1"
    podepnij(nagranie, f"/files/{h}", "gti_plik_nieznany")
    w = KlientGTI("k").sprawdz("plik", h)
    assert w.status == "brak_danych" and w.link == f"{GUI}/file/{h}"


@respx.mock
def test_domena_google(nagranie):
    podepnij(nagranie, "/domains/google.com", "gti_domena_google")
    s = KlientGTI("k").sprawdz("domena", "google.com").skrot
    assert s["werdykt"] == "nieszkodliwy"
    assert s["utworzono"] == 874306800
    assert s["rejestrator"] == "MarkMonitor Inc."


@respx.mock
def test_ip(nagranie):
    podepnij(nagranie, "/ip_addresses/8.8.8.8", "gti_ip_8888")
    w = KlientGTI("k").sprawdz("ip", "8.8.8.8")
    assert (w.skrot["kraj"], w.skrot["asn"], w.skrot["wlasciciel"]) == ("US", 15169, "Google LLC")
    assert w.link == f"{GUI}/ip-address/8.8.8.8"


@respx.mock
def test_url_id_i_link(nagranie):
    assert id_url("https://www.google.com/") == "aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbS8"
    trasa = podepnij(nagranie, "/urls/aHR0cHM6Ly93d3cuZ29vZ2xlLmNvbS8", "gti_url_google")
    w = KlientGTI("k").sprawdz("url", "https://www.google.com/")
    assert trasa.called and w.status == "gotowe"
    assert w.link.startswith(f"{GUI}/url/")


def test_url_unicode():
    wynik = id_url("https://zażółć.pl/ą")
    dopelnienie = "=" * (-len(wynik) % 4)
    assert base64.urlsafe_b64decode(wynik + dopelnienie).decode("utf-8") == "https://zażółć.pl/ą"


@respx.mock
def test_naglowki(nagranie):
    podepnij(nagranie, "/ip_addresses/8.8.8.8", "gti_ip_8888")
    KlientGTI("klucz-testowy").sprawdz("ip", "8.8.8.8")
    h = respx.calls.last.request.headers
    assert h["x-apikey"] == "klucz-testowy"
    assert h["x-tool"] == "miemli"


def test_skrot_niepelny():
    s = skrot_gti({"data": {"attributes": {}}})
    assert s["werdykt"] == "niewykryty"
    assert s["ocena"] is None and s["wykrycia"] is None


def test_zly_typ():
    with pytest.raises(ValueError):
        KlientGTI("k").sprawdz("email", "a@b.pl")
