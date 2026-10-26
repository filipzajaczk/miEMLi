import respx

from integracje.censys import KlientCensys

BAZA = "https://api.platform.censys.io/v3/global/asset/host"


def podepnij(nagranie, ip, nazwa):
    status, cialo = nagranie(nazwa)
    return respx.get(f"{BAZA}/{ip}").respond(status, json=cialo)


@respx.mock
def test_8888(nagranie):
    podepnij(nagranie, "8.8.8.8", "censys_8888")
    w = KlientCensys("t").sprawdz_ip("8.8.8.8")
    assert w.status == "gotowe"
    assert [53, "DNS", "tcp"] in w.skrot["uslugi"]
    assert [443, "HTTP", "tcp"] in w.skrot["uslugi"]
    assert w.skrot["uslugi"] == sorted(w.skrot["uslugi"], key=lambda u: u[0])
    assert w.skrot["asn"] == 15169 and w.skrot["kraj"] == "US"
    assert w.skrot["bgp"] == "8.8.8.0/24"
    assert w.link == "https://platform.censys.io/hosts/8.8.8.8"


@respx.mock
def test_brak_uslug(nagranie):
    podepnij(nagranie, "192.0.2.1", "censys_testnet")
    w = KlientCensys("t").sprawdz_ip("192.0.2.1")
    assert w.status == "gotowe" and w.skrot["uslugi"] == []
    assert len(w.skrot["dns"]) <= 10


@respx.mock
def test_bez_organizacji(nagranie):
    podepnij(nagranie, "8.8.8.8", "censys_8888")
    KlientCensys("t").sprawdz_ip("8.8.8.8")
    assert "organization_id" not in str(respx.calls.last.request.url)


@respx.mock
def test_z_organizacja(nagranie):
    podepnij(nagranie, "8.8.8.8", "censys_8888")
    KlientCensys("t", "org1").sprawdz_ip("8.8.8.8")
    assert respx.calls.last.request.url.params["organization_id"] == "org1"


@respx.mock
def test_naglowki(nagranie):
    podepnij(nagranie, "8.8.8.8", "censys_8888")
    KlientCensys("t").sprawdz_ip("8.8.8.8")
    h = respx.calls.last.request.headers
    assert h["Authorization"] == "Bearer t"
    assert h["User-Agent"] == "miemli/1.0"


@respx.mock
def test_403_org(nagranie):
    podepnij(nagranie, "8.8.8.8", "censys_403_org")
    w = KlientCensys("t", "org1").sprawdz_ip("8.8.8.8")
    assert w.status == "blad" and w.ponawiac is False
