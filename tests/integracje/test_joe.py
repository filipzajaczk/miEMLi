import json

import httpx
import pytest
import respx

from integracje import joe

B = joe.BAZA
KLUCZ = "TajnyKluczJoe1234567890"


def tresc(wywolanie) -> bytes:
    return wywolanie.request.content


@respx.mock
def test_wyslij_parametry():
    trasa = respx.post(f"{B}/v2/submission/new").respond(200, json={"data": {"submission_id": "123"}})
    w = joe.wyslij(KLUCZ, b"From: a@b\r\n\r\nx", "analiza-12.eml", "miemli, analiza #12")
    assert w.status == "ok" and w.dane == {"id_zgloszenia": "123"}
    t = tresc(trasa.calls.last)
    for pole, wartosc in {**joe.PARAMETRY, "apikey": KLUCZ, "comments": "miemli, analiza #12"}.items():
        assert f'name="{pole}"\r\n\r\n{wartosc}\r\n'.encode() in t
    assert b'filename="analiza-12.eml"' in t and b"systems" not in t
    assert all(KLUCZ not in v for v in trasa.calls.last.request.headers.values())


@pytest.mark.parametrize("kod", [401, 403])
@respx.mock
def test_wyslij_odrzucony_klucz(kod):
    respx.post(f"{B}/v2/submission/new").respond(kod)
    w = joe.wyslij(KLUCZ, b"x", "a.eml", "c")
    assert w.status == "odrzucony" and w.ponawiac is False and "Klucz Joe odrzucony" in w.blad


@respx.mock
def test_wyslij_429():
    respx.post(f"{B}/v2/submission/new").respond(429)
    w = joe.wyslij(KLUCZ, b"x", "a.eml", "c")
    assert w.status == "limit" and w.ponawiac is True


@pytest.mark.parametrize("odp", [httpx.Response(502), httpx.ReadTimeout("t"), httpx.ConnectError("c")])
@respx.mock
def test_wyslij_niedostepny(odp):
    trasa = respx.post(f"{B}/v2/submission/new")
    trasa.mock(side_effect=odp) if isinstance(odp, Exception) else trasa.mock(return_value=odp)
    w = joe.wyslij(KLUCZ, b"x", "a.eml", "c")
    assert w.status == "niedostepny" and w.ponawiac is True


@respx.mock
def test_wyslij_blad_joe():
    respx.post(f"{B}/v2/submission/new").respond(400, json={"errors": [{"message": "Unsupported file type " + "x" * 500}]})
    w = joe.wyslij(KLUCZ, b"x", "a.eml", "c")
    assert w.status == "odrzucony" and w.ponawiac is False
    assert w.blad.startswith("Joe nie przyjął pliku: Unsupported") and len(w.blad) <= 230


@respx.mock
def test_odpowiedz_za_duza():
    respx.post(f"{B}/v2/submission/new").respond(200, stream=httpx.ByteStream(b"{" + b" " * (2 * 1024 * 1024)))
    w = joe.wyslij(KLUCZ, b"x", "a.eml", "c")
    assert (w.status, w.blad, w.ponawiac) == ("niedostepny", "Nieprawidłowa odpowiedź Joe.", False)


@pytest.mark.parametrize("cialo", [b"<html>", json.dumps({"data": {"submission_id": "../x"}}).encode(),
                                   json.dumps({"data": "x"}).encode(), b"[" * 100000])
@respx.mock
def test_nieprawidlowa_odpowiedz(cialo):
    respx.post(f"{B}/v2/submission/new").respond(200, content=cialo)
    assert joe.wyslij(KLUCZ, b"x", "a.eml", "c").blad == "Nieprawidłowa odpowiedź Joe."


@respx.mock
def test_stan_trwa_i_zakonczone():
    trasa = respx.post(f"{B}/v2/submission/info")
    trasa.respond(200, json={"data": {"status": "running", "analyses": [{"webid": "4521"}]}})
    w = joe.stan_zgloszenia(KLUCZ, "123")
    assert w.dane == {"status": "trwa", "webid": "4521", "werdykt": None, "wynik": None}
    assert b'submission_id=123' in tresc(trasa.calls.last)  # formularz urlencoded (bez pliku)
    trasa.respond(200, json={"data": {"status": "finished", "analyses": [{"webid": "4521"}],
                                      "most_relevant_analysis": {"webid": "4521", "detection": "malicious", "score": 87}}})
    assert joe.stan_zgloszenia(KLUCZ, "123").dane == {"status": "zakonczone", "webid": "4521",
                                                       "werdykt": "zlosliwy", "wynik": 87}


@respx.mock
def test_stan_w_kolejce():
    respx.post(f"{B}/v2/submission/info").respond(200, json={"data": {"status": "submitted", "analyses": []}})
    assert joe.stan_zgloszenia(KLUCZ, "1").dane["status"] == "w_kolejce"


@respx.mock
def test_stan_zakonczone_bez_analiz():
    respx.post(f"{B}/v2/submission/info").respond(200, json={"data": {"status": "finished", "analyses": []}})
    w = joe.stan_zgloszenia(KLUCZ, "1")
    assert w.status == "ok" and w.dane == {"status": "zakonczone", "webid": None, "werdykt": "nieznany", "wynik": None}


@respx.mock
def test_stan_zly_webid():
    respx.post(f"{B}/v2/submission/info").respond(200, json={"data": {"status": "running", "analyses": [{"webid": "<x>"}]}})
    assert joe.stan_zgloszenia(KLUCZ, "1").blad == "Nieprawidłowa odpowiedź Joe."


def test_link_analizy():
    assert joe.link_analizy("1234567") == "https://jbxcloud.joesecurity.org/analysis/1234567"
    with pytest.raises(ValueError):
        joe.link_analizy("x/../y")


@respx.mock
def test_info_konta():
    trasa = respx.post(f"{B}/v2/account/info")
    trasa.respond(200, json={"data": {"type": "pro"}})
    assert joe.info_konta(KLUCZ).status == "ok"
    trasa.respond(403)
    assert joe.info_konta(KLUCZ).status == "odrzucony"


@respx.mock
def test_wynik_poza_zakresem():
    respx.post(f"{B}/v2/submission/info").respond(200, json={"data": {"status": "finished", "analyses": [{"webid": "1"}],
                                                              "most_relevant_analysis": {"detection": "malicious", "score": 10**12}}})
    assert joe.stan_zgloszenia(KLUCZ, "1").dane["wynik"] is None
