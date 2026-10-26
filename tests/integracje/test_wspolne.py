import httpx
import pytest
import respx

from integracje.wspolne import WynikDostawcy, nowy_klient, wykonaj

URL = "https://api.example/x"


def parsuj(j):
    return {"a": j["a"]}


def wynik() -> WynikDostawcy:
    with nowy_klient() as k:
        return wykonaj(k, URL, {}, parsuj, "L")


@respx.mock
def test_200():
    respx.get(URL).respond(200, json={"a": 1})
    w = wynik()
    assert (w.status, w.skrot, w.surowe, w.link) == ("gotowe", {"a": 1}, {"a": 1}, "L")


@respx.mock
def test_404():
    respx.get(URL).respond(404, json={"error": {}})
    w = wynik()
    assert w.status == "brak_danych" and w.ponawiac is False and w.link == "L"


@respx.mock
def test_429():
    respx.get(URL).respond(429)
    w = wynik()
    assert w.status == "limit" and w.ponawiac is True


@respx.mock
def test_403_html_cloudflare():
    respx.get(URL).respond(403, text="<html>Error 1010</html>")
    w = wynik()
    assert w.status == "blad" and "403" in w.blad and w.ponawiac is False


@respx.mock
def test_500():
    respx.get(URL).respond(500)
    w = wynik()
    assert w.status == "blad" and w.ponawiac is True


@respx.mock
def test_timeout():
    respx.get(URL).mock(side_effect=httpx.ConnectTimeout("t"))
    w = wynik()
    assert w.status == "blad" and w.ponawiac is True and w.blad


@respx.mock
def test_200_nie_json():
    respx.get(URL).respond(200, text="<html>")
    w = wynik()
    assert w.status == "blad" and w.ponawiac is False


@respx.mock
def test_parsuj_rzuca():
    respx.get(URL).respond(200, json={})
    assert wynik().status == "blad"


@respx.mock
def test_user_agent():
    respx.get(URL).respond(200, json={"a": 1})
    wynik()
    assert respx.calls.last.request.headers["User-Agent"] == "miemli/1.0"
