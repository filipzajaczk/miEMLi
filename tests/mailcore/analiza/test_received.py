from datetime import UTC, datetime, timedelta

import pytest

from mailcore.analiza import analizuj
from mailcore.analiza.received import sciezka_received, sygnaly_czasu
from mailcore.parsuj import parsuj

T0 = datetime(2026, 10, 24, 9, 0, tzinfo=UTC)
TERAZ = T0 + timedelta(days=1)


def _rfc(czas: datetime | str) -> str:
    return czas if isinstance(czas, str) else czas.strftime("%a, %d %b %Y %H:%M:%S %z")


def mail(zbuduj_mail, czasy, data=None, bez_ip=()):
    """czasy: od najstarszego przeskoku; nagłówki Received dopisywane są na górze, więc odwracamy."""
    naglowki = []
    for n, czas in enumerate(czasy):
        ip = "" if n in bez_ip else f" [185.243.115.{n + 1}]"
        srodek = f"from h{n}{ip} by h{n + 1}"
        naglowki.append(("Received", f"{srodek}; {_rfc(czas)}" if czas else srodek))
    naglowki.reverse()
    if data:
        naglowki.append(("Date", _rfc(data)))
    return parsuj(zbuduj_mail(naglowki=naglowki), "a.eml")


def kody(hop):
    return [u.kod for u in hop.uwagi]


@pytest.mark.parametrize("cofniecie,jest", [(timedelta(minutes=5, seconds=1), True), (timedelta(minutes=5), False)])
def test_czas_wstecz(zbuduj_mail, cofniecie, jest):
    hopy = sciezka_received(mail(zbuduj_mail, [T0, T0 - cofniecie]), TERAZ)
    assert ("CZAS_WSTECZ" in kody(hopy[1])) is jest
    assert kody(hopy[0]) == []


@pytest.mark.parametrize("postoj,jest", [(timedelta(hours=1, seconds=1), True), (timedelta(hours=1), False)])
def test_dlugi_postoj(zbuduj_mail, postoj, jest):
    hopy = sciezka_received(mail(zbuduj_mail, [T0, T0 + postoj]), TERAZ)
    assert ("DLUGI_POSTOJ" in kody(hopy[1])) is jest
    if jest:
        assert "1 h 0 min" in hopy[1].uwagi[0].opis


@pytest.mark.parametrize("przesuniecie,jest", [(timedelta(minutes=16), True), (timedelta(minutes=15), False)])
def test_przyszlosc(zbuduj_mail, przesuniecie, jest):
    hopy = sciezka_received(mail(zbuduj_mail, [TERAZ + przesuniecie]), TERAZ)
    assert ("CZAS_W_PRZYSZLOSCI" in kody(hopy[0])) is jest


def test_brak_czasu_i_ip(zbuduj_mail):
    hopy = sciezka_received(mail(zbuduj_mail, [T0, None], bez_ip=(0,)), TERAZ)
    assert kody(hopy[0]) == ["BRAK_IP"] and kody(hopy[1]) == ["BRAK_CZASU"]


def test_strefy_i_naiwne(zbuduj_mail):
    # 11:00 +0200 == 09:00 UTC; następny hop 09:10 -0000 (naiwny) → 10 min później, bez anomalii
    hopy = sciezka_received(mail(zbuduj_mail, ["Sat, 24 Oct 2026 11:00:00 +0200", "Sat, 24 Oct 2026 09:10:00 -0000"]),
                            TERAZ)
    assert kody(hopy[0]) == [] and kody(hopy[1]) == []


@pytest.mark.parametrize("roznica,jest", [
    (timedelta(hours=24, seconds=1), True), (-timedelta(hours=24, seconds=1), True), (timedelta(hours=24), False),
])
def test_data_odlegla(zbuduj_mail, roznica, jest):
    w = mail(zbuduj_mail, [T0], data=T0 + roznica)
    sygnaly = sygnaly_czasu(w, sciezka_received(w, TERAZ))
    assert (["DATA_ODLEGLA"] == [s.kod for s in sygnaly]) is jest
    if jest:
        assert "24 h" in sygnaly[0].opis


def test_data_brak(zbuduj_mail):
    w = mail(zbuduj_mail, [T0])
    assert sygnaly_czasu(w, sciezka_received(w, TERAZ)) == []


def test_sygnal_w_analizie(zbuduj_mail):
    w = mail(zbuduj_mail, [T0], data=T0 - timedelta(days=3))
    assert "DATA_ODLEGLA" in [s.kod for s in analizuj(w).wiadomosci["0"].sygnaly]
