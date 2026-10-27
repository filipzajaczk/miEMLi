import io

import pytest
from django.urls import reverse
from PIL import Image

from analizy.uslugi import utworz_lub_otworz

pytestmark = pytest.mark.django_db


def obraz(fmt, w=100, h=50):
    buf = io.BytesIO()
    Image.new("RGB", (w, h), (200, 30, 30)).save(buf, fmt)
    return buf.getvalue()


def gif_animowany():
    buf = io.BytesIO()
    ramki = [Image.new("RGB", (40, 40), (60 * i, 0, 0)) for i in range(3)]
    ramki[0].save(buf, "GIF", save_all=True, append_images=ramki[1:])
    return buf.getvalue()


@pytest.fixture
def analiza_z(zbuduj_mail, analityk):
    def utworz(*obrazki):
        html = "".join(f'<img src="cid:c{i}">' for i in range(len(obrazki)))
        zal = [(n, m, d, {"cid": f"c{i}", "inline": True}) for i, (n, m, d) in enumerate(obrazki)]
        return utworz_lub_otworz(zbuduj_mail(html=html, zalaczniki=zal), "o.eml", analityk)[0]
    return utworz


def strona(klient, a, **p):
    from urllib.parse import urlencode
    return klient.get(reverse("analizy:szczegoly", args=[a.pk]) + ("?" + urlencode(p) if p else "")).content.decode()


def sekcja(t, klasa):
    start = t.find(f'class="{klasa}"')
    return t[start:t.find("</section>", start)] if start >= 0 else ""


def test_ramka_obrazki(zalogowany, analiza_z):
    t = sekcja(strona(zalogowany, analiza_z(("logo.png", "image/png", obraz("PNG")))), "obrazki-wiadomosci")
    assert "Obrazki (1)" in t and "PNG" in t and "100×50" in t and "przekodowany" in t


def test_ostrzezenie_o_nietypowych(zalogowany, analiza_z):
    t = strona(zalogowany, analiza_z(("logo.png", "image/png", obraz("TIFF"))))
    assert "Nietypowe obrazki w wiadomości (1)" in t
    assert '<span class="b warn"' in sekcja(t, "obrazki-wiadomosci")
    assert "format niezgodny" in sekcja(t, "obrazki-wiadomosci")


def test_animacja_neutralna(zalogowany, analiza_z):
    t = strona(zalogowany, analiza_z(("a.gif", "image/gif", gif_animowany())))
    assert "Nietypowe obrazki" not in t
    s = sekcja(t, "obrazki-wiadomosci")
    assert "animacja" in s and '<span class="b neutral"' in s


def test_ioc_odznaka_i_szczegoly(zalogowany, analiza_z):
    a = analiza_z(("logo.png", "image/png", obraz("TIFF")))
    assert "format niezgodny: TIFF" in strona(zalogowany, a, sekcja="ioc")
    ioc = a.ioc.get(typ="plik")
    t = zalogowany.get(reverse("analizy:szczegoly_ioc", args=[a.pk, ioc.pk])).content.decode()
    assert "Obrazek" in t and "TIFF" in t and "image/png" in t and "format niezgodny" in t


def test_podglad_ramka_pominietego(zalogowany, analiza_z):
    a = analiza_z(("logo.png", "image/png", obraz("TIFF")))
    t = zalogowany.get(reverse("analizy:podglad", args=[a.pk, "0"])).content.decode()
    assert "[obrazek pominięty: format TIFF]" in t and ".obrazek-pominiety" in t


@pytest.mark.parametrize("wymaga,stan,baner", [
    (True, {"gvisor": False}, True), (True, {"gvisor": True}, False), (False, {"gvisor": False}, False),
])
def test_baner_gvisor(zalogowany, settings, monkeypatch, wymaga, stan, baner):
    import analizy.piaskownica_klient as k

    settings.PARSER_WYMAGA_GVISOR = wymaga
    monkeypatch.setattr(k, "stan_piaskownicy", lambda: stan)
    t = zalogowany.get(reverse("analizy:lista")).content.decode()
    assert ("parser nie działa w gVisor" in t) is baner
