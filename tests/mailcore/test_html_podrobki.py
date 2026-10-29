from mailcore.html_bezpieczny import bezpieczny_html


def test_podrobiony_dymek_i_klasy_usuniete():
    wynik = bezpieczny_html('<a href="http://evil.example"><span class="link" title="hxxps://bank[.]pl">Zaloguj</span></a>'
                            '<span class="obraz-zewnetrzny obrazek-pominiety inne">[obraz zewnętrzny: bank.pl]</span>', [])
    assert "bank[.]pl" not in wynik and "evil[.]example" in wynik
    assert wynik.count('class="link"') == 1 and "obraz-zewnetrzny" not in wynik and "obrazek-pominiety" not in wynik
