from mailcore.rozbrajanie import rozbroj


def test_rozbroj():
    assert rozbroj("url", "https://evil.com/a.b") == "hxxps://evil[.]com/a.b"
    assert rozbroj("url", "HTTP://evil.com") == "hxxp://evil[.]com"
    assert rozbroj("ip", "1.2.3.4") == "1[.]2[.]3[.]4"
    assert rozbroj("email", "a.b@evil.com") == "a.b@evil[.]com"
    assert rozbroj("domena", "evil.com") == "evil[.]com"
    assert rozbroj("plik", "abc") == "abc"
