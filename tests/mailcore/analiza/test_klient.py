from mailcore.analiza.klient import klient, lancuch_arc
from mailcore.parsuj import parsuj


def wiad(zbuduj_mail, naglowki):
    return parsuj(zbuduj_mail(naglowki=naglowki), "a.eml")


def ogniwo(i, spf="pass", seal=True, ams=True, aar=True, cv="none"):
    n = []
    if seal:
        n.append(("ARC-Seal", f"i={i}; a=rsa-sha256; cv={cv}; d=fwd{i}.example; s=k; b=xx"))
    if ams:
        n.append(("ARC-Message-Signature", f"i={i}; a=rsa-sha256; d=fwd{i}.example; s=k; b=yy"))
    if aar:
        n.append(("ARC-Authentication-Results",
                  f"i={i}; mx{i}.example; spf={spf} smtp.mailfrom=a.example; dkim=fail; dmarc=pass"))
    return n


def test_klient_naglowki(zbuduj_mail):
    k = klient(wiad(zbuduj_mail, [("X-Mailer", "PHPMailer 6.0"), ("User-Agent", "x" * 400),
                                  ("X-Originating-IP", "[185.243.115.20]")]))
    assert k.x_mailer == "PHPMailer 6.0" and len(k.user_agent) == 300 and k.x_originating_ip == "185.243.115.20"


def test_klient_zle_ip_i_brak(zbuduj_mail):
    assert klient(wiad(zbuduj_mail, [("X-Originating-IP", "abc")])).x_originating_ip is None
    k = klient(wiad(zbuduj_mail, []))
    assert (k.x_mailer, k.user_agent, k.x_originating_ip) == (None, None, None)


def test_arc_pelny(zbuduj_mail):
    lancuch = lancuch_arc(wiad(zbuduj_mail, ogniwo(2, spf="fail", cv="pass") + ogniwo(1)))
    assert lancuch.kompletny and lancuch.cv == "pass"
    assert [(o.i, o.serwer, o.spf, o.dkim, o.dmarc) for o in lancuch.ogniwa] == [
        (1, "mx1.example", "pass", "fail", "pass"), (2, "mx2.example", "fail", "fail", "pass")]


def test_arc_niepelny(zbuduj_mail):
    assert lancuch_arc(wiad(zbuduj_mail, ogniwo(2, seal=False) + ogniwo(1))).kompletny is False


def test_arc_luka(zbuduj_mail):
    assert lancuch_arc(wiad(zbuduj_mail, ogniwo(3) + ogniwo(1))).kompletny is False


def test_arc_limit(zbuduj_mail):
    naglowki = [n for i in range(60, 0, -1) for n in ogniwo(i)]
    lancuch = lancuch_arc(wiad(zbuduj_mail, naglowki))
    assert len(lancuch.ogniwa) == 50 and lancuch.ogniwa[0].i == 1


def test_arc_smieci(zbuduj_mail):
    lancuch = lancuch_arc(wiad(zbuduj_mail, [("ARC-Authentication-Results", "bez numeru; spf=pass")]))
    assert lancuch is not None and lancuch.ogniwa == [] and lancuch.kompletny is False


def test_bez_arc(zbuduj_mail):
    assert lancuch_arc(wiad(zbuduj_mail, [])) is None
