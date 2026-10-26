from email.message import EmailMessage

import pytest


def _zbuduj_mail(
    temat="Test",
    od="Nadawca <nadawca@example.com>",
    do="odbiorca@example.org",
    tekst="Treść",
    html=None,
    zalaczniki=(),
    naglowki=(),
    zagniezdzone=(),
) -> bytes:
    """Buduje mail jako bajty .eml.

    zalaczniki: [(nazwa, typ_mime, bajty)] albo [(nazwa, typ_mime, bajty, {"cid": ..., "inline": bool})]
    zagniezdzone: [bajty innego maila] — dołączane jako message/rfc822
    """
    m = EmailMessage()
    for nazwa, wartosc in naglowki:
        m[nazwa] = wartosc
    if temat is not None:
        m["Subject"] = temat
    if od is not None:
        m["From"] = od
    if do is not None:
        m["To"] = do
    if tekst is not None:
        m.set_content(tekst)
    if html is not None:
        if tekst is None:
            m.set_content(html, subtype="html")
        else:
            m.add_alternative(html, subtype="html")
    for z in zalaczniki:
        nazwa, typ, dane = z[:3]
        opcje = z[3] if len(z) > 3 else {}
        maintype, subtype = typ.split("/", 1)
        if m.get_content_maintype() != "multipart":
            m.make_mixed()
        cid = opcje.get("cid")
        m.add_attachment(
            dane,
            maintype=maintype,
            subtype=subtype,
            filename=nazwa,
            disposition="inline" if opcje.get("inline") else "attachment",
            cid=f"<{cid}>" if cid else None,
        )
    for wewn in zagniezdzone:
        from email import message_from_bytes, policy

        if m.get_content_maintype() != "multipart":
            m.make_mixed()
        m.add_attachment(message_from_bytes(wewn, policy=policy.default))
    return m.as_bytes()


@pytest.fixture
def zbuduj_mail():
    return _zbuduj_mail
