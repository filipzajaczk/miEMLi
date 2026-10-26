"""HTML wiadomości do podglądu: bez skryptów, bez zewnętrznych zasobów, bez klikalnych linków.

To pierwsza warstwa. Druga to iframe sandbox + CSP `default-src 'none'; img-src data:` w widoku.
"""

import base64

import nh3
from bs4 import BeautifulSoup

from .analiza.linki import rozpakuj_przekierowanie
from .model import Zalacznik
from .rozbrajanie import rozbroj

TAGI = {
    "a", "abbr", "b", "blockquote", "br", "caption", "center", "code", "col", "colgroup", "dd", "del",
    "div", "dl", "dt", "em", "font", "h1", "h2", "h3", "h4", "h5", "h6", "hr", "i", "img", "ins", "li",
    "ol", "p", "pre", "q", "s", "small", "span", "strike", "strong", "sub", "sup", "table", "tbody",
    "td", "tfoot", "th", "thead", "tr", "u", "ul",
}
ATRYBUTY_WSPOLNE = {"style", "title", "class", "align", "width", "height", "colspan", "rowspan", "valign", "bgcolor", "color"}
ATRYBUTY = {"*": ATRYBUTY_WSPOLNE, "img": {"src", "alt"}}
# Bez background/background-image/list-style-image itp. — tylko właściwości bez URL-i
STYLE = {
    "color", "background-color", "font", "font-family", "font-size", "font-style", "font-weight",
    "text-align", "text-decoration", "text-indent", "text-transform", "line-height", "letter-spacing",
    "white-space", "vertical-align", "display", "width", "max-width", "min-width", "height",
    "margin", "margin-top", "margin-right", "margin-bottom", "margin-left",
    "padding", "padding-top", "padding-right", "padding-bottom", "padding-left",
    "border", "border-top", "border-right", "border-bottom", "border-left", "border-color",
    "border-width", "border-style", "border-collapse", "border-spacing", "border-radius",
}
USUWANE_Z_TRESCIA = {"script", "style", "head", "title", "form", "iframe", "object", "embed", "noscript", "template", "svg", "math"}


def _data_uri(z: Zalacznik) -> str:
    return f"data:{z.typ_mime};base64,{base64.b64encode(z.dane).decode('ascii')}"


def bezpieczny_html(html: str, zalaczniki: list[Zalacznik], max_obraz: int = 2 * 1024 * 1024) -> str:
    obrazy = {
        z.content_id: z
        for z in zalaczniki
        if z.content_id and z.typ_mime.startswith("image/") and z.rozmiar <= max_obraz
    }
    soup = BeautifulSoup(html, "html.parser")

    for tag in soup.find_all(["meta", "base", "link"]):
        tag.decompose()

    for a in soup.find_all("a"):
        href = (a.get("href") or "").strip()
        a.name = "span"
        a.attrs = {"class": "link"}
        if href.lower().startswith(("http://", "https://")):
            a["title"] = rozbroj("url", rozpakuj_przekierowanie(href) or href)

    for tag in soup.find_all(True):
        for atrybut in ("srcset", "background", "poster", "lowsrc", "dynsrc"):
            tag.attrs.pop(atrybut, None)
        if tag.name == "img":
            src = (tag.get("src") or "").strip()
            obraz = obrazy.get(src[4:].strip("<>")) if src.lower().startswith("cid:") else None
            if obraz is not None:
                tag["src"] = _data_uri(obraz)
            else:
                tag.attrs.pop("src", None)
        else:
            tag.attrs.pop("src", None)

    return nh3.clean(
        str(soup),
        tags=TAGI,
        clean_content_tags=USUWANE_Z_TRESCIA,
        attributes=ATRYBUTY,
        url_schemes={"data"},
        filter_style_properties=STYLE,
        link_rel=None,
    )
