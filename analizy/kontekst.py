from django.conf import settings

from . import piaskownica_klient


def piaskownica(request):
    """Baner, gdy produkcja wymaga gVisor, a parser zgłasza, że działa bez niego."""
    if not settings.PARSER_WYMAGA_GVISOR or not request.user.is_authenticated:
        return {}
    stan = piaskownica_klient.stan_piaskownicy()
    return {"ostrzezenie_gvisor": bool(stan) and stan.get("gvisor") is False}
