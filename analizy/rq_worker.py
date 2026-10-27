"""Worker RQ z częstszymi zadaniami utrzymaniowymi.

Po restarcie kontenera poprzedni worker może jeszcze ~60 s trzymać blokadę schedulera. Domyślnie RQ
próbuje ją przejąć ponownie dopiero po 10 minutach — tyle czekałyby zaplanowane zadania (śledzenie
wysyłek do Joe, ponowienia lookupów). Skracamy to do minuty.
"""

from rq import Worker


class WorkerMiemli(Worker):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("maintenance_interval", 60)
        super().__init__(*args, **kwargs)
