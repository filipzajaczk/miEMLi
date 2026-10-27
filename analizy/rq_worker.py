"""Worker RQ miemli.

1. Lista dozwolonych zadań: web zna hasło Redisa, więc po jego przejęciu ktoś mógłby zakolejkować
   dowolną funkcję (np. os.system) i wykonać ją w workerze, który ma klucz prywatny Joe i klucze API.
   Worker wykonuje wyłącznie zadania z listy.
2. Częstsze zadania utrzymaniowe: po restarcie kontenera poprzedni worker może jeszcze ~60 s trzymać
   blokadę schedulera; domyślnie RQ próbuje ponownie dopiero po 10 minutach.
"""

import logging

from rq import Worker

logger = logging.getLogger(__name__)

DOZWOLONE_ZADANIA = frozenset({
    "analizy.zadania.wzbogac",
    "analizy.joe_zadania.wyslij_do_joe",
    "analizy.joe_zadania.sprawdz_joe",
    "analizy.joe_zadania.sprawdz_klucz_joe",
})


class WorkerMiemli(Worker):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("maintenance_interval", 60)
        super().__init__(*args, **kwargs)

    def perform_job(self, job, queue) -> bool:
        try:
            nazwa = job.func_name
        except Exception:
            nazwa = "<nieczytelne>"
        if nazwa not in DOZWOLONE_ZADANIA:
            logger.error("Odrzucono niedozwolone zadanie RQ: %s (możliwe przejęcie web/Redisa)", nazwa[:100])
            self.handle_job_failure(job, queue, exc_string="niedozwolone zadanie")
            return False
        return super().perform_job(job, queue)
