from rq import Worker


def test_worker_czesciej_probuje_uruchomic_scheduler(monkeypatch):
    """Po restarcie stary worker trzyma blokadę schedulera ~60 s; domyślnie RQ ponawia próbę co 10 min,
    przez co zaplanowane zadania (śledzenie Joe, ponowienia GTI/Censys) czekałyby do 10 minut."""
    from analizy.rq_worker import WorkerMiemli

    przekazane = {}
    monkeypatch.setattr(Worker, "__init__", lambda self, *a, **kw: przekazane.update(kw))
    WorkerMiemli(["default"])
    assert przekazane["maintenance_interval"] == 60


class _Zadanie:
    def __init__(self, func_name):
        self.func_name = func_name
        self.id = "x"


def test_worker_odrzuca_niedozwolone_zadania(monkeypatch):
    """Przejęty web ma hasło Redisa — nie może zlecić workerowi dowolnej funkcji (np. os.system)."""
    from analizy.rq_worker import WorkerMiemli

    wykonane, odrzucone = [], []
    monkeypatch.setattr(Worker, "perform_job", lambda self, job, queue: wykonane.append(job.func_name) or True)
    monkeypatch.setattr(Worker, "handle_job_failure",
                        lambda self, job, queue, started_job_registry=None, exc_string="": odrzucone.append(job.func_name))
    w = WorkerMiemli.__new__(WorkerMiemli)
    for nazwa in ("os.system", "subprocess.run", "builtins.eval", "analizy.joe_zadania.zlec_wysylke"):
        assert w.perform_job(_Zadanie(nazwa), None) is False
    for nazwa in ("analizy.zadania.wzbogac", "analizy.joe_zadania.wyslij_do_joe",
                  "analizy.joe_zadania.sprawdz_joe", "analizy.joe_zadania.sprawdz_klucz_joe"):
        assert w.perform_job(_Zadanie(nazwa), None) is True
    assert odrzucone == ["os.system", "subprocess.run", "builtins.eval", "analizy.joe_zadania.zlec_wysylke"]
    assert len(wykonane) == 4
