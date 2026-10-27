from rq import Worker


def test_worker_czesciej_probuje_uruchomic_scheduler(monkeypatch):
    """Po restarcie stary worker trzyma blokadę schedulera ~60 s; domyślnie RQ ponawia próbę co 10 min,
    przez co zaplanowane zadania (śledzenie Joe, ponowienia GTI/Censys) czekałyby do 10 minut."""
    from analizy.rq_worker import WorkerMiemli

    przekazane = {}
    monkeypatch.setattr(Worker, "__init__", lambda self, *a, **kw: przekazane.update(kw))
    WorkerMiemli(["default"])
    assert przekazane["maintenance_interval"] == 60
