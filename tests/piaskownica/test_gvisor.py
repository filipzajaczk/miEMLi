from piaskownica.gvisor import SYGNATURA_PROC_VERSION, w_gvisor


def test_w_gvisor():
    assert w_gvisor(SYGNATURA_PROC_VERSION, "") is True
    assert w_gvisor("Linux version 6.12.0-kali", "[    0.0] Starting gVisor...") is True
    assert w_gvisor("Linux version 6.12.0-kali", "") is False


def test_na_tym_hoscie_bez_gvisor():
    assert w_gvisor() is False
