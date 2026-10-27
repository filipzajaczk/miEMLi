"""Czy proces działa w gVisor (runsc)? gVisor podaje stałą wersję jądra i własne komunikaty dmesg."""

import subprocess

SYGNATURA_PROC_VERSION = "Linux version 4.4.0 #1 SMP Sun Jan 10 15:06:54 PST 2016"


def _odczytaj_proc_version() -> str:
    try:
        with open("/proc/version") as f:
            return f.read()
    except OSError:
        return ""


def _odczytaj_dmesg() -> str:
    try:
        return subprocess.run(["dmesg"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def w_gvisor(proc_version: str | None = None, dmesg: str | None = None) -> bool:
    if proc_version is None:
        proc_version = _odczytaj_proc_version()
    if SYGNATURA_PROC_VERSION in proc_version:
        return True
    if dmesg is None:
        dmesg = _odczytaj_dmesg()
    return "gVisor" in dmesg
