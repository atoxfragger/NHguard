"""Tests unitaires pour les nouveaux helpers de contexte agent-side
(edr_agent.py) : is_off_hours() et has_suspicious_destination_port()."""

from datetime import datetime
from types import SimpleNamespace

import edr_agent


def test_off_hours_true_at_3am_on_a_weekday():
    tuesday_3am = datetime(2026, 8, 18, 3, 0)  # un mardi
    assert edr_agent.is_off_hours(tuesday_3am) is True


def test_off_hours_false_during_business_hours_on_a_weekday():
    tuesday_2pm = datetime(2026, 8, 18, 14, 0)
    assert edr_agent.is_off_hours(tuesday_2pm) is False


def test_off_hours_true_on_a_weekend_even_during_daytime():
    saturday_2pm = datetime(2026, 8, 22, 14, 0)  # un samedi
    assert edr_agent.is_off_hours(saturday_2pm) is True


def test_off_hours_boundaries_are_inclusive_of_business_window():
    assert edr_agent.is_off_hours(datetime(2026, 8, 18, edr_agent.OFF_HOURS_START_HOUR, 0)) is False
    assert edr_agent.is_off_hours(datetime(2026, 8, 18, edr_agent.OFF_HOURS_END_HOUR, 0)) is True
    assert edr_agent.is_off_hours(datetime(2026, 8, 18, edr_agent.OFF_HOURS_START_HOUR - 1, 59)) is True


class _FakeConn:
    def __init__(self, port):
        self.raddr = SimpleNamespace(port=port) if port else None


class _FakeProc:
    def __init__(self, ports):
        self._ports = ports

    def connections(self, kind="inet"):
        return [_FakeConn(p) for p in self._ports]


def test_suspicious_port_detected():
    proc = _FakeProc([443, 4444])  # 4444 = Metasploit par défaut
    assert edr_agent.has_suspicious_destination_port(proc) is True


def test_no_suspicious_port_among_normal_connections():
    proc = _FakeProc([443, 80, 8080, 53])
    assert edr_agent.has_suspicious_destination_port(proc) is False


def test_no_connections_is_not_suspicious():
    proc = _FakeProc([])
    assert edr_agent.has_suspicious_destination_port(proc) is False


def test_connections_lookup_failure_returns_false_not_an_exception():
    import psutil

    class _DeadProc:
        def connections(self, kind="inet"):
            raise psutil.NoSuchProcess(1234)

    assert edr_agent.has_suspicious_destination_port(_DeadProc()) is False
