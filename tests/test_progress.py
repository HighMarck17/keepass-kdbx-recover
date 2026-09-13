"""Tests for progress events, time formatting, and reporter output."""

from keepass_kdbx_recover.progress import (
    ConsoleReporter,
    ProgressEvent,
    fmt_time,
    format_progress_line,
    format_result,
)


def test_fmt_time_scales_units():
    assert fmt_time(0) == "0s"
    assert fmt_time(59) == "59s"
    assert fmt_time(60) == "1m00s"
    assert fmt_time(3661) == "1h01m01s"


def test_progress_event_rate_is_tested_over_elapsed():
    ev = ProgressEvent(tested=100, total=None, elapsed=2.0)
    assert ev.rate == 50.0


def test_progress_event_rate_zero_when_no_time():
    assert ProgressEvent(tested=5, total=None, elapsed=0.0).rate == 0.0


def test_progress_event_eta_uses_remaining_over_rate():
    ev = ProgressEvent(tested=100, total=200, elapsed=2.0)  # rate = 50 pw/s
    assert ev.eta == 2.0  # 100 remaining / 50 = 2s


def test_progress_event_eta_none_without_total():
    assert ProgressEvent(tested=100, total=None, elapsed=2.0).eta is None


def test_format_progress_line_with_total_shows_percent():
    ev = ProgressEvent(tested=50, total=100, elapsed=1.0, candidate="abc")
    line = format_progress_line(ev)
    assert "50/100" in line
    assert "50.0%" in line
    assert "abc" in line


def test_format_progress_line_without_total_shows_count():
    ev = ProgressEvent(tested=1234, total=None, elapsed=1.0)
    line = format_progress_line(ev)
    assert "1,234" in line
    assert "%" not in line


def test_format_result_found_includes_password():
    ev = ProgressEvent(tested=10, total=10, elapsed=1.0)
    assert "FOUND" in format_result("secret", ev)
    assert "secret" in format_result("secret", ev)


def test_format_result_not_found():
    ev = ProgressEvent(tested=10, total=10, elapsed=1.0)
    assert "not found" in format_result(None, ev).lower()


def test_console_reporter_prints_summary(capsys):
    reporter = ConsoleReporter()
    ev = ProgressEvent(tested=3, total=3, elapsed=1.0)
    reporter.on_finish("pw", ev)
    out = capsys.readouterr().out
    assert "pw" in out
