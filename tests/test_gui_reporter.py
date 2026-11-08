"""Tests for the GUI reporter: message contract, state reduction, queue drain.

All of this is pure and runs headless (no Tk, no display).
"""

import queue

from keepass_kdbx_recover.gui.reporter import (
    KIND_ERROR,
    KIND_FINISH,
    KIND_FOUND,
    KIND_PROGRESS,
    KIND_START,
    Message,
    TkReporter,
    UiState,
    drain,
    reduce,
)
from keepass_kdbx_recover.progress import ProgressEvent, format_progress_line, format_result


def test_tkreporter_enqueues_expected_messages():
    q = queue.Queue()
    reporter = TkReporter(q)
    ev = ProgressEvent(tested=5, total=10, elapsed=1.0, candidate="abc")

    reporter.on_start(10)
    reporter.on_progress(ev)
    reporter.on_found("secret", ev)
    reporter.on_finish("secret", ev)
    reporter.error("boom")

    kinds = []
    while not q.empty():
        kinds.append(q.get_nowait())
    assert [m.kind for m in kinds] == [
        KIND_START, KIND_PROGRESS, KIND_FOUND, KIND_FINISH, KIND_ERROR
    ]
    assert kinds[0].total == 10
    assert kinds[1].event is ev
    assert kinds[2].password == "secret"
    assert kinds[3].found == "secret"
    assert kinds[4].text == "boom"


def test_reduce_start_sets_running_and_determinate_by_total():
    determinate = reduce(UiState(), Message(KIND_START, total=100))
    assert determinate.running is True
    assert determinate.finished is False
    assert determinate.total == 100
    assert determinate.determinate is True

    indeterminate = reduce(UiState(), Message(KIND_START, total=None))
    assert indeterminate.determinate is False


def test_reduce_progress_updates_tested_and_status_line():
    ev = ProgressEvent(tested=7, total=10, elapsed=1.0, candidate="x")
    state = reduce(UiState(running=True), Message(KIND_PROGRESS, event=ev))
    assert state.tested == 7
    assert state.status_line == format_progress_line(ev)
    assert state.running is True


def test_reduce_found_sets_password_but_stays_running():
    ev = ProgressEvent(tested=3, total=3, elapsed=1.0)
    state = reduce(UiState(running=True), Message(KIND_FOUND, password="pw", event=ev))
    assert state.found == "pw"
    assert state.running is True  # finish still to come


def test_reduce_finish_stops_and_records_result():
    ev = ProgressEvent(tested=3, total=3, elapsed=1.0)
    state = reduce(UiState(running=True), Message(KIND_FINISH, found="pw", event=ev))
    assert state.running is False
    assert state.finished is True
    assert state.found == "pw"
    assert state.status_line == format_result("pw", ev)


def test_reduce_error_stops_and_records_error():
    state = reduce(UiState(running=True), Message(KIND_ERROR, text="cannot open"))
    assert state.running is False
    assert state.error == "cannot open"


def test_drain_folds_all_messages_and_returns_log_lines():
    q = queue.Queue()
    ev = ProgressEvent(tested=2, total=2, elapsed=1.0)
    q.put(Message(KIND_START, total=2))
    q.put(Message(KIND_FINISH, found="pw", event=ev))
    state, lines = drain(q, UiState())
    assert state.finished is True
    assert state.found == "pw"
    assert any("2" in line for line in lines)          # "Candidates to test: 2"
    assert any("PASSWORD FOUND" in line for line in lines)


def test_drain_on_empty_queue_returns_state_unchanged():
    state_in = UiState(running=True, tested=9)
    state_out, lines = drain(queue.Queue(), state_in)
    assert state_out == state_in
    assert lines == []


def test_exported_message_finishes_the_run_with_its_text():
    q = queue.Queue()
    TkReporter(q).exported("Wrote 10 candidates to out.txt")
    state, lines = drain(q, UiState(running=True))
    assert state.finished is True
    assert state.running is False
    assert state.found is None
    assert state.status_line == "Wrote 10 candidates to out.txt"
    assert lines == ["Wrote 10 candidates to out.txt"]
