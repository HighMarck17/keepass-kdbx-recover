"""Integration tests for the recovery engine against a real KDBX database."""

import threading

import pytest

from keepass_kdbx_recover.config import default
from keepass_kdbx_recover.engine import RecoveryEngine, RecoveryError, RecoveryResult


class RecordingReporter:
    """A ProgressReporter that records the calls it receives."""

    def __init__(self):
        self.started = False
        self.total = "unset"
        self.found_calls = []
        self.finished = None

    def on_start(self, total):
        self.started = True
        self.total = total

    def on_progress(self, event):
        pass

    def on_found(self, password, event):
        self.found_calls.append(password)

    def on_finish(self, found, event):
        self.finished = (found, event.tested)


def make_cfg(db_path, pieces, workers=1):
    c = default()
    c.mask.enabled = False
    c.fragments.enabled = True
    c.fragments.pieces = pieces
    c.fragments.permutations = False
    c.fragments.case_variants = False
    c.fragments.min_fragments = 1
    c.database.path = db_path
    c.recovery.workers = workers
    c.recovery.progress_interval = 0.01
    return c


def test_engine_finds_known_password(kdbx_db):
    db_path, password = kdbx_db
    cfg = make_cfg(db_path, ["nope1", password, "nope2"])
    result = RecoveryEngine().run(cfg, RecordingReporter())
    assert isinstance(result, RecoveryResult)
    assert result.found == password
    assert result.tested >= 1


def test_engine_reports_not_found(kdbx_db):
    db_path, _ = kdbx_db
    cfg = make_cfg(db_path, ["nope1", "nope2", "nope3"])
    result = RecoveryEngine().run(cfg, RecordingReporter())
    assert result.found is None


def test_engine_notifies_reporter_on_start_and_finish(kdbx_db):
    db_path, password = kdbx_db
    cfg = make_cfg(db_path, [password])
    reporter = RecordingReporter()
    RecoveryEngine().run(cfg, reporter)
    assert reporter.started is True
    assert reporter.finished is not None
    assert reporter.found_calls == [password]


def test_engine_cancel_event_stops_before_finding(kdbx_db):
    db_path, password = kdbx_db
    cfg = make_cfg(db_path, ["a", "b", "c", password])
    cancel = threading.Event()
    cancel.set()  # already cancelled: must stop after the first candidate
    result = RecoveryEngine().run(cfg, RecordingReporter(), cancel=cancel)
    assert result.found is None


def test_engine_raises_recovery_error_on_corrupt_database(tmp_path):
    bad = tmp_path / "bad.kdbx"
    bad.write_bytes(b"this is not a real kdbx database")
    cfg = make_cfg(str(bad), ["x"])
    with pytest.raises(RecoveryError):
        RecoveryEngine().run(cfg, RecordingReporter())
