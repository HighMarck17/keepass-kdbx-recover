"""Guarded Tk smoke tests: build the window and drive one poll cycle.

Skips cleanly when Tkinter is not installed or no display is available, so
headless CI neither fails nor hangs. No mainloop is ever entered.
"""

import queue
import time

import pytest

tk = pytest.importorskip("tkinter")

from keepass_kdbx_recover.config import default, save  # noqa: E402
from keepass_kdbx_recover.gui.app import KdbxRecoverApp  # noqa: E402
from keepass_kdbx_recover.gui.reporter import (  # noqa: E402
    KIND_FINISH,
    KIND_FOUND,
    KIND_START,
    Message,
    UiState,
)
from keepass_kdbx_recover.progress import ProgressEvent  # noqa: E402


@pytest.fixture
def root():
    # Creating many Tk roots in one process can transiently fail; retry a few
    # times, then skip (headless / no display) rather than fail.
    last_error = None
    r = None
    for _ in range(3):
        try:
            r = tk.Tk()
            break
        except tk.TclError as exc:
            last_error = exc
    if r is None:
        pytest.skip(f"no display available: {last_error}")
    r.withdraw()
    try:
        yield r
    finally:
        r.destroy()


def test_app_builds_the_four_tabs(root):
    app = KdbxRecoverApp(root)
    root.update_idletasks()
    tabs = [app.notebook.tab(tab_id, "text") for tab_id in app.notebook.tabs()]
    assert tabs == ["Setup", "Recovery", "Inspect", "Help"]


def test_poll_cycle_reflects_a_found_password(root):
    app = KdbxRecoverApp(root)
    event = ProgressEvent(tested=1, total=1, elapsed=0.1)
    app.running = True
    app.queue.put(Message(KIND_START, total=1))
    app.queue.put(Message(KIND_FOUND, password="secret", event=event))
    app.queue.put(Message(KIND_FINISH, found="secret", event=event))

    app._poll()  # drains everything; finish flips running off and calls _finish_run
    root.update_idletasks()

    assert app.found_var.get() == "secret"
    assert app.running is False
    assert str(app.copy_btn["state"]) == "normal"


def test_enable_dpi_awareness_never_raises():
    from keepass_kdbx_recover.gui.app import enable_dpi_awareness
    enable_dpi_awareness()  # safe no-op off Windows / when unavailable


def test_poll_keeps_running_until_a_terminal_message(root):
    # Regression: an empty first poll (engine preflight slower than POLL_MS) must
    # NOT be treated as "finished". Only a FINISH/ERROR message ends the run.
    app = KdbxRecoverApp(root)
    app.running = True
    app.thread = None
    app.queue = queue.Queue()  # empty, non-terminal
    app.state = UiState()  # not finished
    app._poll()
    assert app.running is True  # must not have finished on an empty queue


def test_real_run_surfaces_the_found_password(root, kdbx_db):
    # End-to-end through the GUI worker thread: the found password must reach the UI.
    db_path, password = kdbx_db
    app = KdbxRecoverApp(root)
    app.vars["mask_enabled"].set(False)
    app.vars["fragments_enabled"].set(True)
    app.vars["db_path"].set(db_path)
    app.vars["fragments_pieces"].set(f"wrong, {password}, other")
    app.vars["workers"].set("1")  # sequential: fast and deterministic
    app._revalidate()
    assert str(app.start_btn["state"]) == "normal"

    app._on_start()
    deadline = time.time() + 30
    while app.running and time.time() < deadline:
        root.update()
        root.update_idletasks()
        time.sleep(0.05)

    assert app.running is False
    assert app.found_var.get() == password
    assert str(app.copy_btn["state"]) == "normal"


def test_finish_run_reports_cancelled_distinctly(root):
    app = KdbxRecoverApp(root)
    app.running = True
    app._cancelled = True
    app.state = UiState(finished=True, found=None, error=None)
    app._finish_run()
    assert app.status_var.get() == "Cancelled."


def test_loading_a_config_populates_the_form(root, tmp_path):
    path = tmp_path / "c.toml"
    cfg = default()
    cfg.database.path = "loaded.kdbx"
    save(cfg, path)

    app = KdbxRecoverApp(root, config_path=str(path))
    assert app.vars["db_path"].get() == "loaded.kdbx"
