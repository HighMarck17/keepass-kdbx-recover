"""Thread-safe bridge between the recovery engine (worker thread) and the GUI.

The engine runs on a worker thread and calls a ProgressReporter. ``TkReporter``
turns each callback into a ``Message`` on a ``queue.Queue``; the Tk main loop
drains the queue and folds the messages into a ``UiState`` with the pure
``reduce``/``drain`` functions. Nothing here touches Tk widgets, so the whole
module is unit-testable without a display.
"""

import queue
from dataclasses import dataclass, replace

from ..progress import ProgressEvent, format_progress_line, format_result

KIND_START = "start"
KIND_PROGRESS = "progress"
KIND_FOUND = "found"
KIND_FINISH = "finish"
KIND_ERROR = "error"
KIND_EXPORTED = "exported"


@dataclass(frozen=True)
class Message:
    kind: str
    total: int | None = None
    event: ProgressEvent | None = None
    password: str | None = None
    found: str | None = None
    text: str | None = None


class TkReporter:
    """A ProgressReporter that enqueues messages for the Tk main loop.

    ``error`` and ``exported`` are not part of the ProgressReporter protocol; the
    worker wrapper calls them to surface a RecoveryError (which the engine raises
    before on_start) and the end of an export.
    """

    def __init__(self, message_queue: "queue.Queue[Message]") -> None:
        self._queue = message_queue

    def on_start(self, total: int | None) -> None:
        self._queue.put(Message(KIND_START, total=total))

    def on_progress(self, event: ProgressEvent) -> None:
        self._queue.put(Message(KIND_PROGRESS, event=event))

    def on_found(self, password: str, event: ProgressEvent) -> None:
        self._queue.put(Message(KIND_FOUND, password=password, event=event))

    def on_finish(self, found: str | None, event: ProgressEvent) -> None:
        self._queue.put(Message(KIND_FINISH, found=found, event=event))

    def error(self, text: str) -> None:
        self._queue.put(Message(KIND_ERROR, text=text))

    def exported(self, text: str) -> None:
        self._queue.put(Message(KIND_EXPORTED, text=text))


@dataclass
class UiState:
    running: bool = False
    finished: bool = False
    total: int | None = None
    determinate: bool = False
    tested: int = 0
    status_line: str = ""
    found: str | None = None
    error: str | None = None


def reduce(state: UiState, msg: Message) -> UiState:
    """Fold one message into the UI state (pure; returns a new UiState)."""
    if msg.kind == KIND_START:
        return replace(
            state,
            running=True,
            finished=False,
            total=msg.total,
            determinate=msg.total is not None,
            tested=0,
            found=None,
            error=None,
            status_line="Starting...",
        )
    if msg.kind == KIND_PROGRESS and msg.event is not None:
        return replace(
            state,
            tested=msg.event.tested,
            status_line=format_progress_line(msg.event),
        )
    if msg.kind == KIND_FOUND:
        tested = msg.event.tested if msg.event is not None else state.tested
        return replace(state, found=msg.password, tested=tested)
    if msg.kind == KIND_FINISH:
        tested = msg.event.tested if msg.event is not None else state.tested
        return replace(
            state,
            running=False,
            finished=True,
            found=msg.found,
            tested=tested,
            status_line=format_result(msg.found, msg.event) if msg.event else state.status_line,
        )
    if msg.kind == KIND_ERROR:
        return replace(
            state, running=False, finished=True, error=msg.text, status_line=msg.text or ""
        )
    if msg.kind == KIND_EXPORTED:
        return replace(state, running=False, finished=True, status_line=msg.text or "")
    return state


def _log_line(msg: Message) -> str | None:
    """The log line (if any) a message contributes to the Recovery log."""
    if msg.kind == KIND_START:
        total = f"{msg.total:,}" if msg.total is not None else "unknown (streaming)"
        return f"Candidates to test: {total}"
    if msg.kind == KIND_FINISH and msg.event is not None:
        return format_result(msg.found, msg.event)
    if msg.kind == KIND_ERROR:
        return f"Error: {msg.text}"
    if msg.kind == KIND_EXPORTED:
        return msg.text
    return None


def drain(message_queue: "queue.Queue[Message]", state: UiState) -> tuple[UiState, list[str]]:
    """Drain all pending messages, folding them into the state and collecting the
    log lines they produce. Returns the new state and the new log lines."""
    lines: list[str] = []
    while True:
        try:
            msg = message_queue.get_nowait()
        except queue.Empty:
            break
        state = reduce(state, msg)
        line = _log_line(msg)
        if line:
            lines.append(line)
    return state, lines
