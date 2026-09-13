"""Progress reporting abstraction.

The recovery engine emits progress through a ProgressReporter, so it never needs
to know whether the output goes to a console line or a GUI progress bar. A
ProgressEvent carries the raw counters; rate and ETA are derived on demand.
"""

from dataclasses import dataclass
from typing import Protocol


def fmt_time(seconds: float) -> str:
    """Format a duration in seconds as e.g. '5s', '3m07s', '1h02m03s'."""
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h{m:02d}m{s:02d}s"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


@dataclass
class ProgressEvent:
    """A snapshot of recovery progress."""

    tested: int
    total: int | None
    elapsed: float
    candidate: str | None = None
    status: str | None = None

    @property
    def rate(self) -> float:
        """Candidates tested per second."""
        return self.tested / self.elapsed if self.elapsed > 0 else 0.0

    @property
    def eta(self) -> float | None:
        """Estimated seconds remaining, or None when the total is unknown."""
        if self.total and self.rate > 0:
            return (self.total - self.tested) / self.rate
        return None


def format_progress_line(event: ProgressEvent) -> str:
    """Render a one-line progress string for the console."""
    rate = event.rate
    tail = ""
    if event.candidate is not None:
        tail += f" | trying {event.candidate}"
    if event.status:
        tail += f" | {event.status}"
    if event.total:
        pct = event.tested / event.total * 100
        eta = event.eta or 0
        return (
            f"{event.tested:,}/{event.total:,} ({pct:.1f}%) | {rate:,.0f} pw/s | "
            f"elapsed {fmt_time(event.elapsed)} | ETA {fmt_time(eta)}{tail}"
        )
    return f"{event.tested:,} tested | {rate:,.0f} pw/s | elapsed {fmt_time(event.elapsed)}{tail}"


def format_result(found: str | None, event: ProgressEvent) -> str:
    """Render the final summary line(s)."""
    if found is not None:
        return f"PASSWORD FOUND: {found}\nTried {event.tested:,} in {fmt_time(event.elapsed)}"
    return f"Password not found among {event.tested:,} candidates in {fmt_time(event.elapsed)}"


class ProgressReporter(Protocol):
    """Interface the engine emits to. CLI and GUI provide implementations."""

    def on_start(self, total: int | None) -> None: ...
    def on_progress(self, event: ProgressEvent) -> None: ...
    def on_found(self, password: str, event: ProgressEvent) -> None: ...
    def on_finish(self, found: str | None, event: ProgressEvent) -> None: ...


class ConsoleReporter:
    """Prints a live single-line progress and a final summary to stdout."""

    def on_start(self, total: int | None) -> None:
        if total:
            print(f"Candidates to test: {total:,}")
        else:
            print("Candidates to test: unknown (streaming)")

    def on_progress(self, event: ProgressEvent) -> None:
        # Trailing spaces clear leftovers from a previous, longer line.
        print("  " + format_progress_line(event) + " " * 8, end="\r", flush=True)

    def on_found(self, password: str, event: ProgressEvent) -> None:
        pass  # The summary is printed by on_finish.

    def on_finish(self, found: str | None, event: ProgressEvent) -> None:
        print()
        print(format_result(found, event))
