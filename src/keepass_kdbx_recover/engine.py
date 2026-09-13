"""Recovery engine.

Tries candidate passwords against a KDBX database until one opens it. The engine
is UI-agnostic: it reports progress through a ProgressReporter and can be stopped
through a cancel Event, so both the CLI and the GUI drive it the same way.
"""

import contextlib
import multiprocessing as mp
import threading
import time
from collections.abc import Iterator
from dataclasses import dataclass

from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError

from .candidates import build_candidates, count_total
from .config import Config
from .progress import ProgressEvent, ProgressReporter

# A password no human would choose, used to probe whether a failure is "wrong
# password" (CredentialsError) or a structural problem (anything else).
_PROBE = "\x00__keepass_kdbx_recover_preflight_probe__\x00"


class RecoveryError(Exception):
    """Raised when the database cannot be opened for reasons unrelated to the
    password (corrupt file, wrong keyfile, unsupported format)."""


@dataclass
class RecoveryResult:
    found: str | None
    tested: int
    elapsed: float


def resolve_workers(cfg: Config) -> int:
    """Number of worker processes: the configured value, or an auto default."""
    if cfg.recovery.workers and cfg.recovery.workers > 0:
        return cfg.recovery.workers
    return min(6, max(1, mp.cpu_count()))


def try_password(args: tuple[str, str | None, str]) -> tuple[bool, str]:
    """Worker: return (opened, password). Module-level so it is picklable."""
    db_path, keyfile, pwd = args
    try:
        PyKeePass(db_path, password=pwd, keyfile=keyfile)
        return True, pwd
    except CredentialsError:
        return False, pwd
    except Exception:
        # Any other error during a worker attempt is treated as a miss here;
        # systematic problems are caught up-front by the preflight probe.
        return False, pwd


class RecoveryEngine:
    def _preflight(self, db_path: str, keyfile: str | None) -> str | None:
        """Check the database opens structurally. Returns the probe password if it
        somehow succeeds (astronomically unlikely), None if the credentials were
        merely wrong. Raises RecoveryError for non-credential failures."""
        try:
            PyKeePass(db_path, password=_PROBE, keyfile=keyfile)
            return _PROBE
        except CredentialsError:
            return None
        except Exception as exc:  # corrupt file, bad keyfile, unsupported format
            raise RecoveryError(
                f"Cannot open the database (this is not a password problem): {exc}"
            ) from exc

    def _sequential(
        self, cfg: Config, db_path: str, keyfile: str | None
    ) -> Iterator[tuple[bool, str]]:
        for pwd in build_candidates(cfg):
            yield try_password((db_path, keyfile, pwd))

    def _parallel(
        self, cfg: Config, db_path: str, keyfile: str | None, workers: int
    ) -> Iterator[tuple[bool, str]]:
        args = ((db_path, keyfile, pwd) for pwd in build_candidates(cfg))
        with mp.Pool(workers) as pool:
            try:
                # chunksize=1: KDF is slow on purpose, so IPC overhead is irrelevant
                # and cancellation/feedback stay responsive.
                yield from pool.imap_unordered(try_password, args, chunksize=1)
            finally:
                pool.terminate()

    def run(
        self,
        cfg: Config,
        reporter: ProgressReporter,
        cancel: threading.Event | None = None,
    ) -> RecoveryResult:
        db_path = cfg.database.path
        keyfile = cfg.database.keyfile or None

        probe_hit = self._preflight(db_path, keyfile)

        total = count_total(cfg)
        reporter.on_start(total)
        start = time.time()
        tested = 0
        found: str | None = None
        last_report = start

        if probe_hit is not None:
            found = probe_hit
        else:
            workers = resolve_workers(cfg)
            results = (
                self._sequential(cfg, db_path, keyfile)
                if workers == 1
                else self._parallel(cfg, db_path, keyfile, workers)
            )
            with contextlib.closing(results):
                try:
                    for ok, pwd in results:
                        tested += 1
                        now = time.time()
                        if ok:
                            found = pwd
                            reporter.on_found(pwd, ProgressEvent(tested, total, now - start, pwd))
                            break
                        if cancel is not None and cancel.is_set():
                            break
                        if now - last_report >= cfg.recovery.progress_interval:
                            reporter.on_progress(ProgressEvent(tested, total, now - start, pwd))
                            last_report = now
                except KeyboardInterrupt:
                    pass

        elapsed = time.time() - start
        reporter.on_finish(found, ProgressEvent(tested, total, elapsed, found))
        return RecoveryResult(found, tested, elapsed)
