"""Tests for the plain-language GUI guidance strings (headless, no Tk).

The pure Setup-scroll helpers are covered here too; importing the app module is
headless-safe (tkinter imports without a display; only tk.Tk() needs one).
"""

from keepass_kdbx_recover.gui.app import needs_scrollbar, wheel_units
from keepass_kdbx_recover.gui.guidance import (
    READY,
    outcome,
    run_blocker,
    setup_summary,
)


def test_needs_scrollbar_only_when_content_exceeds_viewport():
    assert needs_scrollbar(900, 600) is True
    assert needs_scrollbar(600, 600) is False
    assert needs_scrollbar(400, 600) is False


def test_wheel_units_maps_windows_notches_and_small_deltas():
    assert wheel_units(120) == -1   # one notch up -> toward the top
    assert wheel_units(-120) == 1   # one notch down
    assert wheel_units(240) == -2   # two notches at once
    assert wheel_units(3) == -1     # small positive delta (trackpad) up
    assert wheel_units(-3) == 1
    assert wheel_units(0) == 0


def test_setup_summary_is_ready_when_there_are_no_errors():
    assert setup_summary([]) == READY


def test_setup_summary_leads_with_the_first_fix():
    assert setup_summary(["No database path is set."]).endswith("No database path is set.")


def test_setup_summary_counts_multiple_fixes_but_shows_only_the_first():
    summary = setup_summary(["first thing", "second thing"])
    assert "2 things to fix" in summary
    assert "first thing" in summary
    assert "second thing" not in summary


def test_run_blocker_is_ready_when_valid_and_points_back_when_not():
    assert "Start" in run_blocker([])
    blocked = run_blocker(["No database path is set."])
    assert "Setup" in blocked
    assert "No database path is set." in blocked


def test_outcome_covers_each_terminal_state():
    assert "Copy" in outcome(found=True, cancelled=False, error=False)
    assert "wrong" in outcome(found=False, cancelled=False, error=True)
    assert "Stopped" in outcome(found=False, cancelled=True, error=False)
    not_found = outcome(found=False, cancelled=False, error=False)
    assert "Case variants" in not_found and "keyfile" in not_found
