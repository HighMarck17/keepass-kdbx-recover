"""Plain-language guidance strings for the GUI (Tk-free, unit-testable).

These turn the validation errors and the run outcome into short, non-technical
sentences that tell a locked-out owner what to do next. They live apart from the
Tk code so the wording is covered by headless tests and reused in two places (the
Setup banner and the Run tab) without duplicating the phrasing.
"""

READY = "Ready to run. Open the Run tab and press Start."


def setup_summary(errors: list[str]) -> str:
    """One line for the top of the Setup tab: ready, or the first thing to fix.

    When more than one thing is missing we still lead with a single, concrete
    action so the user is never faced with a wall of red at once.
    """
    if not errors:
        return READY
    if len(errors) == 1:
        return "Before you can start: " + errors[0]
    return f"Before you can start ({len(errors)} things to fix). First: " + errors[0]


def run_blocker(errors: list[str]) -> str:
    """One line for the Run tab before a run: why Start is off, or that it is ready."""
    if not errors:
        return "Ready. Press Start to begin the search."
    return "Finish the Setup tab first - " + errors[0]


def outcome(found: bool, cancelled: bool, error: bool) -> str:
    """Next-step guidance shown when a run ends (one case applies)."""
    if error:
        return "Something went wrong. Check the database and keyfile, then try again."
    if found:
        return "Found it. Press Copy, open your vault in KeePass, then consider changing it."
    if cancelled:
        return "Stopped before the end. Adjust the Setup tab if needed and run again."
    return (
        "Not found. In Setup, try turning on Case variants, add more pieces or a "
        "wider mask - and if your vault uses a keyfile, make sure it is the right one."
    )
