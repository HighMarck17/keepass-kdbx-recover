"""Tkinter GUI for keepass-kdbx-recover.

Importing this module has no side effects: no Tk root is created and no work
starts until ``main()`` (or ``KdbxRecoverApp``) runs. Recovery runs on a worker
thread; the engine talks to a ``TkReporter`` that enqueues messages, and the Tk
main loop drains the queue and updates the widgets (Tk is single-threaded).

The window is a two-step flow for a non-technical owner locked out of their own
vault: the Setup tab gathers the database and what they remember (with live, plain
guidance on what to fix), and the Run tab starts the search and shows the result
with next steps. Inspect and Help are optional reference tabs.
"""

import multiprocessing
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .. import __version__
from ..candidates import export_candidates
from ..config import check_paths, default, load, save, validate
from ..engine import RecoveryEngine, RecoveryError
from ..inspector import GpuAdvice, format_inspection, inspect_file
from . import guidance, theme
from .mapping import config_to_form, form_to_config
from .reporter import TkReporter, UiState, drain
from .theme import BG, GAP, PAD

POLL_MS = 100
INDENT = 28  # left indent that lines a mode's details up under its checkbox
DISCLAIMER = "Only recover databases you own or are authorized to recover."

HELP_TEXT = """\
{disclaimer}

How it works
  This tool does not break the encryption. It builds password guesses from what
  you remember and tries each one against your database until one opens it.

Step 1 - Setup
  - Choose your database (the .kdbx file). Add a keyfile only if your vault uses one.
  - Turn on one or more ways to describe the password:
      Its shape   - a pattern with placeholders for the characters you are unsure of:
                    ?d digit  ?l lowercase  ?u uppercase  ?s symbol  ?a any.
                    Example: Summer?d?d tries Summer00 to Summer99.
      Some pieces - words or numbers it was made from, separated by commas.
                    "Try every order" and "Try upper/lower/Capitalized" widen the search.
      A list      - a text file with one candidate password per line.

Step 2 - Run
  Press Start. Progress shows how many guesses have been tried. If the password is
  found it appears at the top with a Copy button; if not, the tips there suggest
  what to widen next.

Check database (optional)
  Shows how your database protects the password. If it uses AES-KDF a graphics card
  (via the external hashcat tool) is much faster; if it uses Argon2 this tool on your
  CPU is about as good as it gets.

Advanced
  Workers run the search in parallel (0 lets the tool choose). "Write the candidate
  list to a file" saves the guesses for an external tool instead of testing them here.
"""


def needs_scrollbar(content_height: int, viewport_height: int) -> bool:
    """True when the form is taller than its viewport, so a scrollbar is needed.

    Pure so the show/hide rule is unit-tested without a display.
    """
    return content_height > viewport_height


def wheel_units(delta: int) -> int:
    """Translate a <MouseWheel> delta into a yview_scroll unit count.

    On Windows the delta arrives in multiples of 120 (one notch); smaller deltas
    (for example a trackpad) scroll one unit in the matching direction. Scrolling
    the wheel up gives a positive delta and moves the view toward the top (negative
    units).
    """
    if delta == 0:
        return 0
    if abs(delta) >= 120:
        return int(-delta / 120)
    return -1 if delta > 0 else 1


class KdbxRecoverApp:
    def __init__(self, root: tk.Tk, config_path: str = "config.toml",
                 style: ttk.Style | None = None):
        self.root = root
        self.config_path = config_path
        self.style = style or theme.apply_theme(root)
        self.mono = (getattr(self.style, "mono_family", "TkFixedFont"), 10)

        self.running = False
        self._cancelled = False
        self.state = UiState()
        self._pbar_mode = ""
        # The last run's outcome line, kept on the Run tab across tab switches and
        # revalidations until a new run starts or the form is edited.
        self._outcome_text: str | None = None
        self._outcome_style = "Ok.TLabel"
        self._setup_scroll_on = False  # whether the Setup form currently scrolls
        self.queue: queue.Queue = queue.Queue()
        self.cancel: threading.Event | None = None
        self.thread: threading.Thread | None = None

        self.vars: dict[str, tk.Variable] = {}
        self.found_var = tk.StringVar()
        self.inspect_path_var = tk.StringVar()

        root.title("keepass-kdbx-recover")
        root.minsize(820, 600)
        root.geometry("880x880")

        self._build_header()
        self._build_notebook()
        self._build_footer()

        self._load_initial_config()
        self._sync_advanced_from_config()
        self._add_traces()
        self._sync_modes()
        self._revalidate()

    # ---- construction -------------------------------------------------------

    def _var(self, key: str, boolean: bool = False) -> tk.Variable:
        var: tk.Variable = tk.BooleanVar() if boolean else tk.StringVar()
        self.vars[key] = var
        return var

    def _build_header(self) -> None:
        header = ttk.Frame(self.root, style="Header.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="keepass-kdbx-recover", style="Header.TLabel").pack(
            side="top", anchor="w", padx=12, pady=(10, 0))
        ttk.Label(header,
                  text="Recover your own KeePass master password from what you still remember.",
                  style="Sub.TLabel").pack(side="top", anchor="w", padx=12)
        ttk.Label(header, text=DISCLAIMER, style="Disclaimer.TLabel").pack(
            side="top", anchor="w", padx=12, pady=(4, 10))

    def _build_notebook(self) -> None:
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=8, pady=4)
        self._build_setup_tab()
        self._build_recovery_tab()
        self._build_inspect_tab()
        self._build_help_tab()

    def _build_footer(self) -> None:
        footer = ttk.Frame(self.root)
        footer.pack(fill="x", side="bottom")
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(footer, textvariable=self.status_var).pack(side="left", padx=10, pady=4)
        ttk.Label(footer, text=f"v{__version__}", style="Muted.TLabel").pack(side="right", padx=10)

    def _labeled_entry(self, parent, row, label, var, browse=None, width=40):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", padx=PAD, pady=GAP)
        entry = ttk.Entry(parent, textvariable=var, width=width)
        entry.grid(row=row, column=1, sticky="ew", padx=PAD, pady=GAP)
        if browse is not None:
            ttk.Button(parent, text="Browse...", command=browse).grid(
                row=row, column=2, sticky="e", padx=PAD, pady=GAP)
        parent.columnconfigure(1, weight=1)
        return entry

    def _hint(self, parent, row, text, column=1, columnspan=2):
        """A small muted helper line under a field."""
        lbl = ttk.Label(parent, text=text, style="Muted.TLabel", justify="left", wraplength=560)
        lbl.grid(row=row, column=column, columnspan=columnspan, sticky="w", padx=PAD, pady=(0, GAP))
        return lbl

    def _build_setup_tab(self) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Setup")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(2, weight=1)  # the scrollable form area takes the slack

        # The intro and status banner stay pinned above the scroll area so the
        # "what to do / what to fix" guidance is always visible.
        ttk.Label(
            tab,
            text="Step 1 of 2. Point to your database and describe what you remember, then "
                 "open the Run tab. Everything stays on this computer - nothing is sent anywhere.",
            style="Intro.TLabel", wraplength=800, justify="left").grid(
            row=0, column=0, sticky="ew", padx=PAD, pady=(GAP, PAD))

        banner = ttk.Frame(tab)
        banner.grid(row=1, column=0, sticky="ew", padx=PAD)
        banner.columnconfigure(0, weight=1)
        self.setup_hint_lbl = ttk.Label(banner, text="", style="Ok.TLabel",
                                        wraplength=800, justify="left")
        self.setup_hint_lbl.grid(row=0, column=0, sticky="ew")
        self.setup_errors_lbl = ttk.Label(banner, text="", style="Muted.TLabel",
                                          wraplength=800, justify="left")
        self.setup_errors_lbl.grid(row=1, column=0, sticky="ew", pady=(2, 0))
        self.setup_errors_lbl.grid_remove()

        self._build_scrollable_form(tab, row=2)

    def _build_scrollable_form(self, tab, row) -> None:
        """A Canvas + inner frame + ttk.Scrollbar holding the form groups, so a tall
        form (all modes on, Advanced open) never clips. The scrollbar is shown only
        when the content does not fit, and the wheel is bound to this subtree only."""
        area = ttk.Frame(tab)
        area.grid(row=row, column=0, sticky="nsew")
        area.columnconfigure(0, weight=1)
        area.rowconfigure(0, weight=1)

        canvas = tk.Canvas(area, background=BG, borderwidth=0, highlightthickness=0)
        canvas.grid(row=0, column=0, sticky="nsew")
        vbar = ttk.Scrollbar(area, orient="vertical", command=canvas.yview)
        vbar.grid(row=0, column=1, sticky="ns")
        vbar.grid_remove()  # appears only when the form overflows
        canvas.configure(yscrollcommand=vbar.set)

        inner = ttk.Frame(canvas)
        inner.columnconfigure(0, weight=1)
        window = canvas.create_window((0, 0), window=inner, anchor="nw")

        self.setup_canvas = canvas
        self.setup_vbar = vbar
        self.setup_inner = inner
        self.setup_window = window

        self._build_database_group(inner, row=0)
        self._build_modes_group(inner, row=1)
        self._build_advanced_group(inner, row=2)

        inner.bind("<Configure>", lambda _e: self._update_setup_scroll())
        canvas.bind("<Configure>", self._on_setup_canvas_configure)
        # Scope wheel scrolling to the Setup subtree (not the Run log or other tabs)
        # by binding the handler to every widget in it rather than using bind_all.
        self._bind_setup_wheel(canvas)
        self._bind_setup_wheel(inner)

    def _bind_setup_wheel(self, widget) -> None:
        widget.bind("<MouseWheel>", self._on_setup_wheel)
        widget.bind("<Button-4>", self._on_setup_wheel)  # X11 wheel up
        widget.bind("<Button-5>", self._on_setup_wheel)  # X11 wheel down
        for child in widget.winfo_children():
            self._bind_setup_wheel(child)

    def _on_setup_canvas_configure(self, event) -> None:
        # Keep the inner frame as wide as the canvas so fields still expand to the
        # right and nothing is cut off; then re-check whether a scrollbar is needed.
        self.setup_canvas.itemconfigure(self.setup_window, width=event.width)
        self._update_setup_scroll()

    def _setup_content_height(self) -> int:
        """Rendered height of the form (bottom of its lowest visible group).

        Uses actual laid-out geometry rather than requested height: ttk's requested
        heights can over-count by a wrapped label or trailing padding, which would
        flash a scrollbar even when everything already fits on screen.
        """
        bottom = 0
        for child in self.setup_inner.winfo_children():
            if child.winfo_ismapped():
                bottom = max(bottom, child.winfo_y() + child.winfo_height())
        return bottom

    def _update_setup_scroll(self) -> None:
        canvas = self.setup_canvas
        canvas.configure(scrollregion=canvas.bbox("all"))
        # A few pixels of slop so bottom padding alone never shows the scrollbar.
        self._setup_scroll_on = needs_scrollbar(
            self._setup_content_height(), canvas.winfo_height() + 6)
        if self._setup_scroll_on:
            if self.setup_vbar.winfo_manager() == "":
                self.setup_vbar.grid()
        else:
            if self.setup_vbar.winfo_manager() != "":
                self.setup_vbar.grid_remove()
            canvas.yview_moveto(0.0)

    def _on_setup_wheel(self, event):
        if not self._setup_scroll_on:
            return None  # nothing to scroll; let the event pass through
        if event.num == 4:
            self.setup_canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            self.setup_canvas.yview_scroll(1, "units")
        else:
            self.setup_canvas.yview_scroll(wheel_units(event.delta), "units")
        return "break"

    def _build_database_group(self, tab, row) -> None:
        db = ttk.LabelFrame(tab, text="Your database")
        db.grid(row=row, column=0, sticky="ew", padx=PAD, pady=GAP)
        self.db_entry = self._labeled_entry(
            db, 0, "Database (.kdbx)", self._var("db_path"),
            browse=lambda: self._browse_open("db_path"))
        self._labeled_entry(db, 1, "Keyfile", self._var("keyfile"),
                            browse=lambda: self._browse_open("keyfile"))
        self._hint(db, 2, "Only if your vault also uses a key file. Leave empty otherwise.")

    def _build_modes_group(self, tab, row) -> None:
        modes = ttk.LabelFrame(tab, text="What do you remember?")
        modes.grid(row=row, column=0, sticky="ew", padx=PAD, pady=GAP)
        modes.columnconfigure(0, weight=1)
        ttk.Label(modes, text="Turn on one or more ways to describe it; the details for each "
                              "appear as you switch it on.",
                  style="Muted.TLabel", wraplength=800, justify="left").grid(
            row=0, column=0, sticky="w", padx=PAD, pady=(0, GAP))

        # Mask ----------------------------------------------------------------
        ttk.Checkbutton(
            modes, text="Its shape - a word or pattern with some unknown characters",
            variable=self._var("mask_enabled", boolean=True)).grid(
            row=1, column=0, sticky="w", padx=PAD)
        self.mask_detail = ttk.Frame(modes)
        self.mask_detail.grid(row=2, column=0, sticky="ew", padx=(INDENT, PAD))
        self.mask_detail.columnconfigure(1, weight=1)
        ttk.Label(self.mask_detail, text="Pattern").grid(row=0, column=0, sticky="w", pady=GAP)
        ttk.Entry(self.mask_detail, textvariable=self._var("mask_pattern")).grid(
            row=0, column=1, sticky="ew", padx=PAD, pady=GAP)
        ttk.Label(
            self.mask_detail,
            text="Type the characters you know; use a placeholder for each one you are unsure of:\n"
                 "?d a digit    ?l a lowercase letter    ?u an uppercase letter    "
                 "?s a symbol    ?a any of these.\n"
                 "Example: Summer?d?d tries Summer00 through Summer99.",
            style="Muted.TLabel", justify="left", wraplength=700).grid(
            row=1, column=0, columnspan=2, sticky="w", pady=(0, GAP))

        # Fragments -----------------------------------------------------------
        ttk.Checkbutton(
            modes, text="Some pieces of it - words or numbers it was built from",
            variable=self._var("fragments_enabled", boolean=True)).grid(
            row=3, column=0, sticky="w", padx=PAD)
        self.frag_detail = ttk.Frame(modes)
        self.frag_detail.grid(row=4, column=0, sticky="ew", padx=(INDENT, PAD))
        self.frag_detail.columnconfigure(1, weight=1)
        ttk.Label(self.frag_detail, text="Pieces").grid(row=0, column=0, sticky="w", pady=GAP)
        ttk.Entry(self.frag_detail, textvariable=self._var("fragments_pieces")).grid(
            row=0, column=1, sticky="ew", padx=PAD, pady=GAP)
        self._hint(self.frag_detail, 1, "Separate the pieces with commas, e.g. sun, flower, 42",
                   column=0, columnspan=2)
        opts = ttk.Frame(self.frag_detail)
        opts.grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, GAP))
        ttk.Checkbutton(
            opts, text="Try every order",
            variable=self._var("fragments_permutations", boolean=True)).pack(side="left")
        ttk.Checkbutton(opts, text="Try upper / lower / Capitalized",
                        variable=self._var("fragments_case_variants", boolean=True)).pack(
            side="left", padx=16)
        ttk.Label(self.frag_detail, text="Always first").grid(row=3, column=0, sticky="w", pady=GAP)
        ttk.Entry(self.frag_detail, textvariable=self._var("fragments_fixed_prefix")).grid(
            row=3, column=1, sticky="ew", padx=PAD, pady=GAP)
        ttk.Label(self.frag_detail, text="Fewest pieces").grid(
            row=4, column=0, sticky="w", pady=GAP)
        ttk.Spinbox(self.frag_detail, from_=1, to=64, width=5,
                    textvariable=self._var("fragments_min_fragments")).grid(
            row=4, column=1, sticky="w", padx=PAD, pady=GAP)
        ttk.Label(
            self.frag_detail,
            text='"Always first" must be one of the pieces; "Fewest pieces" is the smallest '
                 "number combined at once (1 tries each piece alone).",
            style="Muted.TLabel", justify="left", wraplength=760).grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(0, GAP))

        # Wordlist ------------------------------------------------------------
        ttk.Checkbutton(
            modes, text="A list in a file - one candidate password per line",
            variable=self._var("wordlist_enabled", boolean=True)).grid(
            row=5, column=0, sticky="w", padx=PAD)
        self.word_detail = ttk.Frame(modes)
        self.word_detail.grid(row=6, column=0, sticky="ew", padx=(INDENT, PAD))
        self.word_detail.columnconfigure(1, weight=1)
        ttk.Label(self.word_detail, text="List file").grid(row=0, column=0, sticky="w", pady=GAP)
        ttk.Entry(self.word_detail, textvariable=self._var("wordlist_path")).grid(
            row=0, column=1, sticky="ew", padx=PAD, pady=GAP)
        ttk.Button(self.word_detail, text="Browse...",
                   command=lambda: self._browse_open("wordlist_path")).grid(
            row=0, column=2, sticky="e", padx=PAD, pady=GAP)

    def _build_advanced_group(self, tab, row) -> None:
        adv = ttk.LabelFrame(tab, text="Advanced (optional)")
        adv.grid(row=row, column=0, sticky="ew", padx=PAD, pady=GAP)
        adv.columnconfigure(0, weight=1)
        # Collapsed by default so the common view stays short; most people never
        # need these. Opening it reveals workers, speed, export and saved setups.
        self.adv_open = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            adv, text="Show advanced settings (workers, speed, export, saved setups)",
            variable=self.adv_open, command=self._sync_advanced).grid(
            row=0, column=0, sticky="w", padx=PAD, pady=(0, GAP))

        body = ttk.Frame(adv)
        body.grid(row=1, column=0, sticky="ew")
        body.columnconfigure(1, weight=1)
        self.adv_body = body

        ttk.Label(body, text="Workers").grid(row=0, column=0, sticky="w", padx=PAD, pady=GAP)
        ttk.Spinbox(body, from_=0, to=64, width=5, textvariable=self._var("workers")).grid(
            row=0, column=1, sticky="w", padx=PAD, pady=GAP)
        ttk.Label(body, text="Parallel processes; 0 lets the tool choose.",
                  style="Muted.TLabel").grid(row=0, column=2, sticky="w", padx=PAD)

        ttk.Label(body, text="Progress every").grid(row=1, column=0, sticky="w", padx=PAD, pady=GAP)
        ttk.Spinbox(body, from_=0.5, to=60, increment=0.5, width=6,
                    textvariable=self._var("progress_interval")).grid(
            row=1, column=1, sticky="w", padx=PAD, pady=GAP)
        ttk.Label(body, text="Seconds between progress updates.",
                  style="Muted.TLabel").grid(row=1, column=2, sticky="w", padx=PAD)

        ttk.Checkbutton(body, text="Write the candidate list to a file instead of testing it",
                        variable=self._var("export_enabled", boolean=True)).grid(
            row=2, column=0, columnspan=3, sticky="w", padx=PAD, pady=(GAP, 0))
        ttk.Label(body, text="For experts using an external tool such as hashcat.",
                  style="Muted.TLabel").grid(row=3, column=0, columnspan=3, sticky="w", padx=PAD)
        self._labeled_entry(body, 4, "Save list to", self._var("export_path"),
                            browse=lambda: self._browse_save("export_path"))

        cfgfile = ttk.Frame(body)
        cfgfile.grid(row=5, column=0, columnspan=3, sticky="w", padx=PAD, pady=(GAP, 0))
        ttk.Button(cfgfile, text="Load setup...", command=self._on_load_config).pack(side="left")
        ttk.Button(cfgfile, text="Save setup...", command=self._on_save_config).pack(
            side="left", padx=8)

        self._sync_advanced()

    def _sync_advanced(self) -> None:
        """Show or hide the advanced body and refresh the scroll state."""
        if self.adv_open.get():
            self.adv_body.grid()
        else:
            self.adv_body.grid_remove()
        if hasattr(self, "setup_canvas"):
            self._update_setup_scroll()

    def _sync_advanced_from_config(self) -> None:
        """Open the advanced section at startup only when a loaded config set one of
        its values away from the defaults, so nothing the user saved is hidden."""
        workers = str(self.vars["workers"].get()).strip()
        interval = str(self.vars["progress_interval"].get()).strip()
        if (bool(self.vars["export_enabled"].get())
                or workers not in ("", "0")
                or interval not in ("", "2.0", "2")):
            self.adv_open.set(True)
            self._sync_advanced()

    def _build_recovery_tab(self) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Run")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(5, weight=1)

        ttk.Label(
            tab, text="Step 2 of 2. Press Start and let it work. You can cancel at any time.",
            style="Intro.TLabel", wraplength=800, justify="left").grid(
            row=0, column=0, sticky="ew", padx=PAD, pady=(GAP, GAP))

        self.run_guidance = ttk.Label(tab, text="", style="Ok.TLabel",
                                      wraplength=800, justify="left")
        self.run_guidance.grid(row=1, column=0, sticky="ew", padx=PAD, pady=(0, GAP))

        ctl = ttk.Frame(tab)
        ctl.grid(row=2, column=0, sticky="ew", padx=PAD, pady=GAP)
        self.start_btn = ttk.Button(
            ctl, text="Start", style="Primary.TButton", command=self._on_start)
        self.start_btn.pack(side="left")
        self.cancel_btn = ttk.Button(ctl, text="Cancel", command=self._on_cancel, state="disabled")
        self.cancel_btn.pack(side="left", padx=8)

        prog = ttk.Frame(tab)
        prog.grid(row=3, column=0, sticky="ew", padx=PAD, pady=GAP)
        prog.columnconfigure(0, weight=1)
        self.pbar = ttk.Progressbar(prog, mode="determinate")
        self.pbar.grid(row=0, column=0, sticky="ew")
        self.status_line = ttk.Label(prog, text="", style="Muted.TLabel")
        self.status_line.grid(row=1, column=0, sticky="ew", pady=(GAP, 0))

        result = ttk.LabelFrame(tab, text="Master password")
        result.grid(row=4, column=0, sticky="ew", padx=PAD, pady=GAP)
        result.columnconfigure(0, weight=1)
        self.found_entry = ttk.Entry(
            result, textvariable=self.found_var, state="readonly", font=(self.mono[0], 13))
        self.found_entry.grid(row=0, column=0, sticky="ew", padx=PAD, pady=GAP)
        self.copy_btn = ttk.Button(
            result, text="Copy", command=self._copy_password, state="disabled")
        self.copy_btn.grid(row=0, column=1, sticky="e", padx=PAD, pady=GAP)
        ttk.Label(result, text="The password appears here when it is found. Keep it private.",
                  style="Muted.TLabel").grid(
            row=1, column=0, columnspan=2, sticky="w", padx=PAD, pady=(0, GAP))

        logframe = ttk.LabelFrame(tab, text="Details")
        logframe.grid(row=5, column=0, sticky="nsew", padx=PAD, pady=GAP)
        logframe.columnconfigure(0, weight=1)
        logframe.rowconfigure(0, weight=1)
        self.log = tk.Text(logframe, state="disabled", wrap="word", height=6, font=self.mono)
        self.log.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(logframe, command=self.log.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)

    def _build_inspect_tab(self) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Check database")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(3, weight=1)

        ttk.Label(
            tab,
            text="Optional. See how your database protects the password, and whether a "
                 "graphics-card tool would be faster. Nothing is unlocked here.",
            style="Intro.TLabel", wraplength=800, justify="left").grid(
            row=0, column=0, sticky="ew", padx=PAD, pady=(GAP, GAP))

        pick = ttk.Frame(tab)
        pick.grid(row=1, column=0, sticky="ew", padx=PAD, pady=GAP)
        pick.columnconfigure(1, weight=1)
        ttk.Label(pick, text="Database (.kdbx)").grid(row=0, column=0, sticky="w")
        ttk.Entry(pick, textvariable=self.inspect_path_var).grid(
            row=0, column=1, sticky="ew", padx=PAD)
        ttk.Button(pick, text="Browse...", command=self._browse_inspect).grid(row=0, column=2)
        ttk.Button(pick, text="Check", command=self._on_inspect).grid(
            row=0, column=3, padx=(8, 0))

        self.advice_lbl = ttk.Label(tab, text="Choose a database above and press Check.",
                                    style="AdviceUnknown.TLabel", wraplength=800, justify="left")
        self.advice_lbl.grid(row=2, column=0, sticky="ew", padx=PAD, pady=GAP)

        self.report_txt = tk.Text(tab, state="disabled", height=10, font=self.mono)
        self.report_txt.grid(row=3, column=0, sticky="nsew", padx=PAD, pady=GAP)

    def _build_help_tab(self) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Help")
        text = tk.Text(tab, state="normal", wrap="word")
        text.insert("1.0", HELP_TEXT.format(disclaimer=DISCLAIMER))
        text.configure(state="disabled")
        text.pack(fill="both", expand=True, padx=PAD, pady=PAD)

    # ---- form <-> vars ------------------------------------------------------

    def _read_form(self) -> dict:
        return {key: var.get() for key, var in self.vars.items()}

    def _apply_form(self, values: dict) -> None:
        for key, var in self.vars.items():
            value = values.get(key)
            if isinstance(var, tk.BooleanVar):
                var.set(bool(value))
            else:
                var.set("" if value is None else str(value))

    def _load_initial_config(self) -> None:
        path = Path(self.config_path)
        cfg = default()
        if path.is_file():
            try:
                cfg = load(path)
            except Exception:
                cfg = default()
        self._apply_form(config_to_form(cfg))

    def _add_traces(self) -> None:
        # Editing the form clears any finished-run outcome (the "ready / what to
        # fix" guidance is the relevant one again); switching tabs must not.
        for var in self.vars.values():
            var.trace_add("write", lambda *_: self._on_form_change())
        for key in ("mask_enabled", "fragments_enabled", "wordlist_enabled"):
            self.vars[key].trace_add("write", lambda *_: self._sync_modes())
        self.notebook.bind("<<NotebookTabChanged>>", lambda _e: self._revalidate())

    def _on_form_change(self) -> None:
        self._outcome_text = None
        self._revalidate()

    def _sync_modes(self) -> None:
        """Show each mode's detail fields only while that mode is enabled, so the
        Setup tab stays short and the user is not faced with every option at once."""
        for key, frame in (("mask_enabled", self.mask_detail),
                           ("fragments_enabled", self.frag_detail),
                           ("wordlist_enabled", self.word_detail)):
            if bool(self.vars[key].get()):
                frame.grid()
            else:
                frame.grid_remove()

    def _revalidate(self) -> None:
        cfg = form_to_config(self._read_form())
        errors = validate(cfg) + check_paths(cfg)
        self._update_guidance(errors)
        if hasattr(self, "start_btn"):
            self.start_btn.configure(state="disabled" if (errors or self.running) else "normal")

    def _update_guidance(self, errors: list[str]) -> None:
        """Refresh the plain-language guidance shown on both tabs from the errors."""
        self.setup_hint_lbl.configure(
            text=guidance.setup_summary(errors),
            style="Warn.TLabel" if errors else "Ok.TLabel")
        if len(errors) > 1:
            self.setup_errors_lbl.configure(text="\n".join("- " + e for e in errors))
            self.setup_errors_lbl.grid()
        else:
            self.setup_errors_lbl.configure(text="")
            self.setup_errors_lbl.grid_remove()
        # The Run tab shows, in order of priority: the live "Working..." line while
        # a run is in progress (owned by _on_start), the finished run's outcome
        # until the form is next edited, otherwise why Start is on or off.
        if hasattr(self, "run_guidance") and not self.running:
            if self._outcome_text is not None:
                self.run_guidance.configure(text=self._outcome_text, style=self._outcome_style)
            else:
                self.run_guidance.configure(
                    text=guidance.run_blocker(errors),
                    style="Warn.TLabel" if errors else "Ok.TLabel")

    # ---- dialogs ------------------------------------------------------------

    def _browse_open(self, key: str) -> None:
        types = [("KeePass database", "*.kdbx"), ("All files", "*.*")]
        path = filedialog.askopenfilename(filetypes=types)
        if path:
            self.vars[key].set(path)

    def _browse_inspect(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("KeePass database", "*.kdbx"), ("All files", "*.*")])
        if path:
            self.inspect_path_var.set(path)

    def _browse_save(self, key: str) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            self.vars[key].set(path)

    def _on_load_config(self) -> None:
        path = filedialog.askopenfilename(
            filetypes=[("TOML config", "*.toml"), ("All files", "*.*")])
        if not path:
            return
        try:
            cfg = load(path)
        except Exception as exc:
            messagebox.showerror("Load setup", f"Could not load the setup file:\n{exc}")
            return
        self._apply_form(config_to_form(cfg))

    def _on_save_config(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".toml", initialfile="config.toml")
        if not path:
            return
        try:
            save(form_to_config(self._read_form()), path)
        except OSError as exc:
            messagebox.showerror("Save setup", f"Could not save the setup file:\n{exc}")

    # ---- recovery -----------------------------------------------------------

    def _on_start(self) -> None:
        cfg = form_to_config(self._read_form())
        errors = validate(cfg) + check_paths(cfg)
        if errors:
            messagebox.showerror("Cannot start", "\n".join(errors))
            return

        self.running = True
        self._cancelled = False
        self._outcome_text = None  # a fresh run clears the previous outcome line
        # Seed running=True so an empty first poll (engine preflight slower than
        # POLL_MS) is not mistaken for a finished run.
        self.state = UiState(running=True)
        self.queue = queue.Queue()
        self.cancel = threading.Event()
        self._pbar_mode = ""
        self.found_var.set("")
        self.copy_btn.configure(state="disabled")
        self._clear_text(self.log)
        self.start_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.run_guidance.configure(
            text="Working... this can take a while. Press Cancel to stop.", style="Ok.TLabel")
        self.status_var.set("Exporting..." if cfg.export.enabled else "Running...")

        reporter = TkReporter(self.queue)
        self.thread = threading.Thread(
            target=self._worker, args=(cfg, reporter, self.cancel), daemon=True)
        self.thread.start()
        self.root.after(POLL_MS, self._poll)

    def _worker(self, cfg, reporter, cancel) -> None:
        try:
            if cfg.export.enabled:
                self._export(cfg, reporter, cancel)
            else:
                RecoveryEngine().run(cfg, reporter, cancel)
        except RecoveryError as exc:
            reporter.error(str(exc))
        except Exception as exc:  # never let the worker die silently
            reporter.error(f"Unexpected error: {exc}")

    @staticmethod
    def _export(cfg, reporter, cancel) -> None:
        path = cfg.export.path
        try:
            written = export_candidates(cfg, path, cancel=cancel)
        except OSError as exc:
            reporter.error(f"Cannot write {path}: {exc}")
            return
        if cancel.is_set():
            reporter.exported(f"Export stopped after {written:,} candidates; {path} is incomplete.")
        else:
            reporter.exported(f"Wrote {written:,} candidates to {path}")

    def _poll(self) -> None:
        self.state, lines = drain(self.queue, self.state)
        for line in lines:
            self._append(self.log, line)
        self._apply_state(self.state)
        if self.state.finished:
            self._finish_run()
        elif self.thread is not None and not self.thread.is_alive():
            # Worker ended without a terminal message (should not happen); drain any
            # last messages and stop rather than poll forever.
            self.state, extra = drain(self.queue, self.state)
            for line in extra:
                self._append(self.log, line)
            self._apply_state(self.state)
            self._finish_run()
        else:
            self.root.after(POLL_MS, self._poll)

    def _apply_state(self, state: UiState) -> None:
        self.status_line.configure(text=state.status_line)
        if state.determinate and state.total:
            if self._pbar_mode != "determinate":
                self.pbar.stop()
                self.pbar.configure(mode="determinate", maximum=state.total)
                self._pbar_mode = "determinate"
            self.pbar["value"] = state.tested
        elif state.running:
            if self._pbar_mode != "indeterminate":
                self.pbar.configure(mode="indeterminate")
                self.pbar.start(12)
                self._pbar_mode = "indeterminate"
        if state.found:
            self.found_var.set(state.found)

    def _finish_run(self) -> None:
        self.running = False
        self.pbar.stop()
        if self._pbar_mode == "determinate" and self.state.found:
            self.pbar["value"] = self.pbar["maximum"]
        self.cancel_btn.configure(state="disabled")
        if self.state.error:
            self.status_var.set("Error")
            messagebox.showerror("Recovery error", self.state.error)
        elif self.state.found:
            self.status_var.set("Password found.")
            self.copy_btn.configure(state="normal")
        elif self._cancelled:
            self.status_var.set("Cancelled.")
        else:
            self.status_var.set("Done.")
        # Record the outcome, then revalidate; _update_guidance shows it (and keeps
        # showing it across tab switches) until the form is next edited.
        self._outcome_text = guidance.outcome(found=bool(self.state.found),
                                              cancelled=self._cancelled,
                                              error=bool(self.state.error))
        self._outcome_style = ("Error.TLabel" if self.state.error
                               else "Ok.TLabel" if self.state.found else "Warn.TLabel")
        self._revalidate()  # re-enable Start; refresh both guidance lines

    def _on_cancel(self) -> None:
        self._cancelled = True
        if self.cancel is not None:
            self.cancel.set()
        self.cancel_btn.configure(state="disabled")
        self.status_var.set("Cancelling...")

    def _copy_password(self) -> None:
        pw = self.found_var.get()
        if pw:
            self.root.clipboard_clear()
            self.root.clipboard_append(pw)
            self.status_var.set("Password copied to clipboard.")

    # ---- inspect ------------------------------------------------------------

    def _on_inspect(self) -> None:
        path = self.inspect_path_var.get() or self.vars["db_path"].get()
        if not path:
            self.advice_lbl.configure(
                text="Choose a .kdbx file to check.", style="AdviceUnknown.TLabel")
            return
        try:
            insp = inspect_file(path)
        except (ValueError, OSError) as exc:
            self.advice_lbl.configure(text=str(exc), style="Error.TLabel")
            self._clear_text(self.report_txt)
            return
        self._clear_text(self.report_txt)
        self._append(self.report_txt, format_inspection(insp))
        if insp.gpu_advice is GpuAdvice.BIG_ADVANTAGE:
            self.advice_lbl.configure(
                text=f"This database uses {insp.kdf}, which a graphics card (GPU) can attack "
                     f"much faster. Advanced users can turn on 'Write the candidate list to a "
                     f"file' on the Setup tab and run it through hashcat (-m 13400).",
                style="AdviceBig.TLabel")
        elif insp.gpu_advice is GpuAdvice.LITTLE_ADVANTAGE:
            self.advice_lbl.configure(
                text=f"This database uses {insp.kdf}, which is memory-hard by design. A graphics "
                     f"card gives little advantage, so running here on your CPU is about as good "
                     f"as it gets.",
                style="AdviceLittle.TLabel")
        else:
            self.advice_lbl.configure(
                text="The key-protection method was not recognized, so the speed-up from a "
                     "graphics card is unknown.",
                style="AdviceUnknown.TLabel")

    # ---- text helpers -------------------------------------------------------

    def _append(self, widget: tk.Text, text: str) -> None:
        widget.configure(state="normal")
        widget.insert("end", text + "\n")
        widget.configure(state="disabled")
        widget.see("end")

    def _clear_text(self, widget: tk.Text) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.configure(state="disabled")

    # ---- window -------------------------------------------------------------

    def on_close(self) -> None:
        if self.running and self.cancel is not None:
            self.cancel.set()
        self.root.destroy()


def enable_dpi_awareness() -> None:
    """Make the process DPI-aware on Windows so Tk renders crisply on high-DPI
    displays (otherwise Windows bitmap-stretches the window and it looks blurry).
    No-op on other platforms and if the call is unavailable."""
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)  # system DPI aware
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


def main(config_path: str = "config.toml") -> int:
    multiprocessing.freeze_support()  # first, for Windows spawn children
    enable_dpi_awareness()
    root = tk.Tk()
    style = theme.apply_theme(root)
    app = KdbxRecoverApp(root, config_path=config_path, style=style)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
    return 0
