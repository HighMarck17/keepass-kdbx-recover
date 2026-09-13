"""Tkinter GUI for keepass-kdbx-recover.

Importing this module has no side effects: no Tk root is created and no work
starts until ``main()`` (or ``KdbxRecoverApp``) runs. Recovery runs on a worker
thread; the engine talks to a ``TkReporter`` that enqueues messages, and the Tk
main loop drains the queue and updates the widgets (Tk is single-threaded).
"""

import multiprocessing
import queue
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from .. import __version__
from ..config import check_paths, default, load, save, validate
from ..engine import RecoveryEngine, RecoveryError
from ..inspector import GpuAdvice, format_inspection, inspect_file
from . import theme
from .mapping import config_to_form, form_to_config
from .reporter import TkReporter, UiState, drain
from .theme import GAP, PAD

POLL_MS = 100
DISCLAIMER = "Only recover databases you own or are authorized to recover."

HELP_TEXT = """\
{disclaimer}

Workflow
  1. Setup: choose your database and enable one or more recovery modes.
  2. Inspect (optional): see the KDF and whether a GPU (hashcat) would help.
  3. Recovery: press Start. The password appears here if it is found.

Mask mode (you remember the structure)
  Hashcat-style placeholders, literals are kept as typed:
    ?l lowercase   ?u uppercase   ?d digit   ?s symbol   ?a any
  Example: Summer?d?d  tries Summer00 .. Summer99.

Fragments mode (you remember pieces)
  Enter the pieces comma-separated (e.g. sun, flower, 42).
  Try all orders  : permute the pieces.
  Case variants   : also try lower / UPPER / Capitalized.
  Fixed prefix    : a piece that is always placed first.
  Min fragments   : 1 also tries each single piece; raise it to prune.

Wordlist mode
  Point at a text file with one candidate per line (streamed, not deduplicated).

Workers
  0 = auto. Argon2 is memory-hard, so a few workers already saturate RAM;
  raising this further mostly wastes memory.

Export / GPU
  For AES-KDF databases, exporting candidates for hashcat (-m 13400) is far
  faster. For Argon2 (memory-hard), CPU recovery here is about as good.
"""


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
        self.queue: queue.Queue = queue.Queue()
        self.cancel: threading.Event | None = None
        self.thread: threading.Thread | None = None

        self.vars: dict[str, tk.Variable] = {}
        self.found_var = tk.StringVar()
        self.inspect_path_var = tk.StringVar()

        root.title("keepass-kdbx-recover")
        root.minsize(760, 600)
        root.geometry("820x660")

        self._build_header()
        self._build_notebook()
        self._build_footer()

        self._load_initial_config()
        self._add_traces()
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
        ttk.Label(header, text="KeePass KDBX master-password recovery",
                  style="Sub.TLabel").pack(side="top", anchor="w", padx=12)
        ttk.Label(header, text=DISCLAIMER, style="Disclaimer.TLabel").pack(
            side="top", anchor="w", padx=12, pady=(2, 8))

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

    def _build_setup_tab(self) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Setup")
        tab.columnconfigure(0, weight=1)

        db = ttk.LabelFrame(tab, text="Database")
        db.grid(row=0, column=0, sticky="ew", padx=PAD, pady=GAP)
        self._labeled_entry(db, 0, "Database (.kdbx)", self._var("db_path"),
                            browse=lambda: self._browse_open("db_path"))
        self._labeled_entry(db, 1, "Keyfile (optional)", self._var("keyfile"),
                            browse=lambda: self._browse_open("keyfile"))

        modes = ttk.LabelFrame(tab, text="Recovery modes (enable one or more)")
        modes.grid(row=1, column=0, sticky="ew", padx=PAD, pady=GAP)
        modes.columnconfigure(1, weight=1)
        ttk.Checkbutton(modes, text="Mask", variable=self._var("mask_enabled", boolean=True)).grid(
            row=0, column=0, sticky="w", padx=PAD, pady=GAP)
        self._labeled_entry(modes, 1, "Pattern", self._var("mask_pattern"))
        ttk.Label(modes, text="?l lower  ?u upper  ?d digit  ?s symbol  ?a any; literals kept",
                  style="Muted.TLabel").grid(row=2, column=1, sticky="w", padx=PAD)

        ttk.Checkbutton(modes, text="Fragments",
                        variable=self._var("fragments_enabled", boolean=True)).grid(
            row=3, column=0, sticky="w", padx=PAD, pady=GAP)
        self._labeled_entry(modes, 4, "Pieces (comma-separated)", self._var("fragments_pieces"))
        opts = ttk.Frame(modes)
        opts.grid(row=5, column=1, sticky="w", padx=PAD)
        ttk.Checkbutton(
            opts, text="Try all orders",
            variable=self._var("fragments_permutations", boolean=True)).pack(side="left")
        ttk.Checkbutton(
            opts, text="Case variants",
            variable=self._var("fragments_case_variants", boolean=True)).pack(side="left", padx=12)
        self._labeled_entry(modes, 6, "Fixed prefix", self._var("fragments_fixed_prefix"))
        ttk.Label(modes, text="Min fragments").grid(row=7, column=0, sticky="w", padx=PAD, pady=GAP)
        ttk.Spinbox(modes, from_=1, to=64, width=5,
                    textvariable=self._var("fragments_min_fragments")).grid(
            row=7, column=1, sticky="w", padx=PAD, pady=GAP)

        ttk.Checkbutton(modes, text="Wordlist",
                        variable=self._var("wordlist_enabled", boolean=True)).grid(
            row=8, column=0, sticky="w", padx=PAD, pady=GAP)
        self._labeled_entry(modes, 9, "Wordlist file", self._var("wordlist_path"),
                            browse=lambda: self._browse_open("wordlist_path"))

        options = ttk.LabelFrame(tab, text="Options")
        options.grid(row=2, column=0, sticky="ew", padx=PAD, pady=GAP)
        options.columnconfigure(1, weight=1)
        ttk.Label(options, text="Workers (0 = auto)").grid(
            row=0, column=0, sticky="w", padx=PAD, pady=GAP)
        ttk.Spinbox(options, from_=0, to=64, width=5, textvariable=self._var("workers")).grid(
            row=0, column=1, sticky="w", padx=PAD, pady=GAP)
        ttk.Label(options, text="Progress interval (s)").grid(
            row=1, column=0, sticky="w", padx=PAD, pady=GAP)
        ttk.Spinbox(options, from_=0.5, to=60, increment=0.5, width=6,
                    textvariable=self._var("progress_interval")).grid(
            row=1, column=1, sticky="w", padx=PAD, pady=GAP)
        ttk.Checkbutton(options, text="Export candidates instead of running",
                        variable=self._var("export_enabled", boolean=True)).grid(
            row=2, column=0, columnspan=2, sticky="w", padx=PAD, pady=GAP)
        self._labeled_entry(options, 3, "Export path", self._var("export_path"),
                            browse=lambda: self._browse_save("export_path"))

        cfgfile = ttk.Frame(tab)
        cfgfile.grid(row=3, column=0, sticky="ew", padx=PAD, pady=GAP)
        ttk.Button(cfgfile, text="Load config...", command=self._on_load_config).pack(side="left")
        ttk.Button(cfgfile, text="Save config...", command=self._on_save_config).pack(
            side="left", padx=8)

        self.err_lbl = ttk.Label(tab, text="", style="Error.TLabel", wraplength=720, justify="left")
        self.err_lbl.grid(row=4, column=0, sticky="ew", padx=PAD, pady=GAP)

    def _build_recovery_tab(self) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Recovery")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(4, weight=1)

        ctl = ttk.Frame(tab)
        ctl.grid(row=0, column=0, sticky="ew", padx=PAD, pady=GAP)
        self.start_btn = ttk.Button(
            ctl, text="Start", style="Primary.TButton", command=self._on_start)
        self.start_btn.pack(side="left")
        self.cancel_btn = ttk.Button(ctl, text="Cancel", command=self._on_cancel, state="disabled")
        self.cancel_btn.pack(side="left", padx=8)

        self.pbar = ttk.Progressbar(tab, mode="determinate")
        self.pbar.grid(row=1, column=0, sticky="ew", padx=PAD, pady=GAP)

        self.status_line = ttk.Label(tab, text="")
        self.status_line.grid(row=2, column=0, sticky="ew", padx=PAD)

        result = ttk.LabelFrame(tab, text="Result")
        result.grid(row=3, column=0, sticky="ew", padx=PAD, pady=GAP)
        result.columnconfigure(0, weight=1)
        self.found_entry = ttk.Entry(
            result, textvariable=self.found_var, state="readonly", font=self.mono)
        self.found_entry.grid(row=0, column=0, sticky="ew", padx=PAD, pady=GAP)
        self.copy_btn = ttk.Button(
            result, text="Copy", command=self._copy_password, state="disabled")
        self.copy_btn.grid(row=0, column=1, sticky="e", padx=PAD, pady=GAP)

        logframe = ttk.LabelFrame(tab, text="Log")
        logframe.grid(row=4, column=0, sticky="nsew", padx=PAD, pady=GAP)
        logframe.columnconfigure(0, weight=1)
        logframe.rowconfigure(0, weight=1)
        self.log = tk.Text(logframe, state="disabled", wrap="word", height=8, font=self.mono)
        self.log.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(logframe, command=self.log.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=scroll.set)

    def _build_inspect_tab(self) -> None:
        tab = ttk.Frame(self.notebook)
        self.notebook.add(tab, text="Inspect")
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(2, weight=1)

        pick = ttk.Frame(tab)
        pick.grid(row=0, column=0, sticky="ew", padx=PAD, pady=GAP)
        pick.columnconfigure(1, weight=1)
        ttk.Label(pick, text="Database (.kdbx)").grid(row=0, column=0, sticky="w")
        ttk.Entry(pick, textvariable=self.inspect_path_var).grid(
            row=0, column=1, sticky="ew", padx=PAD)
        ttk.Button(pick, text="Browse...", command=self._browse_inspect).grid(row=0, column=2)
        ttk.Button(pick, text="Inspect", command=self._on_inspect).grid(
            row=0, column=3, padx=(8, 0))

        self.advice_lbl = ttk.Label(tab, text="", wraplength=720, justify="left")
        self.advice_lbl.grid(row=1, column=0, sticky="ew", padx=PAD, pady=GAP)

        self.report_txt = tk.Text(tab, state="disabled", height=12, font=self.mono)
        self.report_txt.grid(row=2, column=0, sticky="nsew", padx=PAD, pady=GAP)

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
        for var in self.vars.values():
            var.trace_add("write", lambda *_: self._revalidate())
        self.notebook.bind("<<NotebookTabChanged>>", lambda _e: self._revalidate())

    def _revalidate(self) -> None:
        cfg = form_to_config(self._read_form())
        errors = validate(cfg) + check_paths(cfg)
        self.err_lbl.configure(text="\n".join(errors))
        if hasattr(self, "start_btn"):
            self.start_btn.configure(state="disabled" if (errors or self.running) else "normal")

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
            messagebox.showerror("Load config", f"Could not load config:\n{exc}")
            return
        self._apply_form(config_to_form(cfg))

    def _on_save_config(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".toml", initialfile="config.toml")
        if not path:
            return
        try:
            save(form_to_config(self._read_form()), path)
        except OSError as exc:
            messagebox.showerror("Save config", f"Could not save config:\n{exc}")

    # ---- recovery -----------------------------------------------------------

    def _on_start(self) -> None:
        cfg = form_to_config(self._read_form())
        errors = validate(cfg) + check_paths(cfg)
        if errors:
            messagebox.showerror("Cannot start", "\n".join(errors))
            return

        self.running = True
        self._cancelled = False
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
        self.status_var.set("Running...")

        reporter = TkReporter(self.queue)
        self.thread = threading.Thread(
            target=self._worker, args=(cfg, reporter, self.cancel), daemon=True)
        self.thread.start()
        self.root.after(POLL_MS, self._poll)

    def _worker(self, cfg, reporter, cancel) -> None:
        try:
            RecoveryEngine().run(cfg, reporter, cancel)
        except RecoveryError as exc:
            reporter.error(str(exc))
        except Exception as exc:  # never let the worker die silently
            reporter.error(f"Unexpected error: {exc}")

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
        self._revalidate()

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
                text="Choose a .kdbx file to inspect.", style="AdviceUnknown.TLabel")
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
                text=f"This KDF ({insp.kdf}) is compute-bound: a GPU (hashcat -m 13400) "
                     f"gives a BIG advantage. Consider Export + hashcat.",
                style="AdviceBig.TLabel")
        elif insp.gpu_advice is GpuAdvice.LITTLE_ADVANTAGE:
            self.advice_lbl.configure(
                text=f"This KDF ({insp.kdf}) is memory-hard: a GPU gives LITTLE advantage; "
                     f"CPU recovery here is about as good.",
                style="AdviceLittle.TLabel")
        else:
            self.advice_lbl.configure(text="KDF not recognized; GPU benefit unknown.",
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
