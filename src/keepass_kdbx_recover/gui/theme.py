"""ttk theming for an enterprise-grade, neutral light look.

Tk has no reliable cross-platform dark theme and does not follow the OS dark
setting, so this ships a single clean light palette. The 'clam' theme is used
because it is bundled everywhere and honors color options (the native vista/aqua
themes ignore most of them).
"""

import tkinter as tk
from tkinter import font as tkfont
from tkinter import ttk

PAD = 8
GAP = 4

# Neutral light palette.
BG = "#f4f5f7"
SURFACE = "#ffffff"
TEXT = "#1f2328"
MUTED = "#6b7280"
BORDER = "#d0d7de"
ACCENT = "#1f6feb"
ACCENT_ACTIVE = "#1a5fd0"
ERROR = "#b91c1c"
ADVICE_BIG_FG = "#8a5a00"
ADVICE_LITTLE_FG = "#15803d"
ADVICE_UNKNOWN_FG = MUTED


def _pick_family(preferred: str, fallback: str) -> str:
    try:
        available = set(tkfont.families())
    except tk.TclError:
        return fallback
    return preferred if preferred in available else fallback


def apply_theme(root: tk.Tk) -> ttk.Style:
    """Apply the theme to a root window and return the configured Style."""
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass  # keep whatever theme is available

    ui_family = _pick_family("Segoe UI", "TkDefaultFont")
    mono_family = _pick_family("Consolas", "TkFixedFont")

    base = tkfont.Font(family=ui_family, size=10)
    root.option_add("*Font", base)

    root.configure(bg=BG)

    style.configure(".", background=BG, foreground=TEXT, fieldbackground=SURFACE)
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=TEXT)
    style.configure("TButton", padding=6)
    style.configure("TCheckbutton", background=BG)
    style.configure("TLabelframe", background=BG, padding=10, bordercolor=BORDER)
    style.configure("TLabelframe.Label", background=BG, foreground=TEXT)
    style.configure("TEntry", padding=3)
    style.configure("TSpinbox", padding=3)
    style.configure("TNotebook", background=BG)

    style.configure("Header.TFrame", background=SURFACE)
    style.configure("Header.TLabel", background=SURFACE, foreground=TEXT,
                    font=(ui_family, 15, "bold"))
    style.configure("Sub.TLabel", background=SURFACE, foreground=MUTED, font=(ui_family, 9))
    style.configure("Disclaimer.TLabel", background=SURFACE, foreground=MUTED,
                    font=(ui_family, 9, "italic"))
    style.configure("Muted.TLabel", foreground=MUTED)

    style.configure("Primary.TButton", padding=7)
    style.map(
        "Primary.TButton",
        background=[("!disabled", ACCENT), ("active", ACCENT_ACTIVE)],
        foreground=[("!disabled", "#ffffff")],
    )

    style.configure("Error.TLabel", foreground=ERROR, background=BG)
    style.configure("AdviceBig.TLabel", foreground=ADVICE_BIG_FG, background=BG,
                    font=(ui_family, 10, "bold"))
    style.configure("AdviceLittle.TLabel", foreground=ADVICE_LITTLE_FG, background=BG,
                    font=(ui_family, 10, "bold"))
    style.configure("AdviceUnknown.TLabel", foreground=ADVICE_UNKNOWN_FG, background=BG)

    # Expose the chosen families for widgets that are not ttk (tk.Text).
    style.ui_family = ui_family  # type: ignore[attr-defined]
    style.mono_family = mono_family  # type: ignore[attr-defined]
    return style
