import tkinter as tk
from tkinter import ttk

BG_DARK = "#0d1117"  # main background
BG_PANEL = "#161b22"  # panel / card background
BG_SIDEBAR = "#0d1117"  # sidebar
BG_ROW_ALT = "#1a2030"  # alternating table row
BG_HEADER = "#1c2333"  # table header

ACCENT_CYAN = "#00d4ff"  # primary accent
ACCENT_GREEN = "#3fb950"  # safe / whitelisted
ACCENT_RED = "#f85149"  # danger / blocked
ACCENT_AMBER = "#e3b341"  # warning / unknown / pending
ACCENT_BLUE = "#58a6ff"  # info

TEXT_PRIMARY = "#e6edf3"
TEXT_SECONDARY = "#8b949e"
TEXT_MUTED = "#484f58"

BORDER = "#30363d"

STATUS_COLORS = {
    "Whitelisted": ACCENT_GREEN,
    "Blocked": ACCENT_RED,
    "Unknown": ACCENT_AMBER,
    "Pending": ACCENT_AMBER,
    "Ignored": TEXT_SECONDARY,
    "Running": ACCENT_GREEN,
    "Stopped": ACCENT_RED,
}

ATTACK_COLORS = {
    "Benign": ACCENT_GREEN,
    "DoS": ACCENT_RED,
    "Exploits": ACCENT_RED,
    "Backdoor": "#ff7b72",
    "Shellcode": "#ff7b72",
    "Worms": "#ff7b72",
    "Reconnaissance": ACCENT_AMBER,
    "Fuzzers": ACCENT_AMBER,
    "Analysis": ACCENT_BLUE,
    "Generic": ACCENT_BLUE,
}


FONT_TITLE = ("Courier New", 18, "bold")
FONT_SUBTITLE = ("Courier New", 11, "bold")
FONT_BODY = ("Consolas", 10)
FONT_SMALL = ("Consolas", 9)
FONT_MONO = ("Courier New", 10)
FONT_BADGE = ("Consolas", 8, "bold")


def apply_theme(root: tk.Tk):
    style = ttk.Style(root)
    style.theme_use("clam")

    style.configure(
        ".",
        background=BG_DARK,
        foreground=TEXT_PRIMARY,
        fieldbackground=BG_PANEL,
        insertcolor=ACCENT_CYAN,
        troughcolor=BG_PANEL,
        borderwidth=0,
        relief="flat",
    )

    style.configure(
        "Treeview",
        background=BG_PANEL,
        foreground=TEXT_PRIMARY,
        fieldbackground=BG_PANEL,
        rowheight=28,
        borderwidth=0,
        relief="flat",
        font=FONT_BODY,
    )
    style.configure(
        "Treeview.Heading",
        background=BG_HEADER,
        foreground=ACCENT_CYAN,
        relief="flat",
        font=FONT_SUBTITLE,
        padding=(6, 4),
    )
    style.map(
        "Treeview",
        background=[("selected", "#1f3a5f")],
        foreground=[("selected", TEXT_PRIMARY)],
    )
    style.map(
        "Treeview.Heading",
        background=[("active", BG_HEADER)],
    )

    # Scrollbar
    style.configure(
        "Vertical.TScrollbar",
        background=BG_PANEL,
        troughcolor=BG_DARK,
        arrowcolor=TEXT_SECONDARY,
        borderwidth=0,
        width=8,
    )
    style.configure(
        "Horizontal.TScrollbar",
        background=BG_PANEL,
        troughcolor=BG_DARK,
        arrowcolor=TEXT_SECONDARY,
        borderwidth=0,
        width=8,
    )

    # Buttons
    style.configure(
        "TButton",
        background=BG_PANEL,
        foreground=TEXT_PRIMARY,
        borderwidth=1,
        relief="flat",
        padding=(10, 6),
        font=FONT_SMALL,
    )
    style.map(
        "TButton",
        background=[("active", BG_HEADER), ("pressed", BG_DARK)],
    )

    # Accent button
    style.configure(
        "Accent.TButton",
        background=ACCENT_CYAN,
        foreground=BG_DARK,
        font=("Consolas", 10, "bold"),
        padding=(12, 7),
    )
    style.map(
        "Accent.TButton",
        background=[("active", "#00b8e0"), ("pressed", "#0099bb")],
    )

    # Danger button
    style.configure(
        "Danger.TButton",
        background=ACCENT_RED,
        foreground="#ffffff",
        font=FONT_SMALL,
        padding=(8, 5),
    )
    style.map(
        "Danger.TButton",
        background=[("active", "#c93d36")],
    )

    # Success button
    style.configure(
        "Success.TButton",
        background=ACCENT_GREEN,
        foreground=BG_DARK,
        font=FONT_SMALL,
        padding=(8, 5),
    )
    style.map(
        "Success.TButton",
        background=[("active", "#2ea043")],
    )

    # Warning button
    style.configure(
        "Warning.TButton",
        background=ACCENT_AMBER,
        foreground=BG_DARK,
        font=FONT_SMALL,
        padding=(8, 5),
    )

    # Entry
    style.configure(
        "TEntry",
        fieldbackground=BG_PANEL,
        foreground=TEXT_PRIMARY,
        insertcolor=ACCENT_CYAN,
        borderwidth=1,
        relief="solid",
    )

    # Notebook tabs
    style.configure(
        "TNotebook",
        background=BG_DARK,
        borderwidth=0,
    )
    style.configure(
        "TNotebook.Tab",
        background=BG_PANEL,
        foreground=TEXT_SECONDARY,
        padding=(14, 8),
        font=FONT_SMALL,
    )
    style.map(
        "TNotebook.Tab",
        background=[("selected", BG_HEADER)],
        foreground=[("selected", ACCENT_CYAN)],
    )

    # Frame
    style.configure("TFrame", background=BG_DARK)
    style.configure("Panel.TFrame", background=BG_PANEL)
    style.configure("Sidebar.TFrame", background=BG_SIDEBAR)

    # Label
    style.configure(
        "TLabel", background=BG_DARK, foreground=TEXT_PRIMARY, font=FONT_BODY
    )
    style.configure(
        "Muted.TLabel", background=BG_DARK, foreground=TEXT_SECONDARY, font=FONT_SMALL
    )
    style.configure(
        "Title.TLabel", background=BG_DARK, foreground=ACCENT_CYAN, font=FONT_TITLE
    )
    style.configure(
        "Panel.TLabel", background=BG_PANEL, foreground=TEXT_PRIMARY, font=FONT_BODY
    )

    # Separator
    style.configure("TSeparator", background=BORDER)

    return style


def card_frame(parent, **kwargs) -> ttk.Frame:
    """Return a styled panel frame."""
    f = ttk.Frame(parent, style="Panel.TFrame", **kwargs)
    return f


def section_label(parent, text: str, **kwargs) -> tk.Label:
    return tk.Label(parent, text=text, font=FONT_SUBTITLE, fg=TEXT_SECONDARY, **kwargs)


def stat_box(
    parent, title: str, value_var: tk.StringVar, color=ACCENT_CYAN
) -> ttk.Frame:
    frame = ttk.Frame(parent, style="Panel.TFrame", padding=(14, 10))
    tk.Label(frame, text=title, bg=BG_PANEL, fg=TEXT_SECONDARY, font=FONT_SMALL).pack(
        anchor="w"
    )
    tk.Label(
        frame,
        textvariable=value_var,
        bg=BG_PANEL,
        fg=color,
        font=("Courier New", 22, "bold"),
    ).pack(anchor="w")
    return frame


def tag_label(parent, text: str, color: str) -> tk.Label:
    return tk.Label(
        parent,
        text=f" {text} ",
        bg=color,
        fg=BG_DARK
        if color in (ACCENT_CYAN, ACCENT_GREEN, ACCENT_AMBER)
        else TEXT_PRIMARY,
        font=FONT_BADGE,
        relief="flat",
    )


def make_scrolled_tree(parent, columns, headings, col_widths=None):
    """Return (frame, Treeview) with auto scrollbars."""
    frame = ttk.Frame(parent, style="Panel.TFrame")
    frame.pack(fill="both", expand=True)

    vsb = ttk.Scrollbar(frame, orient="vertical")
    hsb = ttk.Scrollbar(frame, orient="horizontal")

    tree = ttk.Treeview(
        frame,
        columns=columns,
        show="headings",
        yscrollcommand=vsb.set,
        xscrollcommand=hsb.set,
        selectmode="browse",
    )
    vsb.configure(command=tree.yview)
    hsb.configure(command=tree.xview)

    for col, heading in zip(columns, headings):
        tree.heading(col, text=heading, anchor="w")
        w = 120
        if col_widths and col in col_widths:
            w = col_widths[col]
        tree.column(col, width=w, minwidth=60, anchor="w")

    tree.grid(row=0, column=0, sticky="nsew")
    vsb.grid(row=0, column=1, sticky="ns")
    hsb.grid(row=1, column=0, sticky="ew")

    frame.rowconfigure(0, weight=1)
    frame.columnconfigure(0, weight=1)

    # Row tags
    tree.tag_configure("green", background="#0d2818", foreground=ACCENT_GREEN)
    tree.tag_configure("red", background="#2d1215", foreground=ACCENT_RED)
    tree.tag_configure("amber", background="#2a1f0a", foreground=ACCENT_AMBER)
    tree.tag_configure("blue", background="#0d1f3c", foreground=ACCENT_BLUE)
    tree.tag_configure("normal", background=BG_PANEL, foreground=TEXT_PRIMARY)

    return frame, tree
