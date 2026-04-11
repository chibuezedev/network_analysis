"""
Dashboard panel — stat cards + real-time log console.
"""

import tkinter as tk
from datetime import datetime
from tkinter import ttk

from .theme import (
    ACCENT_AMBER,
    ACCENT_BLUE,
    ACCENT_CYAN,
    ACCENT_GREEN,
    ACCENT_RED,
    BG_DARK,
    BG_HEADER,
    BG_PANEL,
    FONT_MONO,
    FONT_SMALL,
    FONT_SUBTITLE,
    FONT_TITLE,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    stat_box,
)


class DashboardPanel(ttk.Frame):
    """Main dashboard with KPI cards and scrolling log."""

    def __init__(self, parent, db, **kwargs):
        super().__init__(parent, style="TFrame", **kwargs)
        self.db = db

        self._stat_vars = {
            "devices": tk.StringVar(value="0"),
            "whitelisted": tk.StringVar(value="0"),
            "alerts": tk.StringVar(value="0"),
            "blocked": tk.StringVar(value="0"),
        }
        self._packets_var = tk.StringVar(value="0")
        self._status_var = tk.StringVar(value="● STOPPED")
        self._status_color = ACCENT_RED

        self._build()
        self.refresh_stats()

    def _build(self):
        hdr = tk.Frame(self, bg=BG_DARK)
        hdr.pack(fill="x", pady=(0, 2))

        tk.Label(
            hdr,
            text="⬡  NIDS COMMAND CENTER",
            bg=BG_DARK,
            fg=ACCENT_CYAN,
            font=FONT_TITLE,
        ).pack(side="left", padx=(6, 0), pady=8)

        self._status_lbl = tk.Label(
            hdr,
            textvariable=self._status_var,
            bg=BG_DARK,
            fg=ACCENT_RED,
            font=FONT_SUBTITLE,
        )
        self._status_lbl.pack(side="right", padx=12)

        tk.Frame(self, bg=ACCENT_CYAN, height=2).pack(fill="x")

        cards_row = tk.Frame(self, bg=BG_DARK)
        cards_row.pack(fill="x", padx=8, pady=8)

        specs = [
            ("DEVICES SEEN", "devices", ACCENT_BLUE),
            ("WHITELISTED", "whitelisted", ACCENT_GREEN),
            ("ALERTS TOTAL", "alerts", ACCENT_AMBER),
            ("BLOCKED IPs", "blocked", ACCENT_RED),
        ]
        for i, (title, key, color) in enumerate(specs):
            box = stat_box(cards_row, title, self._stat_vars[key], color)
            box.grid(row=0, column=i, padx=6, pady=4, sticky="ew")
            cards_row.columnconfigure(i, weight=1)

        heat_frame = tk.Frame(self, bg=BG_PANEL, pady=6, padx=8)
        heat_frame.pack(fill="x", padx=8, pady=(0, 8))

        tk.Label(
            heat_frame,
            text="RECENT ACTIVITY",
            bg=BG_PANEL,
            fg=TEXT_SECONDARY,
            font=FONT_SMALL,
        ).pack(anchor="w")

        self._heat_canvas = tk.Canvas(
            heat_frame,
            bg=BG_PANEL,
            height=24,
            highlightthickness=0,
            bd=0,
        )
        self._heat_canvas.pack(fill="x", expand=True, pady=(4, 0))
        self._heat_data = [0] * 60
        self._heat_canvas.bind("<Configure>", lambda e: self._redraw_heat())

        log_frame = tk.Frame(self, bg=BG_PANEL, padx=8, pady=8)
        log_frame.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        top = tk.Frame(log_frame, bg=BG_PANEL)
        top.pack(fill="x")
        tk.Label(
            top,
            text="LIVE LOG CONSOLE",
            bg=BG_PANEL,
            fg=ACCENT_CYAN,
            font=FONT_SUBTITLE,
        ).pack(side="left")

        btn_clear = tk.Button(
            top,
            text="CLR",
            bg=BG_HEADER,
            fg=TEXT_SECONDARY,
            font=FONT_SMALL,
            relief="flat",
            bd=0,
            cursor="hand2",
            command=self._clear_log,
        )
        btn_clear.pack(side="right")

        self._log = tk.Text(
            log_frame,
            bg=BG_DARK,
            fg=TEXT_PRIMARY,
            font=FONT_MONO,
            state="disabled",
            relief="flat",
            bd=0,
            wrap="word",
            cursor="arrow",
        )
        vsb = ttk.Scrollbar(log_frame, orient="vertical", command=self._log.yview)
        self._log.configure(yscrollcommand=vsb.set)

        vsb.pack(side="right", fill="y")
        self._log.pack(fill="both", expand=True, pady=(4, 0))

        self._log.tag_configure("ts", foreground=TEXT_SECONDARY, font=FONT_SMALL)
        self._log.tag_configure("info", foreground=ACCENT_BLUE)
        self._log.tag_configure("warn", foreground=ACCENT_AMBER)
        self._log.tag_configure("danger", foreground=ACCENT_RED)
        self._log.tag_configure("success", foreground=ACCENT_GREEN)

        self._log_append("System initialised. Monitoring engine ready.", "info")
        # self._log_append("Run in simulation mode — no admin rights required.", "warn")

    def set_status(self, running: bool):
        if running:
            self._status_var.set("● RUNNING")
            self._status_lbl.configure(fg=ACCENT_GREEN)
        else:
            self._status_var.set("● STOPPED")
            self._status_lbl.configure(fg=ACCENT_RED)

    def refresh_stats(self):
        stats = self.db.get_stats()
        for k, v in self._stat_vars.items():
            v.set(str(stats.get(k, 0)))

    def update_packets(self, count: int):
        self._packets_var.set(str(count))
        self._heat_data.append(count % 20)
        self._heat_data = self._heat_data[-60:]
        self._redraw_heat()

    def log_device(self, ip: str, mac: str):
        self._log_append(f"Device  {ip}  [{mac}]", "info")

    def log_alert(self, ip: str, attack: str, confidence: float):
        self._log_append(
            f"⚠  ALERT  {ip}  —  {attack}  ({confidence * 100:.1f}%)", "danger"
        )
        self.refresh_stats()

    def log_block(self, ip: str):
        self._log_append(f"🔴 BLOCKED  {ip}", "danger")
        self.refresh_stats()

    def log_whitelist(self, ip: str):
        self._log_append(f"✅ WHITELISTED  {ip}", "success")
        self.refresh_stats()

    def log_info(self, msg: str):
        self._log_append(msg, "info")

    def _log_append(self, msg: str, tag: str = "info"):
        ts = datetime.now().strftime("%H:%M:%S")
        self._log.configure(state="normal")
        self._log.insert("end", f"[{ts}] ", "ts")
        self._log.insert("end", msg + "\n", tag)
        self._log.see("end")
        self._log.configure(state="disabled")
        lines = int(self._log.index("end-1c").split(".")[0])
        if lines > 500:
            self._log.configure(state="normal")
            self._log.delete("1.0", "50.0")
            self._log.configure(state="disabled")

    def _clear_log(self):
        self._log.configure(state="normal")
        self._log.delete("1.0", "end")
        self._log.configure(state="disabled")

    def _redraw_heat(self):
        c = self._heat_canvas
        c.delete("all")
        w = c.winfo_width()
        if w < 10:
            return
        h = 22
        n = len(self._heat_data)
        cell = max(1, w / n)
        max_v = max(self._heat_data) if max(self._heat_data) > 0 else 1
        colors = [
            "#0d2818",
            "#0f3320",
            "#1a4d2e",
            "#2a7a46",
            "#3fb950",
            "#7ee787",
        ]
        for i, val in enumerate(self._heat_data):
            ratio = val / max_v
            ci = int(ratio * (len(colors) - 1))
            x0 = i * cell
            x1 = x0 + cell - 1
            bar_h = max(2, int(ratio * h))
            c.create_rectangle(
                x0,
                h - bar_h,
                x1,
                h,
                fill=colors[ci],
                outline="",
            )
