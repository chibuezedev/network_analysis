import tkinter as tk

from .alerts import AlertsPanel
from .blocked import BlockedPanel
from .dashboard import DashboardPanel
from .devices import DevicesPanel
from .theme import (
    ACCENT_AMBER,
    ACCENT_CYAN,
    ACCENT_GREEN,
    ACCENT_RED,
    BG_DARK,
    BG_HEADER,
    BG_PANEL,
    BG_SIDEBAR,
    BORDER,
    FONT_BODY,
    FONT_SMALL,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    apply_theme,
)
from .whitelist import WhitelistPanel

NAV_ITEMS = [
    ("Dashboard", "⊞", "dashboard"),
    ("Live Traffic", "⌁", "devices"),
    ("Alerts", "⚠", "alerts"),
    ("Blocked", "⊗", "blocked"),
    ("Whitelist", "✓", "whitelist"),
]


class MainWindow:
    def __init__(self, root: tk.Tk, db, monitor_service):
        self.root = root
        self.db = db
        self.svc = monitor_service

        self._active_page = tk.StringVar(value="dashboard")
        self._nav_buttons = {}
        self._pages = {}

        apply_theme(root)
        root.configure(bg=BG_DARK)
        root.title("NIDS — Network Intrusion Detection System")
        root.minsize(1100, 680)

        self._build_layout()
        self._register_callbacks()
        self._schedule_refresh()

        self._sound_enabled = True
        try:
            import winsound

            self._beep = lambda: winsound.Beep(880, 300)
            self._beep_device = lambda: winsound.Beep(440, 150)
        except ImportError:
            self._beep = lambda: self.root.bell()
            self._beep_device = lambda: self.root.bell()

    def _build_layout(self):
        self.root.columnconfigure(1, weight=1)
        self.root.rowconfigure(0, weight=1)

        sidebar = tk.Frame(self.root, bg=BG_SIDEBAR, width=190)
        sidebar.grid(row=0, column=0, sticky="ns")
        sidebar.grid_propagate(False)

        logo_frame = tk.Frame(sidebar, bg=BG_SIDEBAR, pady=16)
        logo_frame.pack(fill="x")

        tk.Label(
            logo_frame,
            text="◈ NIDS",
            bg=BG_SIDEBAR,
            fg=ACCENT_CYAN,
            font=("Courier New", 16, "bold"),
        ).pack()
        tk.Label(
            logo_frame,
            text="Intrusion Detection",
            bg=BG_SIDEBAR,
            fg=TEXT_SECONDARY,
            font=FONT_SMALL,
        ).pack()

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=12, pady=4)

        nav_frame = tk.Frame(sidebar, bg=BG_SIDEBAR)
        nav_frame.pack(fill="x", pady=8)

        for label, icon, key in NAV_ITEMS:
            btn = self._make_nav_btn(nav_frame, label, icon, key)
            btn.pack(fill="x", padx=8, pady=2)
            self._nav_buttons[key] = btn

        tk.Frame(sidebar, bg=BORDER, height=1).pack(fill="x", padx=12, pady=8)

        # Controls
        ctrl_frame = tk.Frame(sidebar, bg=BG_SIDEBAR, padx=8)
        ctrl_frame.pack(fill="x")

        tk.Label(
            ctrl_frame,
            text="MONITORING",
            bg=BG_SIDEBAR,
            fg=TEXT_SECONDARY,
            font=FONT_SMALL,
        ).pack(anchor="w", pady=(0, 4))

        self._start_btn = tk.Button(
            ctrl_frame,
            text="▶  START",
            bg=ACCENT_GREEN,
            fg=BG_DARK,
            font=("Consolas", 10, "bold"),
            relief="flat",
            bd=0,
            cursor="hand2",
            pady=7,
            command=self._start_monitoring,
        )
        self._start_btn.pack(fill="x", pady=2)

        self._stop_btn = tk.Button(
            ctrl_frame,
            text="■  STOP",
            bg=BG_PANEL,
            fg=ACCENT_RED,
            font=("Consolas", 10, "bold"),
            relief="flat",
            bd=0,
            cursor="hand2",
            pady=7,
            command=self._stop_monitoring,
            state="disabled",
        )
        self._stop_btn.pack(fill="x", pady=2)

        self._mute_btn = tk.Button(
            ctrl_frame,
            text="🔔  Sound ON",
            bg=BG_PANEL,
            fg=ACCENT_CYAN,
            font=FONT_SMALL,
            relief="flat",
            bd=0,
            cursor="hand2",
            pady=4,
            command=self._toggle_sound,
        )
        self._mute_btn.pack(fill="x", pady=2)

        self._status_dot = tk.Label(
            ctrl_frame,
            text="● STOPPED",
            bg=BG_SIDEBAR,
            fg=ACCENT_RED,
            font=("Consolas", 9, "bold"),
        )
        self._status_dot.pack(anchor="w", pady=(8, 0))

        self._sim_var = tk.BooleanVar(value=False)
        chk = tk.Checkbutton(
            ctrl_frame,
            text="Simulation mode",
            variable=self._sim_var,
            bg=BG_SIDEBAR,
            fg=TEXT_SECONDARY,
            selectcolor=BG_HEADER,
            activebackground=BG_SIDEBAR,
            font=FONT_SMALL,
            relief="flat",
        )
        chk.pack(anchor="w", pady=(4, 0))

        tk.Frame(sidebar, bg=BG_SIDEBAR).pack(fill="both", expand=True)
        tk.Label(
            sidebar,
            text="v1.0.0  BiLSTM+Attention",
            bg=BG_SIDEBAR,
            fg=TEXT_MUTED if hasattr(tk, "_TEXT_MUTED") else "#484f58",
            font=FONT_SMALL,
        ).pack(side="bottom", pady=8)

        content_wrapper = tk.Frame(self.root, bg=BG_DARK)
        content_wrapper.grid(row=0, column=1, sticky="nsew")
        content_wrapper.columnconfigure(0, weight=1)
        content_wrapper.rowconfigure(0, weight=1)

        self._pages["dashboard"] = DashboardPanel(content_wrapper, self.db)
        self._pages["devices"] = DevicesPanel(
            content_wrapper, self.db, self.svc, self._pages["dashboard"]
        )
        self._pages["alerts"] = AlertsPanel(
            content_wrapper, self.db, self.svc, self._pages["dashboard"]
        )
        self._pages["blocked"] = BlockedPanel(
            content_wrapper, self.db, self.svc, self._pages["dashboard"]
        )
        self._pages["whitelist"] = WhitelistPanel(
            content_wrapper, self.db, self.svc, self._pages["dashboard"]
        )

        for page in self._pages.values():
            page.grid(row=0, column=0, sticky="nsew")

        self._show_page("dashboard")

    def _make_nav_btn(self, parent, label, icon, key):
        btn = tk.Button(
            parent,
            text=f"  {icon}  {label}",
            bg=BG_SIDEBAR,
            fg=TEXT_SECONDARY,
            font=FONT_BODY,
            anchor="w",
            relief="flat",
            bd=0,
            cursor="hand2",
            padx=8,
            pady=8,
            activebackground=BG_HEADER,
            activeforeground=TEXT_PRIMARY,
            command=lambda k=key: self._show_page(k),
        )
        return btn

    def _show_page(self, key: str):
        old = self._active_page.get()
        if old in self._nav_buttons:
            self._nav_buttons[old].configure(bg=BG_SIDEBAR, fg=TEXT_SECONDARY)
        self._active_page.set(key)
        if key in self._nav_buttons:
            self._nav_buttons[key].configure(bg=BG_HEADER, fg=ACCENT_CYAN)
        self._pages[key].tkraise()

    def _start_monitoring(self):
        self.svc._use_sim = self._sim_var.get()
        self.svc.start()
        self._start_btn.configure(state="disabled")
        self._stop_btn.configure(state="normal")
        self._status_dot.configure(text="● RUNNING", fg=ACCENT_GREEN)
        self._pages["dashboard"].set_status(True)
        self._pages["dashboard"].log_info(
            "Monitoring started — "
            + ("simulation mode" if self._sim_var.get() else "live capture")
        )

    def _stop_monitoring(self):
        self.svc.stop()
        self._start_btn.configure(state="normal")
        self._stop_btn.configure(state="disabled")
        self._status_dot.configure(text="● STOPPED", fg=ACCENT_RED)
        self._pages["dashboard"].set_status(False)
        self._pages["dashboard"].log_info("Monitoring stopped.")

    def _toggle_sound(self):
        self._sound_enabled = not self._sound_enabled
        self._mute_btn.configure(
            text="🔔  Sound ON" if self._sound_enabled else "🔕  Sound OFF",
            fg=ACCENT_CYAN if self._sound_enabled else TEXT_SECONDARY,
        )

    def _register_callbacks(self):
        def _on_device():
            self.root.after(0, self._ui_device_update)

        def _on_alert():
            self.root.after(0, self._ui_alert_update)

        def _on_stats(stats):
            self.root.after(0, lambda s=stats: self._ui_stats_update(s))

        self.svc.on_device_update = _on_device
        self.svc.on_alert_update = _on_alert
        self.svc.on_stats_update = _on_stats

    def _ui_device_update(self):
        if self._sound_enabled:
            self._beep_device()
        self._pages["devices"].refresh()
        self._pages["dashboard"].refresh_stats()

    def _ui_alert_update(self):
        if self._sound_enabled:
            self._beep()
        alerts = self.db.get_alerts(limit=1)
        if alerts:
            a = alerts[0]
            self._pages["dashboard"].log_alert(
                a["src_ip"], a["attack_type"], a["confidence"]
            )
        self._pages["alerts"].refresh()
        self._update_nav_badge()

    def _ui_stats_update(self, stats):
        self._pages["dashboard"].update_packets(stats.get("packets", 0))

    def _update_nav_badge(self):
        counts = self.db.get_alert_counts()
        pending = counts.get("pending", 0)
        btn = self._nav_buttons.get("alerts")
        if btn:
            if pending > 0:
                btn.configure(text=f"  ⚠  Alerts  [{pending}]", fg=ACCENT_AMBER)
            else:
                btn.configure(text="  ⚠  Alerts", fg=TEXT_SECONDARY)

    def _schedule_refresh(self):
        self._pages["dashboard"].refresh_stats()
        active = self._active_page.get()
        if active in self._pages:
            panel = self._pages[active]
            if hasattr(panel, "refresh"):
                panel.refresh()
        self._update_nav_badge()
        self.root.after(5000, self._schedule_refresh)
