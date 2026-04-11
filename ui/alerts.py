"""
Alerts panel — detected anomalies with action buttons.
"""

import tkinter as tk
from tkinter import ttk

from .theme import (
    ACCENT_CYAN,
    BG_DARK,
    BG_HEADER,
    BG_PANEL,
    FONT_SMALL,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    make_scrolled_tree,
    section_label,
)


class AlertsPanel(ttk.Frame):
    def __init__(self, parent, db, monitor_service, dashboard, **kwargs):
        super().__init__(parent, style="TFrame", **kwargs)
        self.db = db
        self.svc = monitor_service
        self.dashboard = dashboard
        self._build()
        self.refresh()

    def _build(self):
        # Header
        hdr = tk.Frame(self, bg=BG_DARK)
        hdr.pack(fill="x", padx=8, pady=(8, 4))
        section_label(hdr, "THREAT ALERTS", bg=BG_DARK).pack(side="left")

        btn_row = tk.Frame(hdr, bg=BG_DARK)
        btn_row.pack(side="right")

        # Filter
        self._filter_var = tk.StringVar(value="All")
        for label in ("All", "Pending", "Blocked", "Ignored"):
            b = tk.Radiobutton(
                btn_row,
                text=label,
                variable=self._filter_var,
                value=label,
                bg=BG_DARK,
                fg=TEXT_SECONDARY,
                selectcolor=BG_HEADER,
                activebackground=BG_DARK,
                font=FONT_SMALL,
                relief="flat",
                bd=0,
                command=self.refresh,
            )
            b.pack(side="left", padx=4)

        ttk.Button(
            btn_row, text="⟳", style="TButton", width=2, command=self.refresh
        ).pack(side="left", padx=4)

        # Table
        cols = (
            "id",
            "src_ip",
            "mac",
            "attack_type",
            "confidence",
            "action",
            "timestamp",
        )
        heads = (
            "#",
            "Source IP",
            "MAC",
            "Attack Type",
            "Confidence",
            "Status",
            "Timestamp",
        )
        widths = {
            "id": 36,
            "src_ip": 130,
            "mac": 140,
            "attack_type": 120,
            "confidence": 80,
            "action": 80,
            "timestamp": 155,
        }
        _, self._tree = make_scrolled_tree(self, cols, heads, widths)
        self._tree.bind("<Button-3>", self._ctx_show)
        self._tree.bind("<Double-1>", self._ctx_show)

        # Action buttons row (below table)
        act_bar = tk.Frame(self, bg=BG_DARK)
        act_bar.pack(fill="x", padx=8, pady=6)

        ttk.Button(
            act_bar,
            text="🔴  Block IP",
            style="Danger.TButton",
            command=self._act_block,
        ).pack(side="left", padx=4)
        ttk.Button(
            act_bar,
            text="✅  Whitelist",
            style="Success.TButton",
            command=self._act_whitelist,
        ).pack(side="left", padx=4)
        ttk.Button(
            act_bar, text="⊘  Ignore", style="TButton", command=self._act_ignore
        ).pack(side="left", padx=4)
        ttk.Button(
            act_bar,
            text="✖  Clear Ignored",
            style="TButton",
            command=self._clear_ignored,
        ).pack(side="right", padx=4)

        # Context menu
        self._ctx = tk.Menu(
            self,
            tearoff=0,
            bg=BG_PANEL,
            fg=TEXT_PRIMARY,
            activebackground=BG_HEADER,
            activeforeground=ACCENT_CYAN,
            font=FONT_SMALL,
        )
        self._ctx.add_command(label="🔴  Block IP", command=self._act_block)
        self._ctx.add_command(label="✅  Whitelist", command=self._act_whitelist)
        self._ctx.add_command(label="⊘  Ignore", command=self._act_ignore)

        self._count_var = tk.StringVar(value="")
        tk.Label(
            self,
            textvariable=self._count_var,
            bg=BG_DARK,
            fg=TEXT_SECONDARY,
            font=FONT_SMALL,
        ).pack(anchor="e", padx=8, pady=2)

    # ------------------------------------------------------------------ #

    def refresh(self):
        alerts = self.db.get_alerts(limit=300)
        filt = self._filter_var.get()
        if filt != "All":
            alerts = [a for a in alerts if a["action"] == filt]

        sel = self._tree.focus()
        sel_id = self._tree.set(sel, "id") if sel else None

        self._tree.delete(*self._tree.get_children())
        for a in alerts:
            conf_str = f"{a['confidence'] * 100:.1f}%"
            tag = self._pick_tag(a["attack_type"], a["action"])
            iid = self._tree.insert(
                "",
                "end",
                values=(
                    a["id"],
                    a["src_ip"],
                    a["mac"],
                    a["attack_type"],
                    conf_str,
                    a["action"],
                    a["timestamp"],
                ),
                tags=(tag,),
            )
            if str(a["id"]) == str(sel_id):
                self._tree.focus(iid)
                self._tree.selection_set(iid)

        total = len(alerts)
        counts = self.db.get_alert_counts()
        self._count_var.set(
            f"{total} shown  |  {counts['pending']} pending  |  {counts['blocked']} blocked"
        )

    def _pick_tag(self, attack: str, action: str) -> str:
        if action == "Blocked":
            return "red"
        if action == "Whitelisted":
            return "green"
        if action == "Ignored":
            return "normal"
        # Pending — color by severity
        high = {"DoS", "Exploits", "Backdoor", "Shellcode", "Worms"}
        if attack in high:
            return "red"
        return "amber"

    def _selected_alert(self):
        sel = self._tree.focus()
        if not sel:
            return None
        return {
            "id": self._tree.set(sel, "id"),
            "src_ip": self._tree.set(sel, "src_ip"),
            "mac": self._tree.set(sel, "mac"),
            "attack": self._tree.set(sel, "attack_type"),
        }

    def _ctx_show(self, event):
        iid = self._tree.identify_row(event.y)
        if iid:
            self._tree.focus(iid)
            self._tree.selection_set(iid)
        try:
            self._ctx.tk_popup(event.x_root, event.y_root)
        finally:
            self._ctx.grab_release()

    def _act_block(self):
        a = self._selected_alert()
        if not a:
            return
        self.svc.block_ip(a["src_ip"], a["mac"], f"Alert #{a['id']}: {a['attack']}")
        self.db.update_alert_action(int(a["id"]), "Blocked")
        self.dashboard.log_block(a["src_ip"])
        self.refresh()

    def _act_whitelist(self):
        a = self._selected_alert()
        if not a:
            return
        self.svc.whitelist_ip(a["src_ip"], a["mac"])
        self.db.update_alert_action(int(a["id"]), "Whitelisted")
        self.dashboard.log_whitelist(a["src_ip"])
        self.refresh()

    def _act_ignore(self):
        a = self._selected_alert()
        if not a:
            return
        self.db.update_alert_action(int(a["id"]), "Ignored")
        self.refresh()

    def _clear_ignored(self):
        # Mark all Ignored as... still Ignored but re-filter
        self._filter_var.set("All")
        self.refresh()
