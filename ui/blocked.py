"""
Blocked IPs panel.
"""

import tkinter as tk
from tkinter import messagebox, ttk

from .theme import (
    BG_DARK,
    FONT_SMALL,
    TEXT_SECONDARY,
    make_scrolled_tree,
    section_label,
)


class BlockedPanel(ttk.Frame):
    def __init__(self, parent, db, monitor_service, dashboard, **kwargs):
        super().__init__(parent, style="TFrame", **kwargs)
        self.db = db
        self.svc = monitor_service
        self.dashboard = dashboard
        self._build()
        self.refresh()

    def _build(self):
        hdr = tk.Frame(self, bg=BG_DARK)
        hdr.pack(fill="x", padx=8, pady=(8, 4))
        section_label(hdr, "BLOCKED IPs", bg=BG_DARK).pack(side="left")
        ttk.Button(hdr, text="⟳ Refresh", style="TButton", command=self.refresh).pack(
            side="right", padx=4
        )

        cols = ("ip", "mac", "reason", "blocked_at")
        heads = ("IP Address", "MAC Address", "Reason", "Blocked At")
        widths = {"ip": 140, "mac": 155, "reason": 220, "blocked_at": 160}
        _, self._tree = make_scrolled_tree(self, cols, heads, widths)

        for iid in self._tree.get_children():
            self._tree.item(iid, tags=("red",))

        act_bar = tk.Frame(self, bg=BG_DARK)
        act_bar.pack(fill="x", padx=8, pady=6)

        ttk.Button(
            act_bar,
            text="🔓  Unblock Selected",
            style="Success.TButton",
            command=self._unblock,
        ).pack(side="left", padx=4)
        ttk.Button(
            act_bar,
            text="✖  Unblock All",
            style="Danger.TButton",
            command=self._unblock_all,
        ).pack(side="left", padx=4)

        self._count_var = tk.StringVar(value="")
        tk.Label(
            self,
            textvariable=self._count_var,
            bg=BG_DARK,
            fg=TEXT_SECONDARY,
            font=FONT_SMALL,
        ).pack(anchor="e", padx=8, pady=2)

    def refresh(self):
        blocked = self.db.get_blocked_ips()
        self._tree.delete(*self._tree.get_children())
        for b in blocked:
            self._tree.insert(
                "",
                "end",
                values=(b["ip"], b["mac"], b["reason"], b["blocked_at"]),
                tags=("red",),
            )
        self._count_var.set(f"{len(blocked)} blocked IP(s)")

    def _unblock(self):
        sel = self._tree.focus()
        if not sel:
            return
        ip = self._tree.set(sel, "ip")
        if messagebox.askyesno("Unblock", f"Remove firewall block for {ip}?"):
            self.svc.unblock_ip(ip)
            self.dashboard.log_info(f"Unblocked {ip}")
            self.refresh()

    def _unblock_all(self):
        blocked = self.db.get_blocked_ips()
        if not blocked:
            return
        if messagebox.askyesno("Unblock All", f"Remove all {len(blocked)} blocks?"):
            for b in blocked:
                self.svc.unblock_ip(b["ip"])
            self.dashboard.log_info(f"Unblocked {len(blocked)} IPs")
            self.refresh()
