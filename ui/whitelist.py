import tkinter as tk
from tkinter import messagebox, ttk

from .theme import (
    BG_DARK,
    BG_PANEL,
    FONT_SMALL,
    TEXT_SECONDARY,
    make_scrolled_tree,
    section_label,
)


class WhitelistPanel(ttk.Frame):
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
        section_label(hdr, "TRUSTED DEVICES  (WHITELIST)", bg=BG_DARK).pack(side="left")

        btn_row = tk.Frame(hdr, bg=BG_DARK)
        btn_row.pack(side="right")
        ttk.Button(
            btn_row, text="⟳", style="TButton", width=2, command=self.refresh
        ).pack(side="right", padx=4)

        # Add form
        form = tk.Frame(self, bg=BG_PANEL, padx=10, pady=8)
        form.pack(fill="x", padx=8, pady=(0, 6))

        tk.Label(
            form, text="IP:", bg=BG_PANEL, fg=TEXT_SECONDARY, font=FONT_SMALL
        ).grid(row=0, column=0, sticky="w")
        self._ip_var = tk.StringVar()
        ttk.Entry(form, textvariable=self._ip_var, width=16).grid(
            row=0, column=1, padx=6
        )

        tk.Label(
            form, text="MAC:", bg=BG_PANEL, fg=TEXT_SECONDARY, font=FONT_SMALL
        ).grid(row=0, column=2, sticky="w")
        self._mac_var = tk.StringVar()
        ttk.Entry(form, textvariable=self._mac_var, width=18).grid(
            row=0, column=3, padx=6
        )

        tk.Label(
            form, text="Label:", bg=BG_PANEL, fg=TEXT_SECONDARY, font=FONT_SMALL
        ).grid(row=0, column=4, sticky="w")
        self._label_var = tk.StringVar()
        ttk.Entry(form, textvariable=self._label_var, width=14).grid(
            row=0, column=5, padx=6
        )

        ttk.Button(form, text="+ Add", style="Success.TButton", command=self._add).grid(
            row=0, column=6, padx=8
        )

        # Table
        cols = ("ip", "mac", "label", "added")
        heads = ("IP Address", "MAC Address", "Label", "Added")
        widths = {"ip": 140, "mac": 155, "label": 140, "added": 155}
        _, self._tree = make_scrolled_tree(self, cols, heads, widths)

        act_bar = tk.Frame(self, bg=BG_DARK)
        act_bar.pack(fill="x", padx=8, pady=6)
        ttk.Button(
            act_bar,
            text="✖  Remove Selected",
            style="Danger.TButton",
            command=self._remove,
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
        wl = self.db.get_whitelist()
        self._tree.delete(*self._tree.get_children())
        for w in wl:
            self._tree.insert(
                "",
                "end",
                values=(w["ip"], w["mac"], w["label"], w["added"]),
                tags=("green",),
            )
        self._count_var.set(f"{len(wl)} trusted device(s)")

    def _add(self):
        ip = self._ip_var.get().strip()
        mac = self._mac_var.get().strip()
        label = self._label_var.get().strip()
        if not ip or not mac:
            return
        self.svc.whitelist_ip(ip, mac, label)
        self.dashboard.log_whitelist(ip)
        self._ip_var.set("")
        self._mac_var.set("")
        self._label_var.set("")
        self.refresh()

    def _remove(self):
        sel = self._tree.focus()
        if not sel:
            return
        ip = self._tree.set(sel, "ip")
        if messagebox.askyesno("Remove", f"Remove {ip} from whitelist?"):
            self.svc.remove_whitelist(ip)
            self.dashboard.log_info(f"Removed whitelist entry {ip}")
            self.refresh()
