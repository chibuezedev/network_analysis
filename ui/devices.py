import tkinter as tk
from tkinter import messagebox, ttk

from .theme import (
    ACCENT_CYAN,
    ACCENT_RED,
    BG_DARK,
    BG_HEADER,
    BG_PANEL,
    FONT_SMALL,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    make_scrolled_tree,
    section_label,
)


class DevicesPanel(ttk.Frame):
    def __init__(self, parent, db, monitor_service, dashboard, **kwargs):
        super().__init__(parent, style="TFrame", **kwargs)
        self.db = db
        self.svc = monitor_service
        self.dashboard = dashboard
        self._build()
        self.refresh()

    def _build(self):
        # Title row
        hdr = tk.Frame(self, bg=BG_DARK)
        hdr.pack(fill="x", padx=8, pady=(8, 4))
        section_label(hdr, "DEVICE INVENTORY", bg=BG_DARK).pack(side="left")

        btn_frame = tk.Frame(hdr, bg=BG_DARK)
        btn_frame.pack(side="right")

        self._btn_whitelist = ttk.Button(
            btn_frame,
            text="+ Whitelist",
            style="Success.TButton",
            command=self._add_whitelist_dialog,
        )
        self._btn_whitelist.pack(side="left", padx=4)

        ttk.Button(
            btn_frame,
            text="⟳ Refresh",
            style="TButton",
            command=self.refresh,
        ).pack(side="left", padx=4)

        # Search bar
        search_row = tk.Frame(self, bg=BG_DARK)
        search_row.pack(fill="x", padx=8, pady=(0, 4))
        tk.Label(
            search_row, text="Search:", bg=BG_DARK, fg=TEXT_SECONDARY, font=FONT_SMALL
        ).pack(side="left")
        self._search_var = tk.StringVar()
        self._search_var.trace_add("write", lambda *_: self.refresh())
        e = ttk.Entry(search_row, textvariable=self._search_var, width=30)
        e.pack(side="left", padx=6)

        # Table
        cols = ("ip", "mac", "status", "last_seen")
        heads = ("IP Address", "MAC Address", "Status", "Last Seen")
        widths = {"ip": 140, "mac": 160, "status": 110, "last_seen": 160}
        _, self._tree = make_scrolled_tree(self, cols, heads, widths)

        # Context-menu via right-click
        self._tree.bind("<Button-3>", self._show_context_menu)
        self._tree.bind("<Double-1>", lambda e: self._show_context_menu(e))

        # Context menu
        self._ctx = tk.Menu(
            self,
            tearoff=0,
            bg=BG_PANEL,
            fg=TEXT_PRIMARY,
            activebackground=BG_HEADER,
            activeforeground=ACCENT_CYAN,
            font=FONT_SMALL,
            relief="flat",
        )
        self._ctx.add_command(label="✅  Whitelist", command=self._ctx_whitelist)
        self._ctx.add_command(label="🔴  Block", command=self._ctx_block)
        self._ctx.add_separator()
        self._ctx.add_command(label="🔓  Unblock", command=self._ctx_unblock)
        self._ctx.add_command(label="✖  Remove WL", command=self._ctx_remove_wl)

        self._count_var = tk.StringVar(value="0 devices")
        tk.Label(
            self,
            textvariable=self._count_var,
            bg=BG_DARK,
            fg=TEXT_SECONDARY,
            font=FONT_SMALL,
        ).pack(anchor="e", padx=8, pady=2)

    def refresh(self):
        query = self._search_var.get().strip().lower()
        devices = self.db.get_all_devices()
        if query:
            devices = [
                d
                for d in devices
                if query in d["ip"].lower() or query in d["mac"].lower()
            ]

        # Save selection
        sel = self._tree.focus()
        sel_ip = self._tree.set(sel, "ip") if sel else None

        self._tree.delete(*self._tree.get_children())
        for d in devices:
            tag = {
                "Whitelisted": "green",
                "Blocked": "red",
                "Unknown": "amber",
            }.get(d["status"], "normal")
            iid = self._tree.insert(
                "",
                "end",
                values=(d["ip"], d["mac"], d["status"], d["last_seen"]),
                tags=(tag,),
            )
            if d["ip"] == sel_ip:
                self._tree.focus(iid)
                self._tree.selection_set(iid)

        self._count_var.set(f"{len(devices)} device(s)")

    # ------------------------------------------------------------------ #

    def _selected_device(self):
        sel = self._tree.focus()
        if not sel:
            return None, None
        ip = self._tree.set(sel, "ip")
        mac = self._tree.set(sel, "mac")
        return ip, mac

    def _show_context_menu(self, event):
        iid = self._tree.identify_row(event.y)
        if iid:
            self._tree.focus(iid)
            self._tree.selection_set(iid)
        try:
            self._ctx.tk_popup(event.x_root, event.y_root)
        finally:
            self._ctx.grab_release()

    def _ctx_whitelist(self):
        ip, mac = self._selected_device()
        if ip:
            self.svc.whitelist_ip(ip, mac)
            self.dashboard.log_whitelist(ip)
            self.refresh()

    def _ctx_block(self):
        ip, mac = self._selected_device()
        if ip:
            if messagebox.askyesno("Block IP", f"Block {ip}?"):
                self.svc.block_ip(ip, mac, "Manual block")
                self.dashboard.log_block(ip)
                self.refresh()

    def _ctx_unblock(self):
        ip, _ = self._selected_device()
        if ip:
            self.svc.unblock_ip(ip)
            self.dashboard.log_info(f"Unblocked {ip}")
            self.refresh()

    def _ctx_remove_wl(self):
        ip, _ = self._selected_device()
        if ip:
            self.svc.remove_whitelist(ip)
            self.dashboard.log_info(f"Removed {ip} from whitelist")
            self.refresh()

    def _add_whitelist_dialog(self):
        dlg = _WhitelistDialog(self)
        self.wait_window(dlg)
        if dlg.result:
            ip, mac, label = dlg.result
            self.svc.whitelist_ip(ip, mac, label)
            self.dashboard.log_whitelist(ip)
            self.refresh()


class _WhitelistDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.result = None
        self.title("Add to Whitelist")
        self.configure(bg=BG_PANEL)
        self.resizable(False, False)
        self.grab_set()

        pad = {"padx": 10, "pady": 5}
        tk.Label(
            self, text="IP Address", bg=BG_PANEL, fg=TEXT_SECONDARY, font=FONT_SMALL
        ).grid(row=0, column=0, sticky="w", **pad)
        self._ip = ttk.Entry(self, width=22)
        self._ip.grid(row=0, column=1, **pad)

        tk.Label(
            self, text="MAC Address", bg=BG_PANEL, fg=TEXT_SECONDARY, font=FONT_SMALL
        ).grid(row=1, column=0, sticky="w", **pad)
        self._mac = ttk.Entry(self, width=22)
        self._mac.grid(row=1, column=1, **pad)

        tk.Label(
            self, text="Label (opt.)", bg=BG_PANEL, fg=TEXT_SECONDARY, font=FONT_SMALL
        ).grid(row=2, column=0, sticky="w", **pad)
        self._label = ttk.Entry(self, width=22)
        self._label.grid(row=2, column=1, **pad)

        btns = tk.Frame(self, bg=BG_PANEL)
        btns.grid(row=3, column=0, columnspan=2, pady=8)
        ttk.Button(btns, text="Add", style="Success.TButton", command=self._ok).pack(
            side="left", padx=6
        )
        ttk.Button(btns, text="Cancel", command=self.destroy).pack(side="left", padx=6)

        self._ip.focus()
        self.bind("<Return>", lambda _: self._ok())

    def _ok(self):
        ip = self._ip.get().strip()
        mac = self._mac.get().strip()
        label = self._label.get().strip()
        if ip and mac:
            self.result = (ip, mac, label)
            self.destroy()
        else:
            tk.Label(
                self,
                text="IP and MAC required",
                bg=BG_PANEL,
                fg=ACCENT_RED,
                font=FONT_SMALL,
            ).grid(row=4, columnspan=2)
