"""
gui.py
──────
Graphical User Interface for Secure File Sharing over WLAN.
Project Abstract by: ALAN JAISON

Features:
  - Simple interface for connecting to receiver & selecting files
  - Authentication management (passphrase / pre-shared key)
  - Real-time transfer monitoring (progress bar, speed MB/s, chunk count)
  - Cryptographic delivery confirmation (AES-256-GCM decryption & SHA-256 verification)
  - WLAN Receiver mode & Mobile Web Portal support
  - Standalone SHA-256 File Integrity Tool
  - Live cryptographic activity console
"""

import os
import sys
import time
import socket
import threading
from typing import Optional, Dict, Any, List
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import webbrowser

# Attempt to load customtkinter if available, otherwise use modern tkinter ttk
try:
    import customtkinter as ctk
    USE_CTK = True
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
except ImportError:
    USE_CTK = False

import crypto_utils
import server
import client
from server import SecureWLANServer, start_portal_server, get_wlan_ip, format_size
from client import SecureWLANClient

# ── Colors & Aesthetics ───────────────────────────────────────────────────────
BG_DEEP      = "#0f1318"   # Dark canvas
BG_PANEL     = "#161b22"   # Panel background
BG_CARD      = "#21262d"   # Card / list items
BG_SIDEBAR   = "#111419"   # Sidebar background

ACCENT       = "#1f6feb"   # Electric blue
ACCENT_HOVER = "#388bfd"   # Hover
SUCCESS      = "#238636"   # Emerald green
SUCCESS_TEXT = "#3fb950"
DANGER       = "#da3633"   # Crimson red
DANGER_TEXT  = "#f85149"
WARN         = "#d29922"   # Amber
WARN_TEXT    = "#e3b341"

TEXT_PRIMARY = "#f0f6fc"   # White / high contrast
TEXT_MUTED   = "#8b949e"   # Slate grey


class SecureFileSharingApp:

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Secure File Sharing over WLAN — Alan Jaison")
        self.root.geometry("1060x720")
        self.root.minsize(920, 620)
        self.root.configure(bg=BG_DEEP)

        # Set window icon if exists
        try:
            base_path = sys._MEIPASS if getattr(sys, 'frozen', False) else os.path.dirname(__file__)
            icon_path = os.path.join(base_path, "icon.ico")
            if os.path.exists(icon_path):
                self.root.iconbitmap(icon_path)
        except Exception:
            pass

        # State
        self.server_instance: Optional[SecureWLANServer] = None
        self.portal_instance = None
        self.send_files_list: List[str] = []
        self.active_tab = "send"
        self.is_transferring = False

        # Config variables
        self.var_local_ip   = tk.StringVar(value=get_wlan_ip())
        self.var_server_port = tk.StringVar(value="8765")
        self.var_server_key  = tk.StringVar(value="AlanJaisonWLAN2026")
        self.var_save_dir    = tk.StringVar(value=os.path.abspath("./received_files"))

        self.var_rx_ip       = tk.StringVar(value=get_wlan_ip())
        self.var_rx_port     = tk.StringVar(value="8765")
        self.var_client_key  = tk.StringVar(value="AlanJaisonWLAN2026")
        self.var_client_name = tk.StringVar(value=socket.gethostname())

        # Bind logging callbacks
        server.LOG_CALLBACK = self.log_message
        server.STATUS_CALLBACK = self.on_server_status_update
        server.CONN_CALLBACK = self.on_conn_event

        self._configure_styles()
        self._build_ui()
        self.switch_tab("send")

        # Periodically refresh IP
        self._periodic_ip_refresh()

    def _configure_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=BG_PANEL, foreground=TEXT_PRIMARY)
        style.configure("TProgressbar", thickness=16, troughcolor=BG_CARD, background=SUCCESS)

    def _build_ui(self):
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_rowconfigure(1, weight=0)
        self.root.grid_columnconfigure(0, weight=0)
        self.root.grid_columnconfigure(1, weight=1)

        self._build_sidebar()
        self._build_status_bar()

        # Tab containers
        self.tab_container = tk.Frame(self.root, bg=BG_DEEP)
        self.tab_container.grid(row=0, column=1, sticky="nsew", padx=16, pady=16)
        self.tab_container.grid_rowconfigure(0, weight=1)
        self.tab_container.grid_columnconfigure(0, weight=1)

        self.frames = {
            "send": self._build_send_tab(),
            "receive": self._build_receive_tab(),
            "integrity": self._build_integrity_tab(),
            "console": self._build_console_tab(),
            "about": self._build_about_tab(),
        }

    # ── Sidebar ───────────────────────────────────────────────────────────────
    def _build_sidebar(self):
        sb = tk.Frame(self.root, width=220, bg=BG_SIDEBAR)
        sb.grid(row=0, column=0, sticky="nsew")
        sb.grid_propagate(False)

        # Branding
        title_box = tk.Frame(sb, bg=BG_SIDEBAR)
        title_box.pack(fill="x", padx=18, pady=(24, 6))

        dot = tk.Canvas(title_box, width=12, height=12, bg=BG_SIDEBAR, highlightthickness=0)
        dot.create_oval(1, 1, 11, 11, fill="#58a6ff", outline="")
        dot.pack(side="left", padx=(0, 8))

        lbl_t = tk.Label(title_box, text="Secure WLAN", font=("Segoe UI", 13, "bold"),
                         fg=TEXT_PRIMARY, bg=BG_SIDEBAR)
        lbl_t.pack(side="left")

        lbl_sub = tk.Label(sb, text="AES-256-GCM • SHA-256\nALAN JAISON", font=("Segoe UI", 9),
                           fg=TEXT_MUTED, bg=BG_SIDEBAR, justify="left")
        lbl_sub.pack(anchor="w", padx=20, pady=(0, 16))

        # Thin separator
        sep = tk.Frame(sb, height=1, bg="#30363d")
        sep.pack(fill="x", padx=14, pady=(0, 16))

        # Navigation Buttons
        self.nav_btns = {}
        items = [
            ("send",      "📤  Send (Client)"),
            ("receive",   "📥  Receive (Server)"),
            ("integrity", "🔍  SHA-256 Integrity"),
            ("console",   "📜  Live Console"),
            ("about",     "✦  Abstract & About"),
        ]

        for key, text in items:
            btn = tk.Button(
                sb, text=text, anchor="w", font=("Segoe UI", 11),
                fg=TEXT_MUTED, bg=BG_SIDEBAR, activebackground=ACCENT,
                activeforeground="#ffffff", relief="flat", bd=0, padx=14, pady=10,
                cursor="hand2", command=lambda k=key: self.switch_tab(k)
            )
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_btns[key] = btn

    # ── Status Bar ────────────────────────────────────────────────────────────
    def _build_status_bar(self):
        bar = tk.Frame(self.root, height=32, bg=BG_SIDEBAR)
        bar.grid(row=1, column=0, columnspan=2, sticky="ew")

        self.lbl_ip_status = tk.Label(
            bar, text=f"  📡 WLAN IP: {self.var_local_ip.get()}",
            font=("Segoe UI", 9, "bold"), fg=SUCCESS_TEXT, bg=BG_SIDEBAR
        )
        self.lbl_ip_status.pack(side="left", padx=12)

        self.lbl_crypto_badge = tk.Label(
            bar, text="🛡 AES-256-GCM + SHA-256 Authenticated",
            font=("Segoe UI", 9), fg="#58a6ff", bg=BG_SIDEBAR
        )
        self.lbl_crypto_badge.pack(side="left", padx=16)

        self.lbl_devices = tk.Label(
            bar, text="0 active transfers  ", font=("Segoe UI", 9),
            fg=TEXT_MUTED, bg=BG_SIDEBAR
        )
        self.lbl_devices.pack(side="right", padx=12)

    def switch_tab(self, key: str):
        self.active_tab = key
        for k, btn in self.nav_btns.items():
            if k == key:
                btn.configure(bg=ACCENT, fg="#ffffff", font=("Segoe UI", 11, "bold"))
            else:
                btn.configure(bg=BG_SIDEBAR, fg=TEXT_MUTED, font=("Segoe UI", 11))

        for k, f in self.frames.items():
            f.pack_forget()

        self.frames[key].pack(fill="both", expand=True)

    # ── TAB 1: Send Files (Client Mode) ───────────────────────────────────────
    def _build_send_tab(self) -> tk.Frame:
        f = tk.Frame(self.tab_container, bg=BG_DEEP)

        # Connection & Authentication Panel
        card_conn = tk.LabelFrame(f, text=" 1. Receiver WLAN Connection & Authentication ",
                                  font=("Segoe UI", 10, "bold"), fg=TEXT_PRIMARY, bg=BG_PANEL, bd=1, relief="solid")
        card_conn.pack(fill="x", pady=(0, 12), ipady=4)

        row1 = tk.Frame(card_conn, bg=BG_PANEL)
        row1.pack(fill="x", padx=12, pady=6)

        tk.Label(row1, text="Receiver IP:", font=("Segoe UI", 10), fg=TEXT_MUTED, bg=BG_PANEL).pack(side="left")
        e_ip = tk.Entry(row1, textvariable=self.var_rx_ip, font=("Segoe UI", 10), bg=BG_CARD, fg=TEXT_PRIMARY,
                        insertbackground=TEXT_PRIMARY, relief="flat", width=16)
        e_ip.pack(side="left", padx=(6, 18), ipady=3)

        tk.Label(row1, text="Port:", font=("Segoe UI", 10), fg=TEXT_MUTED, bg=BG_PANEL).pack(side="left")
        e_port = tk.Entry(row1, textvariable=self.var_rx_port, font=("Segoe UI", 10), bg=BG_CARD, fg=TEXT_PRIMARY,
                          insertbackground=TEXT_PRIMARY, relief="flat", width=7)
        e_port.pack(side="left", padx=(6, 18), ipady=3)

        tk.Label(row1, text="Auth Key (AES-256):", font=("Segoe UI", 10), fg=TEXT_MUTED, bg=BG_PANEL).pack(side="left")
        self.entry_auth_key = tk.Entry(row1, textvariable=self.var_client_key, show="•", font=("Segoe UI", 10),
                                       bg=BG_CARD, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat", width=22)
        self.entry_auth_key.pack(side="left", padx=(6, 8), ipady=3)

        btn_show_key = tk.Button(row1, text="👁", font=("Segoe UI", 9), bg=BG_CARD, fg=TEXT_PRIMARY,
                                 relief="flat", cursor="hand2", command=self._toggle_auth_key_visibility)
        btn_show_key.pack(side="left", padx=2)

        # File Selection Panel
        card_files = tk.LabelFrame(f, text=" 2. File Selection & Integrity Preview (SHA-256) ",
                                   font=("Segoe UI", 10, "bold"), fg=TEXT_PRIMARY, bg=BG_PANEL, bd=1, relief="solid")
        card_files.pack(fill="both", expand=True, pady=(0, 12))

        btn_box = tk.Frame(card_files, bg=BG_PANEL)
        btn_box.pack(fill="x", padx=12, pady=8)

        btn_add = tk.Button(btn_box, text="＋  Select Files to Share", font=("Segoe UI", 10, "bold"),
                            bg=ACCENT, fg="#ffffff", activebackground=ACCENT_HOVER, relief="flat",
                            padx=14, pady=6, cursor="hand2", command=self.select_files_to_send)
        btn_add.pack(side="left", padx=(0, 8))

        btn_clear = tk.Button(btn_box, text="✕  Clear Selected", font=("Segoe UI", 10),
                              bg=BG_CARD, fg=TEXT_MUTED, relief="flat", padx=12, pady=6,
                              cursor="hand2", command=self.clear_send_files)
        btn_clear.pack(side="left")

        self.lbl_selected_count = tk.Label(btn_box, text="0 files selected", font=("Segoe UI", 10),
                                           fg=TEXT_MUTED, bg=BG_PANEL)
        self.lbl_selected_count.pack(side="right")

        # Treeview / List of files to send
        tree_frame = tk.Frame(card_files, bg=BG_PANEL)
        tree_frame.pack(fill="both", expand=True, padx=12, pady=(0, 8))

        columns = ("name", "size", "sha256")
        self.send_tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=5)
        self.send_tree.heading("name", text="File Name")
        self.send_tree.heading("size", text="Size")
        self.send_tree.heading("sha256", text="Original SHA-256 Hash")
        self.send_tree.column("name", width=220)
        self.send_tree.column("size", width=90, anchor="e")
        self.send_tree.column("sha256", width=420)

        sb_tree = ttk.Scrollbar(tree_frame, orient="vertical", command=self.send_tree.yview)
        self.send_tree.configure(yscrollcommand=sb_tree.set)
        self.send_tree.pack(side="left", fill="both", expand=True)
        sb_tree.pack(side="right", fill="y")

        # Transfer Monitor & Execution Panel
        card_monitor = tk.LabelFrame(f, text=" 3. Transfer Monitor & Cryptographic Delivery Confirmation ",
                                     font=("Segoe UI", 10, "bold"), fg=TEXT_PRIMARY, bg=BG_PANEL, bd=1, relief="solid")
        card_monitor.pack(fill="x", ipady=6)

        m_top = tk.Frame(card_monitor, bg=BG_PANEL)
        m_top.pack(fill="x", padx=12, pady=(8, 4))

        self.btn_send_now = tk.Button(
            m_top, text="🚀  Initiate Secure WLAN Transfer",
            font=("Segoe UI", 11, "bold"), bg=SUCCESS, fg="#ffffff", activebackground="#2ea043",
            relief="flat", padx=18, pady=8, cursor="hand2", command=self.start_send_transfer
        )
        self.btn_send_now.pack(side="left")

        self.lbl_transfer_status = tk.Label(
            m_top, text="Status: Ready to transmit", font=("Segoe UI", 10),
            fg=TEXT_MUTED, bg=BG_PANEL
        )
        self.lbl_transfer_status.pack(side="right", padx=8)

        # Progress bar
        self.progress_bar = ttk.Progressbar(card_monitor, orient="horizontal", mode="determinate")
        self.progress_bar.pack(fill="x", padx=12, pady=6)

        # Confirmation box
        self.lbl_confirm_receipt = tk.Label(
            card_monitor, text="Delivery Confirmation: Awaiting transmission...",
            font=("Segoe UI", 9), fg=TEXT_MUTED, bg=BG_PANEL, justify="left"
        )
        self.lbl_confirm_receipt.pack(anchor="w", padx=12, pady=(2, 6))

        return f

    # ── TAB 2: Receive Files (Server Mode) ─────────────────────────────────────
    def _build_receive_tab(self) -> tk.Frame:
        f = tk.Frame(self.tab_container, bg=BG_DEEP)

        # Configuration Card
        card_cfg = tk.LabelFrame(f, text=" Receiver WLAN Server Configuration ",
                                 font=("Segoe UI", 10, "bold"), fg=TEXT_PRIMARY, bg=BG_PANEL, bd=1, relief="solid")
        card_cfg.pack(fill="x", pady=(0, 12), ipady=6)

        r1 = tk.Frame(card_cfg, bg=BG_PANEL)
        r1.pack(fill="x", padx=12, pady=6)

        tk.Label(r1, text="WLAN IP:", font=("Segoe UI", 10), fg=TEXT_MUTED, bg=BG_PANEL).pack(side="left")
        tk.Label(r1, textvariable=self.var_local_ip, font=("Segoe UI", 10, "bold"), fg=SUCCESS_TEXT, bg=BG_PANEL).pack(side="left", padx=(6, 20))

        tk.Label(r1, text="Listen Port:", font=("Segoe UI", 10), fg=TEXT_MUTED, bg=BG_PANEL).pack(side="left")
        e_port = tk.Entry(r1, textvariable=self.var_server_port, font=("Segoe UI", 10), bg=BG_CARD, fg=TEXT_PRIMARY,
                          insertbackground=TEXT_PRIMARY, relief="flat", width=7)
        e_port.pack(side="left", padx=(6, 20), ipady=3)

        tk.Label(r1, text="Shared Auth Key:", font=("Segoe UI", 10), fg=TEXT_MUTED, bg=BG_PANEL).pack(side="left")
        e_key = tk.Entry(r1, textvariable=self.var_server_key, font=("Segoe UI", 10), bg=BG_CARD, fg=TEXT_PRIMARY,
                         insertbackground=TEXT_PRIMARY, relief="flat", width=22)
        e_key.pack(side="left", padx=(6, 8), ipady=3)

        r2 = tk.Frame(card_cfg, bg=BG_PANEL)
        r2.pack(fill="x", padx=12, pady=6)

        tk.Label(r2, text="Save To:", font=("Segoe UI", 10), fg=TEXT_MUTED, bg=BG_PANEL).pack(side="left")
        e_save = tk.Entry(r2, textvariable=self.var_save_dir, font=("Segoe UI", 10), bg=BG_CARD, fg=TEXT_PRIMARY,
                          insertbackground=TEXT_PRIMARY, relief="flat", width=46)
        e_save.pack(side="left", padx=(6, 8), ipady=3)

        btn_browse = tk.Button(r2, text="Browse…", font=("Segoe UI", 9), bg=BG_CARD, fg=TEXT_PRIMARY,
                               relief="flat", cursor="hand2", command=self.browse_save_dir)
        btn_browse.pack(side="left", padx=4)

        btn_open_folder = tk.Button(r2, text="📂 Open Folder", font=("Segoe UI", 9), bg=BG_CARD, fg="#58a6ff",
                                    relief="flat", cursor="hand2", command=self.open_received_folder)
        btn_open_folder.pack(side="left", padx=8)

        # Server Controls & Status
        r3 = tk.Frame(card_cfg, bg=BG_PANEL)
        r3.pack(fill="x", padx=12, pady=(10, 4))

        self.btn_start_server = tk.Button(
            r3, text="▶  Start Receiver Server", font=("Segoe UI", 11, "bold"),
            bg=SUCCESS, fg="#ffffff", activebackground="#2ea043", relief="flat",
            padx=16, pady=8, cursor="hand2", command=self.toggle_server
        )
        self.btn_start_server.pack(side="left")

        self.lbl_server_status = tk.Label(
            r3, text="Receiver: Stopped", font=("Segoe UI", 10, "bold"),
            fg=TEXT_MUTED, bg=BG_PANEL
        )
        self.lbl_server_status.pack(side="left", padx=16)

        # Mobile Web Portal Card
        card_portal = tk.LabelFrame(f, text=" Mobile Computing WLAN Web Portal (Browser Access) ",
                                    font=("Segoe UI", 10, "bold"), fg=TEXT_PRIMARY, bg=BG_PANEL, bd=1, relief="solid")
        card_portal.pack(fill="x", pady=(0, 12), ipady=4)

        portal_box = tk.Frame(card_portal, bg=BG_PANEL)
        portal_box.pack(fill="x", padx=12, pady=6)

        self.lbl_portal_link = tk.Label(
            portal_box,
            text=f"📱 Mobile Browser Link: http://{self.var_local_ip.get()}:8766  (Requires Authentication Key)",
            font=("Segoe UI", 10), fg="#58a6ff", bg=BG_PANEL, cursor="hand2"
        )
        self.lbl_portal_link.pack(side="left")
        self.lbl_portal_link.bind("<Button-1>", lambda e: webbrowser.open(f"http://{self.var_local_ip.get()}:8766"))

        # Received Files History
        card_hist = tk.LabelFrame(f, text=" Received & Decrypted Files (AES-256-GCM + Verified SHA-256) ",
                                  font=("Segoe UI", 10, "bold"), fg=TEXT_PRIMARY, bg=BG_PANEL, bd=1, relief="solid")
        card_hist.pack(fill="both", expand=True)

        rx_tree_frame = tk.Frame(card_hist, bg=BG_PANEL)
        rx_tree_frame.pack(fill="both", expand=True, padx=12, pady=8)

        cols = ("file", "size", "sha256", "status")
        self.rx_tree = ttk.Treeview(rx_tree_frame, columns=cols, show="headings", height=6)
        self.rx_tree.heading("file", text="Received File")
        self.rx_tree.heading("size", text="Size")
        self.rx_tree.heading("sha256", text="Verified SHA-256 Digest")
        self.rx_tree.heading("status", text="Integrity Status")
        self.rx_tree.column("file", width=220)
        self.rx_tree.column("size", width=90, anchor="e")
        self.rx_tree.column("sha256", width=360)
        self.rx_tree.column("status", width=120)

        sb_rx = ttk.Scrollbar(rx_tree_frame, orient="vertical", command=self.rx_tree.yview)
        self.rx_tree.configure(yscrollcommand=sb_rx.set)
        self.rx_tree.pack(side="left", fill="both", expand=True)
        sb_rx.pack(side="right", fill="y")

        return f

    # ── TAB 3: SHA-256 Integrity Verification Tool ────────────────────────────
    def _build_integrity_tab(self) -> tk.Frame:
        f = tk.Frame(self.tab_container, bg=BG_DEEP)

        wrap = tk.LabelFrame(f, text=" Standalone SHA-256 Integrity Verification Utility ",
                             font=("Segoe UI", 11, "bold"), fg=TEXT_PRIMARY, bg=BG_PANEL, bd=1, relief="solid")
        wrap.pack(fill="both", expand=True, padx=4, pady=4, ipady=12)

        p = tk.Frame(wrap, bg=BG_PANEL)
        p.pack(fill="x", padx=18, pady=12)

        tk.Label(p, text="Select any file to calculate or verify its SHA-256 cryptographic hash:",
                 font=("Segoe UI", 10), fg=TEXT_MUTED, bg=BG_PANEL).pack(anchor="w", pady=(0, 8))

        btn_pick = tk.Button(p, text="📂 Choose File to Check Hash", font=("Segoe UI", 10, "bold"),
                             bg=ACCENT, fg="#ffffff", relief="flat", padx=14, pady=6, cursor="hand2",
                             command=self._tool_compute_hash)
        btn_pick.pack(anchor="w")

        self.lbl_tool_file = tk.Label(p, text="Selected File: None", font=("Segoe UI", 10),
                                      fg=TEXT_PRIMARY, bg=BG_PANEL)
        self.lbl_tool_file.pack(anchor="w", pady=(12, 4))

        self.lbl_tool_hash = tk.Label(p, text="SHA-256 Digest: —", font=("Consolas", 10),
                                      fg=SUCCESS_TEXT, bg=BG_PANEL)
        self.lbl_tool_hash.pack(anchor="w", pady=(0, 16))

        # Compare with expected hash
        tk.Label(p, text="Compare Against Expected Hash:", font=("Segoe UI", 10, "bold"),
                 fg=TEXT_PRIMARY, bg=BG_PANEL).pack(anchor="w", pady=(8, 4))

        row_comp = tk.Frame(p, bg=BG_PANEL)
        row_comp.pack(fill="x", pady=4)

        self.var_expected_hash = tk.StringVar()
        e_exp = tk.Entry(row_comp, textvariable=self.var_expected_hash, font=("Consolas", 10),
                         bg=BG_CARD, fg=TEXT_PRIMARY, insertbackground=TEXT_PRIMARY, relief="flat", width=66)
        e_exp.pack(side="left", ipady=4, padx=(0, 8))

        btn_verify = tk.Button(row_comp, text="Verify Match", font=("Segoe UI", 10, "bold"),
                               bg=SUCCESS, fg="#ffffff", relief="flat", padx=12, pady=4,
                               cursor="hand2", command=self._tool_verify_hash)
        btn_verify.pack(side="left")

        self.lbl_tool_result = tk.Label(p, text="", font=("Segoe UI", 11, "bold"), bg=BG_PANEL)
        self.lbl_tool_result.pack(anchor="w", pady=12)

        return f

    # ── TAB 4: Console Log ────────────────────────────────────────────────────
    def _build_console_tab(self) -> tk.Frame:
        f = tk.Frame(self.tab_container, bg=BG_DEEP)

        hdr = tk.Frame(f, bg=BG_DEEP)
        hdr.pack(fill="x", pady=(0, 8))

        tk.Label(hdr, text="Activity & Cryptographic Audit Log", font=("Segoe UI", 12, "bold"),
                 fg=TEXT_PRIMARY, bg=BG_DEEP).pack(side="left")

        btn_clear = tk.Button(hdr, text="🗑 Clear Log", font=("Segoe UI", 9),
                              bg=BG_CARD, fg=TEXT_MUTED, relief="flat", padx=10, pady=4,
                              cursor="hand2", command=self.clear_console)
        btn_clear.pack(side="right")

        text_wrap = tk.Frame(f, bg="#0d1117", bd=1, relief="solid")
        text_wrap.pack(fill="both", expand=True)

        self.log_text = tk.Text(
            text_wrap, bg="#0d1117", fg="#c9d1d9", font=("Consolas", 10),
            wrap="word", state="disabled", bd=0, padx=10, pady=10
        )
        sb_log = ttk.Scrollbar(text_wrap, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb_log.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        sb_log.pack(side="right", fill="y")

        # Color tags
        self.log_text.tag_config("info",    foreground=SUCCESS_TEXT)
        self.log_text.tag_config("error",   foreground=DANGER_TEXT)
        self.log_text.tag_config("warning", foreground=WARN_TEXT)
        self.log_text.tag_config("auth",    foreground="#58a6ff")
        self.log_text.tag_config("normal",  foreground="#c9d1d9")

        return f

    # ── TAB 5: About & Abstract ───────────────────────────────────────────────
    def _build_about_tab(self) -> tk.Frame:
        f = tk.Frame(self.tab_container, bg=BG_DEEP)

        card = tk.LabelFrame(f, text=" Project Abstract ", font=("Segoe UI", 11, "bold"),
                             fg=TEXT_PRIMARY, bg=BG_PANEL, bd=1, relief="solid")
        card.pack(fill="both", expand=True, padx=4, pady=4, ipady=12)

        txt = (
            "SECURE FILE SHARING OVER WLAN\n"
            "Project Abstract\n"
            "Submitted by: ALAN JAISON\n\n"
            "ABSTRACT\n"
            "Secure File Sharing over WLAN is a software application designed to enable secure and "
            "efficient file transfer between devices connected to the same Wireless Local Area Network (WLAN). "
            "The system eliminates the need for external internet-based file-sharing services by allowing "
            "devices on the same network to communicate through a local client-server architecture. Users can "
            "authenticate before initiating a transfer, select files for sharing, and transmit them securely over the WLAN.\n\n"
            "To enhance security, the proposed system employs AES-256-GCM encryption to protect file contents "
            "during transmission. At the receiving end, the encrypted data is decrypted using the appropriate key. "
            "SHA-256 hashing can additionally be used to verify file integrity by comparing the hash values of "
            "the original and received files. The application provides a simple interface for connecting to the "
            "receiver, selecting files, monitoring transfers, and confirming successful delivery. The project "
            "demonstrates the practical application of WLAN communication, client-server networking, authentication, "
            "encryption, and data integrity in mobile computing.\n\n"
            "Keywords: WLAN, Secure File Transfer, Client-Server Architecture, Authentication, "
            "AES-256-GCM, SHA-256, Data Integrity, Mobile Computing."
        )

        lbl = tk.Label(card, text=txt, font=("Segoe UI", 10), fg=TEXT_PRIMARY,
                       bg=BG_PANEL, justify="left", wraplength=760)
        lbl.pack(padx=20, pady=16, anchor="nw")

        return f

    # ── Client / Sending Logic ────────────────────────────────────────────────
    def _toggle_auth_key_visibility(self):
        current = self.entry_auth_key.cget("show")
        self.entry_auth_key.configure(show="" if current == "•" else "•")

    def select_files_to_send(self):
        paths = filedialog.askopenfilenames(title="Select Files for Secure WLAN Transfer")
        if not paths:
            return

        for p in paths:
            if p not in self.send_files_list:
                self.send_files_list.append(p)
                size_str = format_size(os.path.getsize(p))
                # Compute SHA-256 preview
                sha_str = crypto_utils.compute_sha256(p)
                self.send_tree.insert("", "end", values=(os.path.basename(p), size_str, sha_str))

        n = len(self.send_files_list)
        self.lbl_selected_count.configure(text=f"{n} file{'s' if n != 1 else ''} selected")
        self.log_message("info", f"[SELECTION] Added {len(paths)} file(s) for transfer.")

    def clear_send_files(self):
        self.send_files_list.clear()
        for item in self.send_tree.get_children():
            self.send_tree.delete(item)
        self.lbl_selected_count.configure(text="0 files selected")
        self.lbl_confirm_receipt.configure(text="Delivery Confirmation: Awaiting transmission...", fg=TEXT_MUTED)

    def start_send_transfer(self):
        if not self.send_files_list:
            messagebox.showwarning("No Files", "Please select one or more files to transmit.")
            return

        rx_ip = self.var_rx_ip.get().strip()
        try:
            rx_port = int(self.var_rx_port.get().strip())
        except ValueError:
            messagebox.showerror("Invalid Port", "Receiver port must be a valid number.")
            return

        auth_key = self.var_client_key.get().strip()
        if not auth_key:
            messagebox.showwarning("Key Required", "Please enter the pre-shared authentication key.")
            return

        self.btn_send_now.configure(state="disabled", text="⌛  Transmitting...")
        self.is_transferring = True
        self.progress_bar["value"] = 0

        def _worker():
            client_inst = SecureWLANClient(
                receiver_ip=rx_ip,
                port=rx_port,
                auth_key=auth_key,
                client_name=self.var_client_name.get()
            )

            total_files = len(self.send_files_list)
            for idx, filepath in enumerate(list(self.send_files_list), start=1):
                fname = os.path.basename(filepath)
                self.root.after(0, lambda fn=fname, i=idx: self.lbl_transfer_status.configure(
                    text=f"Transmitting file {i}/{total_files}: '{fn}'...", fg=WARN_TEXT
                ))

                def on_progress(p_info):
                    pct = p_info["percent"]
                    speed = p_info["speed_mbps"]
                    self.root.after(0, lambda: self._update_send_progress(pct, speed, fname))

                try:
                    result = client_inst.send_file(
                        filepath=filepath,
                        progress_callback=on_progress,
                        log_callback=self.log_message
                    )

                    if result["success"]:
                        orig_h = result["original_sha256"]
                        rx_h   = result["receiver_sha256"]
                        confirm_text = (
                            f"✓ DELIVERY CONFIRMED for '{fname}'!\n"
                            f"  • Encryption: AES-256-GCM (Authenticated)\n"
                            f"  • Sender SHA-256:   {orig_h}\n"
                            f"  • Receiver SHA-256: {rx_h}\n"
                            f"  • Integrity Match:  VERIFIED ✓ (Speed: {result['speed_mbps']:.2f} MB/s)"
                        )
                        self.root.after(0, lambda t=confirm_text: self.lbl_confirm_receipt.configure(
                            text=t, fg=SUCCESS_TEXT
                        ))
                    else:
                        err_text = f"✕ Transfer Failed for '{fname}': {result['message']}"
                        self.root.after(0, lambda t=err_text: self.lbl_confirm_receipt.configure(
                            text=t, fg=DANGER_TEXT
                        ))
                except Exception as e:
                    self.log_message("error", f"[CLIENT ERR] Failed to transfer '{fname}': {e}")
                    self.root.after(0, lambda err=str(e): self.lbl_confirm_receipt.configure(
                        text=f"✕ Error: {err}", fg=DANGER_TEXT
                    ))

            self.root.after(0, self._on_send_complete)

        threading.Thread(target=_worker, daemon=True).start()

    def _update_send_progress(self, percent: int, speed: float, filename: str):
        self.progress_bar["value"] = percent
        self.lbl_transfer_status.configure(
            text=f"Transmitting: {percent}% at {speed:.2f} MB/s", fg=SUCCESS_TEXT
        )

    def _on_send_complete(self):
        self.is_transferring = False
        self.btn_send_now.configure(state="normal", text="🚀  Initiate Secure WLAN Transfer")
        self.lbl_transfer_status.configure(text="Transfer complete", fg=SUCCESS_TEXT)

    # ── Receiver / Server Logic ───────────────────────────────────────────────
    def browse_save_dir(self):
        folder = filedialog.askdirectory(title="Select Destination Folder for Received Files")
        if folder:
            self.var_save_dir.set(os.path.abspath(folder))

    def open_received_folder(self):
        folder = self.var_save_dir.get()
        if os.path.exists(folder):
            os.startfile(folder)
        else:
            messagebox.showinfo("Folder", "Destination folder does not exist yet.")

    def toggle_server(self):
        if self.server_instance:
            # Stop
            self.server_instance.stop()
            self.server_instance = None
            if self.portal_instance:
                try:
                    self.portal_instance.shutdown()
                except Exception:
                    pass
                self.portal_instance = None

            self.btn_start_server.configure(text="▶  Start Receiver Server", bg=SUCCESS)
            self.lbl_server_status.configure(text="Receiver: Stopped", fg=TEXT_MUTED)
            self.lbl_devices.configure(text="0 active transfers  ")
        else:
            # Start
            port = int(self.var_server_port.get().strip())
            key = self.var_server_key.get().strip()
            save_dir = self.var_save_dir.get().strip()

            self.server_instance = SecureWLANServer(
                host="0.0.0.0",
                port=port,
                auth_key=key,
                save_dir=save_dir
            )
            self.server_instance.start()

            # Also start mobile web portal on port + 1
            try:
                self.portal_instance = start_portal_server(
                    port=port + 1,
                    auth_key=key,
                    save_dir=save_dir,
                    shared_files=self.send_files_list
                )
            except Exception as e:
                self.log_message("warning", f"[PORTAL] Web portal start error: {e}")

            self.btn_start_server.configure(text="■  Stop Receiver Server", bg=DANGER)
            self.lbl_server_status.configure(text=f"Receiver: Listening on port {port}", fg=SUCCESS_TEXT)

    def on_server_status_update(self, status: Dict[str, Any]):
        event = status.get("event")
        if event == "delivered":
            fname = status["filename"]
            sha   = status["sha256"]
            saved = status["saved_to"]
            size_str = format_size(os.path.getsize(saved)) if os.path.exists(saved) else "—"
            self.root.after(0, lambda: self.rx_tree.insert("", 0, values=(fname, size_str, sha, "✓ Verified Match")))

    def on_conn_event(self, action: str):
        count = self.server_instance.active_connections if self.server_instance else 0
        self.root.after(0, lambda: self.lbl_devices.configure(text=f"{count} active connection{'s' if count != 1 else ''}  "))

    # ── Standalone SHA-256 Tool ───────────────────────────────────────────────
    def _tool_compute_hash(self):
        fpath = filedialog.askopenfilename(title="Select File to Compute SHA-256")
        if not fpath:
            return
        self.current_tool_file = fpath
        self.lbl_tool_file.configure(text=f"Selected File: {os.path.basename(fpath)} ({format_size(os.path.getsize(fpath))})")
        sha = crypto_utils.compute_sha256(fpath)
        self.current_tool_hash = sha
        self.lbl_tool_hash.configure(text=f"SHA-256: {sha}")
        self.lbl_tool_result.configure(text="")

    def _tool_verify_hash(self):
        expected = self.var_expected_hash.get().strip().lower()
        if not hasattr(self, "current_tool_hash"):
            messagebox.showwarning("Select File", "Please choose a file first.")
            return
        if not expected:
            messagebox.showwarning("Enter Hash", "Please enter the expected SHA-256 hash.")
            return

        if expected == self.current_tool_hash.lower():
            self.lbl_tool_result.configure(text="✓ INTEGRITY VERIFIED! Exact SHA-256 hash match.", fg=SUCCESS_TEXT)
        else:
            self.lbl_tool_result.configure(text="✕ INTEGRITY MISMATCH! Hash does not match.", fg=DANGER_TEXT)

    # ── Periodic Refresh & Console Logging ────────────────────────────────────
    def _periodic_ip_refresh(self):
        wlan_ip = get_wlan_ip()
        self.var_local_ip.set(wlan_ip)
        self.lbl_ip_status.configure(text=f"  📡 WLAN IP: {wlan_ip}")
        self.lbl_portal_link.configure(text=f"📱 Mobile Browser Link: http://{wlan_ip}:8766  (Requires Authentication Key)")
        self.root.after(10000, self._periodic_ip_refresh)

    def log_message(self, level: str, msg: str):
        self.root.after(0, lambda: self._insert_log(level, msg))

    def _insert_log(self, level: str, msg: str):
        self.log_text.configure(state="normal")
        timestamp = time.strftime("[%H:%M:%S] ")
        tag = "info" if "MATCH" in msg or "DELIVERY CONFIRMED" in msg or "authenticated" in msg.lower() else level
        self.log_text.insert("end", timestamp, "normal")
        self.log_text.insert("end", msg + "\n", tag)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def clear_console(self):
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    app = SecureFileSharingApp()
    app.run()
