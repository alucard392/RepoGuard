"""Native desktop GUI for RepoGuard.

The GUI is a thin view over the shared :mod:`repoguard.scanner` engine. All
scanning happens on a background thread; results are delivered to the Tk main
loop through a queue. The GUI is strictly read-only.
"""

from __future__ import annotations

import os
import queue
import sys
import threading
import tkinter as tk
import traceback
from tkinter import filedialog, font as tkfont, messagebox, ttk
from typing import Callable

from .detectors import Finding
from .scanner import ScanCancelled, ScanError, ScanResult, scan_repository
from .staged import GitError, is_git_repo

SEVERITIES = ("high", "medium", "low")


# ---------------------------------------------------------------------------
# Controller (Tk-independent, unit-testable)
# ---------------------------------------------------------------------------

class ScanController:
    """Run a scan on a worker thread and deliver the outcome via a queue."""

    def __init__(self) -> None:
        self.queue: "queue.Queue[tuple[str, object]]" = queue.Queue()
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()
        self._lock = threading.Lock()
        self.on_result: Callable[[ScanResult], None] = lambda result: None
        self.on_error: Callable[[str], None] = lambda message: None
        self.on_cancelled: Callable[[], None] = lambda: None
        self.on_traceback: Callable[[str], None] = lambda text: None

    def start(self, root: str, staged: bool, max_size_mb: float = 5.0) -> bool:
        """Start a scan. Returns False if one is already running."""

        with self._lock:
            if self.is_running():
                return False
            self._cancel = threading.Event()
            thread = threading.Thread(
                target=self._run,
                args=(root, staged, max_size_mb, self._cancel),
                daemon=True,
                name="repoguard-scan",
            )
            self._thread = thread
            thread.start()
            return True

    def _run(
        self,
        root: str,
        staged: bool,
        max_size_mb: float,
        cancel: threading.Event,
    ) -> None:
        try:
            result = scan_repository(
                root,
                staged=staged,
                max_size_mb=max_size_mb,
                cancel_event=cancel,
            )
        except ScanCancelled:
            self.queue.put(("cancelled", None))
        except (ScanError, GitError) as exc:
            self.queue.put(("error", str(exc)))
        except Exception as exc:  # noqa: BLE001 - surfaced in the UI
            self.queue.put(("error", f"{type(exc).__name__}: {exc}"))
            self.queue.put(("traceback", traceback.format_exc()))
        else:
            self.queue.put(("result", result))

    def poll(self) -> bool:
        """Deliver queued outcomes. Returns True while work or messages remain."""

        while True:
            try:
                kind, payload = self.queue.get_nowait()
            except queue.Empty:
                break
            if kind == "result":
                self.on_result(payload)  # type: ignore[arg-type]
            elif kind == "error":
                self.on_error(str(payload))
            elif kind == "cancelled":
                self.on_cancelled()
            elif kind == "traceback":
                self.on_traceback(str(payload))
        return self.is_running() or not self.queue.empty()

    def cancel(self) -> None:
        self._cancel.set()

    def is_running(self) -> bool:
        thread = self._thread
        return thread is not None and thread.is_alive()


# ---------------------------------------------------------------------------
# Tk view
# ---------------------------------------------------------------------------

BG = "#f6f7f9"
CARD = "#ffffff"
TEXT = "#1f2937"
MUTED = "#6b7280"
ACCENT = "#2563eb"
ACCENT_DARK = "#1d4ed8"
HIGH_COLOR = "#b91c1c"
MEDIUM_COLOR = "#b45309"
LOW_COLOR = "#047857"
BORDER = "#e5e7eb"
HOVER_BG = "#eef2f7"
FOCUS_BORDER = "#2563eb"

FONT_FAMILY = "Segoe UI" if os.name == "nt" else "Helvetica"

USAGE_GUIDE = """GETTING STARTED
1. Click Browse… and select the root folder of the repository you want to inspect.
2. Click Scan Working Tree to inspect the files currently on disk.
3. If the folder is a Git repository, click Scan Staged to inspect only the staged index
   (the content that would enter your next commit), not unstaged edits.
4. Select a finding to see its severity, redacted evidence, why it matters and a fix.
5. Use the Severity filter and Search field to narrow the list. The count shows
   visible findings out of the total scan findings.
6. Use Copy path or Copy fix in the detail panel when you need to reference a result.
7. Click Cancel to request a cooperative stop during a scan.

WORKING TREE VS STAGED
Working Tree scans the current files on disk. Staged scans Git's index blobs only.
Staged mode requires Git and a repository. If you changed a file after staging it,
the staged scan intentionally sees the staged version, not the newer working copy.

SEVERITY
HIGH: likely credentials, tokens or private keys. Assume a real credential is
exposed: revoke/rotate it immediately, remove it from the repository, and follow
your provider's incident guidance. Removing a line does not invalidate a leaked key.
MEDIUM: heuristic generic-secret or sensitive-file/size issue. Review the context.
LOW: repository metadata hygiene, such as a missing README or license.

IGNORE RULES
Create .repoguardignore in the selected repository root. Supported examples:
  *.log          Ignore matching basenames at any depth
  build/         Ignore a directory and its contents
  /config/dev    Match a root-anchored path
  **/secrets.json Match that basename at any depth
Blank lines and lines beginning with # are ignored. Negation rules (!) and the
complete Git .gitignore syntax are not supported.

COMMAND LINE
  python -m repoguard gui [PATH]
  python -m repoguard scan [PATH]
  python -m repoguard scan --staged [PATH]
  python -m repoguard scan --format json [PATH]
  python -m repoguard scan --fail-on low [PATH]
Exit codes: 0 = no findings at/above threshold; 1 = findings at/above threshold;
2 = usage or scan error.

PRIVACY AND SAFETY
RepoGuard runs locally. It does not upload files, make network requests, send
telemetry, or modify the scanned repository. Findings contain redacted snippets.
The scanner is heuristic, not a guarantee: obfuscated/split secrets may be missed,
and generic rules may produce false positives. Always review results.
Never paste real credentials into public GitHub issues. Use synthetic examples.
A clean scan does not replace code review, secret scanning on GitHub, or good
credential management.
"""


class RepoGuardApp:
    """The Tk application window."""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.controller = ScanController()
        self.controller.on_result = self._on_result
        self.controller.on_error = self._on_error
        self.controller.on_cancelled = self._on_cancelled
        self.controller.on_traceback = self._on_traceback

        self.result: ScanResult | None = None
        self.filtered: list[Finding] = []
        self.selected: Finding | None = None

        self.root.title("RepoGuard")
        self.root.geometry("1180x760")
        self.root.minsize(900, 600)
        self.root.configure(bg=BG)

        self._init_fonts()
        self._init_style()
        self._build()
        self._closing = False
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._poll()

    # -- setup ------------------------------------------------------------

    def _init_fonts(self) -> None:
        base = tkfont.nametofont("TkDefaultFont")
        family = base.actual("family")
        if family and family != FONT_FAMILY:
            try:
                tkfont.nametofont("TkDefaultFont").configure(family=FONT_FAMILY)
            except tk.TclError:
                pass
            family = tkfont.nametofont("TkDefaultFont").actual("family")
        self.f_body = tkfont.Font(family=family, size=10)
        self.f_bold = tkfont.Font(family=family, size=10, weight="bold")
        self.f_heading = tkfont.Font(family=family, size=12, weight="bold")
        self.f_card = tkfont.Font(family=family, size=20, weight="bold")
        try:
            self.f_mono = tkfont.Font(
                family="Consolas" if os.name == "nt" else "Menlo", size=10
            )
        except tk.TclError:
            self.f_mono = tkfont.Font(family=family, size=10)

    def _init_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=TEXT, font=self.f_body)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Title.TLabel", background=BG, foreground=TEXT, font=self.f_heading)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("TButton", background=CARD, foreground=TEXT, padding=(12, 8), borderwidth=1)
        style.map("TButton",
            background=[("active", HOVER_BG), ("pressed", "#dbeafe"), ("disabled", BG)],
            foreground=[("disabled", MUTED)],
            bordercolor=[("focus", FOCUS_BORDER), ("active", FOCUS_BORDER)],
        )
        style.configure(
            "Accent.TButton",
            background=ACCENT,
            foreground="#ffffff",
            padding=(14, 8),
            borderwidth=0,
        )
        style.map(
            "Accent.TButton",
            background=[("active", ACCENT_DARK), ("pressed", "#1e40af"), ("disabled", "#c7d2e4")],
            foreground=[("disabled", "#f8fafc")],
        )
        style.configure("TEntry",
            fieldbackground=CARD,
            foreground=TEXT,
            borderwidth=1,
            relief="flat",
            padding=(8, 6),
        )
        style.map("TEntry",
            bordercolor=[("focus", FOCUS_BORDER), ("!focus", BORDER)],
            lightcolor=[("focus", FOCUS_BORDER)],
            darkcolor=[("focus", FOCUS_BORDER)],
        )
        style.configure("TCombobox",
            fieldbackground=CARD,
            foreground=TEXT,
            borderwidth=1,
            relief="flat",
            padding=(8, 6),
        )
        style.map("TCombobox",
            bordercolor=[("focus", FOCUS_BORDER), ("!focus", BORDER)],
        )
        style.configure(
            "Treeview",
            background=CARD,
            fieldbackground=CARD,
            foreground=TEXT,
            rowheight=28,
            borderwidth=1,
            relief="flat",
        )
        style.map(
            "Treeview",
            background=[("selected", "#dbeafe"), ("focus", "#dbeafe")],
            foreground=[("selected", TEXT)],
        )
        style.configure(
            "Treeview.Heading",
            background="#eef1f5",
            foreground=TEXT,
            font=self.f_bold,
            relief="flat",
            padding=(10, 8),
            borderwidth=0,
        )
        style.map(
            "Treeview.Heading",
            background=[("active", "#e2e8f0")],
        )
        style.configure("Vertical.TScrollbar", background="#d7dbe2")
        style.configure(
            "Horizontal.TProgressbar",
            background=ACCENT,
            troughcolor="#e5e7eb",
            borderwidth=0,
        )

    def _build(self) -> None:
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(4, weight=1)

        header = ttk.Frame(self.root, padding=(16, 14, 16, 6))
        header.grid(row=0, column=0, sticky="ew")
        header.columnconfigure(1, weight=1)
        ttk.Label(header, text="RepoGuard", style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Label(
            header,
            text="Local, offline repository hygiene scanner",
            style="Muted.TLabel",
        ).grid(row=1, column=0, sticky="w")

        path_box = ttk.Frame(header)
        path_box.grid(row=0, column=1, rowspan=2, sticky="ew", padx=(24, 0))
        path_box.columnconfigure(1, weight=1)
        ttk.Label(path_box, text="Folder:").grid(row=0, column=0, sticky="w")
        self.path_var = tk.StringVar(value=os.getcwd())
        self.path_entry = ttk.Entry(
            path_box, textvariable=self.path_var, state="readonly"
        )
        self.path_entry.grid(row=0, column=1, sticky="ew", padx=(8, 8))
        ttk.Button(path_box, text="Browse…", command=self._browse).grid(row=0, column=2)

        toolbar = ttk.Frame(self.root, padding=(16, 0, 16, 10))
        toolbar.grid(row=1, column=0, sticky="ew")
        toolbar.columnconfigure(4, weight=1)
        self.scan_button = ttk.Button(
            toolbar,
            text="Scan Working Tree",
            style="Accent.TButton",
            command=self._scan_working_tree,
        )
        self.scan_button.grid(row=0, column=0, padx=(0, 8))
        self.staged_button = ttk.Button(
            toolbar, text="Scan Staged", command=self._scan_staged
        )
        self.staged_button.grid(row=0, column=1, padx=(0, 8))
        self.cancel_button = ttk.Button(
            toolbar, text="Cancel", command=self._cancel, state="disabled"
        )
        self.cancel_button.grid(row=0, column=2, padx=(0, 8))
        ttk.Button(toolbar, text="Refresh path", command=self._refresh_path).grid(
            row=0, column=3, padx=(0, 8)
        )
        self.staged_hint = ttk.Label(toolbar, text="", style="Muted.TLabel")
        self.staged_hint.grid(row=0, column=4, sticky="w", padx=(16, 0))
        ttk.Button(toolbar, text="How to use", command=self._show_usage).grid(
            row=0, column=5, padx=(12, 0)
        )
        ttk.Button(toolbar, text="About", command=self._show_about).grid(
            row=0, column=6, padx=(8, 0)
        )

        summary = ttk.Frame(self.root, padding=(16, 0, 16, 8))
        summary.grid(row=2, column=0, sticky="ew")
        for i in range(4):
            summary.columnconfigure(i, weight=1)
        self.card_labels: dict[str, tk.Label] = {}
        cards = (
            ("total", "Total", TEXT),
            ("high", "High", HIGH_COLOR),
            ("medium", "Medium", MEDIUM_COLOR),
            ("low", "Low", LOW_COLOR),
        )
        for i, (key, label, color) in enumerate(cards):
            card = tk.Frame(
                summary,
                bg=CARD,
                highlightbackground=BORDER,
                highlightthickness=1,
            )
            card.grid(
                row=0,
                column=i,
                sticky="nsew",
                padx=(0 if i == 0 else 12, 0),
            )
            card.columnconfigure(0, weight=1)
            tk.Label(
                card,
                text=label.upper(),
                bg=CARD,
                fg=MUTED,
                font=self.f_bold,
            ).grid(row=0, column=0, sticky="w", padx=(16, 0), pady=(12, 4))
            value = tk.Label(card, text="0", bg=CARD, fg=color, font=self.f_card)
            value.grid(row=1, column=0, sticky="w", padx=(16, 0), pady=(0, 12))
            self.card_labels[key] = value

        filters = ttk.Frame(self.root, padding=(16, 8, 16, 8))
        filters.grid(row=3, column=0, sticky="ew")
        filters.columnconfigure(3, weight=1)
        ttk.Label(filters, text="Severity:").grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.severity_var = tk.StringVar(value="All")
        self.severity_combo = ttk.Combobox(
            filters,
            textvariable=self.severity_var,
            state="readonly",
            width=10,
            values=["All", "High", "Medium", "Low"],
        )
        self.severity_combo.grid(row=0, column=1, padx=(0, 16))
        self.severity_combo.bind(
            "<<ComboboxSelected>>", lambda _event: self._render_table()
        )

        ttk.Label(filters, text="Search:").grid(row=0, column=2, sticky="w", padx=(16, 8))
        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._render_table())
        search = ttk.Entry(filters, textvariable=self.search_var)
        search.grid(row=0, column=3, sticky="ew", padx=(0, 8))
        self.count_label = ttk.Label(
            filters, text="0 findings", style="Muted.TLabel"
        )
        self.count_label.grid(row=0, column=4, sticky="e")

        body = ttk.Panedwindow(self.root, orient="horizontal")
        body.grid(row=4, column=0, sticky="nsew", padx=16, pady=(0, 8))

        table_frame = ttk.Frame(body)
        table_frame.columnconfigure(0, weight=1)
        table_frame.rowconfigure(0, weight=1)
        columns = ("severity", "rule", "path", "line")
        self.tree = ttk.Treeview(
            table_frame,
            columns=columns,
            show="headings",
            selectmode="browse",
        )
        widths = {"severity": 90, "rule": 170, "path": 420, "line": 60}
        for col in columns:
            self.tree.heading(col, text=col.capitalize())
            self.tree.column(
                col,
                width=widths[col],
                anchor="w" if col != "line" else "e",
            )
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(
            table_frame, orient="vertical", command=self.tree.yview
        )
        yscroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.tag_configure("high", foreground=HIGH_COLOR)
        self.tree.tag_configure("medium", foreground=MEDIUM_COLOR)
        self.tree.tag_configure("low", foreground=LOW_COLOR)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", self._on_double_click)
        body.add(table_frame, weight=3)

        detail_frame = ttk.Frame(body)
        detail_frame.columnconfigure(0, weight=1)
        detail_frame.rowconfigure(1, weight=1)
        detail_head = ttk.Frame(detail_frame)
        detail_head.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        detail_head.columnconfigure(0, weight=1)
        ttk.Label(detail_head, text="Detail", style="Title.TLabel").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Button(
            detail_head, text="Copy path", command=lambda: self._copy_selected("path")
        ).grid(row=0, column=1, padx=(8, 4))
        ttk.Button(
            detail_head, text="Copy fix", command=lambda: self._copy_selected("fix")
        ).grid(row=0, column=2, padx=(4, 4))
        ttk.Button(
            detail_head, text="Export JSON…", command=self._export_json
        ).grid(row=0, column=3, padx=(4, 0))
        self.detail_text = tk.Text(
            detail_frame,
            wrap="word",
            state="disabled",
            relief="flat",
            bg=CARD,
            fg=TEXT,
            font=self.f_mono,
            padx=14,
            pady=14,
            highlightbackground=BORDER,
            highlightthickness=1,
        )
        self.detail_text.grid(row=1, column=0, sticky="nsew")
        # Configure text tags for rich formatting
        self.detail_text.tag_configure("hint", foreground=MUTED, font=self.f_body)
        self.detail_text.tag_configure("heading", font=self.f_bold, foreground=TEXT, spacing3=6)
        self.detail_text.tag_configure("severity-high", foreground=HIGH_COLOR, font=self.f_bold)
        self.detail_text.tag_configure("severity-medium", foreground=MEDIUM_COLOR, font=self.f_bold)
        self.detail_text.tag_configure("severity-low", foreground=LOW_COLOR, font=self.f_bold)
        self.detail_text.tag_configure("label", font=self.f_bold, foreground=TEXT)
        self.detail_text.tag_configure("value", font=self.f_body, foreground=TEXT)
        self.detail_text.tag_configure("monospace", font=self.f_mono, foreground=TEXT, background="#f0f2f5", lmargin1=18, lmargin2=18, rmargin=18, spacing1=3, spacing3=3)
        self.detail_text.tag_configure("section", font=self.f_heading, foreground=ACCENT, spacing3=10, spacing1=6)
        self.detail_text.tag_configure("remediation", font=self.f_body, foreground=TEXT, lmargin1=10, lmargin2=10, spacing1=6)
        body.add(detail_frame, weight=2)

        status = ttk.Frame(self.root, padding=(16, 8, 16, 12))
        status.grid(row=5, column=0, sticky="ew")
        status.columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="Ready.")
        ttk.Label(
            status, textvariable=self.status_var, style="Muted.TLabel"
        ).grid(row=0, column=0, sticky="w")
        self.progress = ttk.Progressbar(status, mode="indeterminate", length=140)
        self.progress.grid(row=0, column=1, padx=(16, 0))

        self._set_detail_hint(
            "WELCOME TO REPOGUARD\n\nQuick start\n"
            "1. Choose a repository folder with Browse.\n"
            "2. Click Scan Working Tree to inspect files as they exist now.\n"
            "3. In a Git repository, use Scan Staged to inspect staged content.\n"
            "4. Select a finding to read its redacted evidence and suggested fix.\n"
            "5. Search or filter by severity to narrow the results.\n\n"
            "RepoGuard is local and read-only. It never uploads files or changes your repository.\n"
            "Open How to use for the full guide, CLI commands, ignore rules and safety notes."
        )
        self._update_staged_state()

    # -- help and onboarding ---------------------------------------------

    def _show_usage(self) -> None:
        """Show the complete in-app usage and safety guide."""
        window = tk.Toplevel(self.root)
        window.title("How to use RepoGuard")
        window.geometry("760x680")
        window.minsize(560, 420)
        window.transient(self.root)
        window.columnconfigure(0, weight=1)
        window.rowconfigure(1, weight=1)
        ttk.Label(
            window, text="RepoGuard — Quick user guide", style="Title.TLabel",
            padding=(16, 14, 16, 8),
        ).grid(row=0, column=0, sticky="w")
        frame = ttk.Frame(window, padding=(16, 0, 16, 12))
        frame.grid(row=1, column=0, sticky="nsew")
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)
        guide = tk.Text(frame, wrap="word", padx=14, pady=12, relief="flat")
        guide.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(frame, orient="vertical", command=guide.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        guide.configure(yscrollcommand=scroll.set)
        guide.insert("1.0", USAGE_GUIDE)
        guide.configure(state="disabled")
        ttk.Button(window, text="Close", command=window.destroy).grid(
            row=2, column=0, sticky="e", padx=16, pady=(0, 14)
        )
        window.focus_set()

    def _show_about(self) -> None:
        """Show version, privacy and license information."""
        from . import __version__
        messagebox.showinfo(
            "About RepoGuard",
            f"RepoGuard {__version__}\\n\\n"
            "Offline repository hygiene scanner.\\n"
            "Read-only: scans files and staged Git blobs without changing them.\\n"
            "No network, telemetry, uploads or third-party runtime dependencies.\\n\\n"
            "MIT License. See LICENSE for details.\\n"
            "Security is heuristic: a clean scan is not a guarantee.",
            parent=self.root,
        )

    # -- path handling ----------------------------------------------------

    def _browse(self) -> None:
        initial = self.path_var.get() or os.getcwd()
        chosen = filedialog.askdirectory(
            initialdir=initial, title="Choose a repository folder"
        )
        if chosen:
            self.path_var.set(os.path.abspath(chosen))
            self._update_staged_state()

    def _refresh_path(self) -> None:
        self._update_staged_state()

    def _update_staged_state(self) -> None:
        path = self.path_var.get()
        try:
            available = bool(path) and is_git_repo(path)
        except Exception:
            available = False
        if available:
            self.staged_button.configure(state="normal")
            self.staged_hint.configure(text="Staged scan available")
        else:
            self.staged_button.configure(state="disabled")
            self.staged_hint.configure(
                text="Staged scan requires a Git repository at the selected folder"
            )

    # -- scanning ---------------------------------------------------------

    def _scan_working_tree(self) -> None:
        self._start_scan(staged=False)

    def _scan_staged(self) -> None:
        self._start_scan(staged=True)

    def _start_scan(self, staged: bool) -> None:
        if self.controller.is_running():
            return
        path = self.path_var.get()
        if not os.path.isdir(path):
            messagebox.showerror("RepoGuard", "Choose a valid folder first.")
            return
        if staged and not is_git_repo(path):
            messagebox.showerror(
                "RepoGuard",
                "The selected folder is not inside a Git repository.",
            )
            return
        self._set_busy(True)
        self.status_var.set(
            "Scanning staged files…" if staged else "Scanning working tree…"
        )
        self.progress.start(12)
        if not self.controller.start(path, staged=staged):
            self._set_busy(False)
            self.progress.stop()

    def _cancel(self) -> None:
        if self.controller.is_running():
            self.controller.cancel()
            self.status_var.set("Cancelling…")
            self.cancel_button.configure(state="disabled")

    def _poll(self) -> None:
        if self._closing:
            return
        self.controller.poll()
        self.root.after(80, self._poll)

    def _set_busy(self, busy: bool) -> None:
        state = "disabled" if busy else "normal"
        self.scan_button.configure(state=state)
        self.cancel_button.configure(state="normal" if busy else "disabled")
        if not busy:
            self._update_staged_state()
        else:
            self.staged_button.configure(state="disabled")

    # -- result handling --------------------------------------------------

    def _on_result(self, result: ScanResult) -> None:
        self.result = result
        self.selected = None
        self._render_summary(result)
        self._render_table()
        mode = "working tree" if result.mode == "working-tree" else "staged"
        suffix = f" — {len(result.warnings)} warning(s)" if result.warnings else ""
        self.status_var.set(
            f"Scanned {result.root} ({mode}) in {result.duration_s:.2f}s{suffix}"
        )
        self._set_busy(False)
        self.progress.stop()
        if not result.findings:
            self._set_detail_hint(
                "No findings. This repository looks clean for the current checks."
            )

    def _on_error(self, message: str) -> None:
        self._set_busy(False)
        self.progress.stop()
        self.status_var.set("Scan failed.")
        self._set_detail_hint(f"Error: {message}")

    def _on_cancelled(self) -> None:
        self._set_busy(False)
        self.progress.stop()
        self.status_var.set("Scan cancelled.")

    def _on_traceback(self, text: str) -> None:
        self._set_detail_hint(f"Unexpected error:\n{text}")

    def _render_summary(self, result: ScanResult) -> None:
        counts = result.counts
        for key, label in self.card_labels.items():
            label.configure(text=str(counts.get(key, 0)))

    def _render_table(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.filtered = []
        if self.result is None:
            self.count_label.configure(text="0 findings")
            return
        severity = self.severity_var.get().lower()
        needle = self.search_var.get().strip().lower()
        for finding in self.result.findings:
            if severity != "all" and finding.severity != severity:
                continue
            haystack = " ".join(
                [
                    finding.rule_id,
                    finding.severity,
                    finding.path,
                    finding.snippet,
                    finding.fix,
                ]
            ).lower()
            if needle and needle not in haystack:
                continue
            index = len(self.filtered)
            self.filtered.append(finding)
            self.tree.insert(
                "",
                "end",
                iid=str(index),
                values=(
                    finding.severity.upper(),
                    finding.rule_id,
                    finding.path,
                    "" if finding.line is None else finding.line,
                ),
                tags=(finding.severity,),
            )
        total = len(self.result.findings)
        shown = len(self.filtered)
        self.count_label.configure(
            text=f"{shown} of {total} findings"
            if shown != total
            else f"{total} findings"
        )

    def _on_select(self, _event: object = None) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        index = int(selection[0])
        if 0 <= index < len(self.filtered):
            self.selected = self.filtered[index]
            self._show_detail(self.selected)

    def _on_double_click(self, _event: object = None) -> None:
        self._on_select()

    def _show_detail(self, finding: Finding) -> None:
        """Display a finding with rich formatting using text tags."""
        where = finding.path + (
            f":{finding.line}" if finding.line is not None else ""
        )
        why = (
            "This is a high-confidence credential or private-key pattern. "
            "Treat it as exposed, remove it from the repository, and rotate/revoke it."
            if finding.severity == "high"
            else "This heuristic may indicate a credential or repository hygiene risk. "
            "Verify the context before changing anything."
        )
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        
        # Title section
        self.detail_text.insert("end", "Finding Details\n", "section")
        
        # Severity with colored tag
        self.detail_text.insert("end", "Severity:  ", "label")
        self.detail_text.insert("end", f"{finding.severity.upper()}\n", f"severity-{finding.severity}")
        
        # Rule ID
        self.detail_text.insert("end", "Rule:      ", "label")
        self.detail_text.insert("end", f"{finding.rule_id}\n", "value")
        
        # File location
        self.detail_text.insert("end", "File:      ", "label")
        self.detail_text.insert("end", f"{where}\n\n", "value")
        
        # Why this matters
        self.detail_text.insert("end", "Why this matters:\n", "heading")
        self.detail_text.insert("end", f"  {why}\n\n", "value")
        
        # Redacted evidence
        self.detail_text.insert("end", "Redacted evidence:\n", "heading")
        self.detail_text.insert("end", f"  {finding.snippet}\n\n", "monospace")
        
        # Suggested remediation
        self.detail_text.insert("end", "Suggested remediation:\n", "heading")
        self.detail_text.insert("end", f"  {finding.fix}\n\n", "remediation")
        
        # Safety note
        self.detail_text.insert("end", "Safety: ", "label")
        self.detail_text.insert("end", 
            "RepoGuard never displays the detected secret value. "
            "Do not paste credentials into public issues or support requests.", "hint")
        
        self.detail_text.configure(state="disabled")

    def _set_detail_hint(self, text: str) -> None:
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.tag_add("hint", "1.0", "end")
        self.detail_text.configure(state="disabled")

    def _copy_selected(self, attribute: str) -> None:
        if self.selected is None:
            return
        value = getattr(self.selected, attribute)
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(value))
            self.status_var.set(f"Copied {attribute} to clipboard.")
        except tk.TclError as exc:
            self.status_var.set("Could not access the clipboard.")
            messagebox.showerror("Clipboard", str(exc), parent=self.root)

    def _export_json(self) -> None:
        if self.result is None:
            messagebox.showinfo("RepoGuard", "No scan results available to export.", parent=self.root)
            return
        chosen = filedialog.asksaveasfilename(
            initialdir=self.path_var.get() or os.getcwd(),
            title="Export scan results as JSON",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if chosen:
            try:
                export_result_json(self.result, chosen)
                self.status_var.set(f"Exported scan results to {chosen}")
            except Exception as exc:
                messagebox.showerror("Export Error", str(exc), parent=self.root)

    def _on_close(self) -> None:
        self._closing = True
        self.controller.cancel()
        self.root.destroy()


def export_result_json(result: ScanResult, path: str) -> None:
    from .output import format_result_json
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(format_result_json(result))


def run_gui(initial_path: str | None = None) -> int:
    """Launch the GUI. Returns a process exit code."""

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(
            "repoguard: the GUI requires a Tk display. "
            f"({exc}) Use 'repoguard scan' for terminal output.",
            file=sys.stderr,
        )
        return 2

    try:
        app = RepoGuardApp(root)
        if initial_path:
            app.path_var.set(os.path.abspath(initial_path))
            app._update_staged_state()
        root.mainloop()
    finally:
        try:
            root.destroy()
        except tk.TclError:
            pass
    return 0


__all__ = ["RepoGuardApp", "ScanController", "run_gui"]
