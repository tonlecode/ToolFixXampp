import os
import queue
import subprocess
import sys
import threading
from datetime import datetime
from pathlib import Path
from typing import List
from tkinter import filedialog, messagebox
import tkinter as tk
from tkinter import ttk


class ToolFixUI(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("ToolFix XAMPP - Modern UI")
        self.geometry("1180x760")
        self.minsize(980, 640)

        self.colors = {
            "bg": "#F4F7FB",
            "surface": "#FFFFFF",
            "surface_soft": "#EDF2F7",
            "text": "#0F172A",
            "muted": "#475569",
            "accent": "#0284C7",
            "accent_dark": "#0369A1",
            "danger": "#BE123C",
            "warning": "#B45309",
            "success": "#047857",
            "border": "#D8E2EE",
        }

        self.fix_script = Path(__file__).with_name("fix.py")
        self.proc = None
        self.read_thread = None
        self.log_queue = queue.Queue()
        self.last_report_path = None

        self.path_var = tk.StringVar(value=self._detect_default_xampp())
        self.mode_var = tk.StringVar(value="auto")
        self.dry_run_var = tk.BooleanVar(value=True)
        self.auto_kill_var = tk.BooleanVar(value=False)
        self.no_remap_var = tk.BooleanVar(value=False)
        self.skip_apache_var = tk.BooleanVar(value=False)
        self.skip_mysql_var = tk.BooleanVar(value=False)
        self.status_var = tk.StringVar(value="Ready")

        self._configure_theme()
        self._build_layout()
        self.after(120, self._drain_log_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_theme(self) -> None:
        self.configure(bg=self.colors["bg"])
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("Root.TFrame", background=self.colors["bg"])
        style.configure("Card.TFrame", background=self.colors["surface"], relief="flat")
        style.configure("Muted.TLabel", background=self.colors["surface"], foreground=self.colors["muted"])
        style.configure("Title.TLabel", background=self.colors["bg"], foreground=self.colors["text"], font=("Segoe UI Semibold", 18))
        style.configure("Subtitle.TLabel", background=self.colors["bg"], foreground=self.colors["muted"], font=("Segoe UI", 10))
        style.configure("CardTitle.TLabel", background=self.colors["surface"], foreground=self.colors["text"], font=("Segoe UI Semibold", 11))
        style.configure("CardBody.TLabel", background=self.colors["surface"], foreground=self.colors["muted"], font=("Segoe UI", 9))

        style.configure(
            "Primary.TButton",
            font=("Segoe UI Semibold", 10),
            foreground="#FFFFFF",
            background=self.colors["accent"],
            borderwidth=0,
            focusthickness=0,
            padding=(14, 9),
        )
        style.map(
            "Primary.TButton",
            background=[("active", self.colors["accent_dark"]), ("disabled", "#93C5FD")],
        )

        style.configure(
            "Danger.TButton",
            font=("Segoe UI Semibold", 10),
            foreground="#FFFFFF",
            background=self.colors["danger"],
            borderwidth=0,
            focusthickness=0,
            padding=(14, 9),
        )
        style.map(
            "Danger.TButton",
            background=[("active", "#9F1239"), ("disabled", "#FDA4AF")],
        )

        style.configure(
            "Ghost.TButton",
            font=("Segoe UI", 10),
            foreground=self.colors["text"],
            background=self.colors["surface_soft"],
            borderwidth=0,
            focusthickness=0,
            padding=(12, 8),
        )
        style.map(
            "Ghost.TButton",
            background=[("active", "#E2E8F0")],
        )

        style.configure(
            "Switch.TCheckbutton",
            background=self.colors["surface"],
            foreground=self.colors["text"],
            font=("Segoe UI", 9),
        )

        style.configure(
            "ToolFix.TCombobox",
            fieldbackground="#FFFFFF",
            background="#FFFFFF",
            foreground=self.colors["text"],
            borderwidth=1,
            arrowsize=15,
            padding=(6, 4),
        )

    def _build_layout(self) -> None:
        root = ttk.Frame(self, style="Root.TFrame", padding=18)
        root.pack(fill="both", expand=True)
        root.columnconfigure(0, weight=1)
        root.rowconfigure(3, weight=1)

        header = ttk.Frame(root, style="Root.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 12))
        header.columnconfigure(0, weight=1)

        ttk.Label(header, text="ToolFix XAMPP", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            header,
            text="Modern control panel for diagnose, safe repair, and live logs",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w")
        badge = tk.Label(
            header,
            text="SAFE-FIRST",
            bg="#E0F2FE",
            fg=self.colors["accent_dark"],
            font=("Segoe UI Semibold", 9),
            padx=10,
            pady=4,
        )
        badge.grid(row=0, column=1, rowspan=2, sticky="e")

        controls = ttk.Frame(root, style="Card.TFrame", padding=14)
        controls.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        controls.columnconfigure(1, weight=1)
        controls.columnconfigure(3, weight=1)
        self._card_border(controls)

        ttk.Label(controls, text="Settings", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(controls, text="Configure options then run one of the actions.", style="CardBody.TLabel").grid(
            row=1, column=0, columnspan=4, sticky="w", pady=(0, 10)
        )

        ttk.Label(controls, text="XAMPP Path", style="CardBody.TLabel").grid(row=2, column=0, sticky="w", pady=(0, 6))
        path_entry = tk.Entry(
            controls,
            textvariable=self.path_var,
            font=("Segoe UI", 10),
            bg="#FFFFFF",
            fg=self.colors["text"],
            insertbackground=self.colors["text"],
            relief="flat",
            highlightthickness=1,
            highlightbackground=self.colors["border"],
            highlightcolor=self.colors["accent"],
            bd=0,
        )
        path_entry.grid(row=2, column=1, columnspan=2, sticky="ew", padx=(8, 8), pady=(0, 6), ipady=6)
        ttk.Button(controls, text="Browse", style="Ghost.TButton", command=self._browse_path).grid(
            row=2, column=3, sticky="ew", pady=(0, 6)
        )

        ttk.Label(controls, text="MySQL Repair Mode", style="CardBody.TLabel").grid(row=3, column=0, sticky="w")
        repair_combo = ttk.Combobox(
            controls,
            style="ToolFix.TCombobox",
            textvariable=self.mode_var,
            values=("auto", "always", "never"),
            state="readonly",
            width=18,
        )
        repair_combo.grid(row=3, column=1, sticky="w", padx=(8, 12), pady=(2, 8))

        toggles = ttk.Frame(controls, style="Card.TFrame")
        toggles.grid(row=4, column=0, columnspan=4, sticky="ew", pady=(0, 4))
        for idx in range(3):
            toggles.columnconfigure(idx, weight=1)

        ttk.Checkbutton(toggles, text="Dry Run", variable=self.dry_run_var, style="Switch.TCheckbutton").grid(
            row=0, column=0, sticky="w", pady=2
        )
        ttk.Checkbutton(toggles, text="Auto Kill Port Blockers", variable=self.auto_kill_var, style="Switch.TCheckbutton").grid(
            row=0, column=1, sticky="w", pady=2
        )
        ttk.Checkbutton(toggles, text="Disable Port Remap", variable=self.no_remap_var, style="Switch.TCheckbutton").grid(
            row=0, column=2, sticky="w", pady=2
        )
        ttk.Checkbutton(toggles, text="Skip Apache", variable=self.skip_apache_var, style="Switch.TCheckbutton").grid(
            row=1, column=0, sticky="w", pady=2
        )
        ttk.Checkbutton(toggles, text="Skip MySQL", variable=self.skip_mysql_var, style="Switch.TCheckbutton").grid(
            row=1, column=1, sticky="w", pady=2
        )

        actions = ttk.Frame(root, style="Card.TFrame", padding=14)
        actions.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        actions.columnconfigure(0, weight=1)
        actions.columnconfigure(1, weight=1)
        actions.columnconfigure(2, weight=1)
        actions.columnconfigure(3, weight=1)
        actions.columnconfigure(4, weight=1)
        self._card_border(actions)

        ttk.Label(actions, text="Actions", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(actions, text="Recommended flow: Diagnose -> Safe Repair -> Deep Repair (only if needed)", style="CardBody.TLabel").grid(
            row=1, column=0, columnspan=5, sticky="w", pady=(0, 10)
        )

        self.quick_button = ttk.Button(actions, text="Quick Diagnose", style="Primary.TButton", command=self._run_quick_diagnose)
        self.quick_button.grid(row=2, column=0, sticky="ew", padx=(0, 8))
        self.safe_button = ttk.Button(actions, text="Safe Repair", style="Primary.TButton", command=self._run_safe_repair)
        self.safe_button.grid(row=2, column=1, sticky="ew", padx=(0, 8))
        self.deep_button = ttk.Button(actions, text="Deep Repair", style="Danger.TButton", command=self._run_deep_repair)
        self.deep_button.grid(row=2, column=2, sticky="ew", padx=(0, 8))
        self.custom_button = ttk.Button(actions, text="Run Custom", style="Ghost.TButton", command=self._run_custom)
        self.custom_button.grid(row=2, column=3, sticky="ew", padx=(0, 8))
        self.stop_button = ttk.Button(actions, text="Stop", style="Ghost.TButton", command=self._stop_current_task, state="disabled")
        self.stop_button.grid(row=2, column=4, sticky="ew")

        logs = ttk.Frame(root, style="Card.TFrame", padding=12)
        logs.grid(row=3, column=0, sticky="nsew")
        logs.columnconfigure(0, weight=1)
        logs.rowconfigure(2, weight=1)
        self._card_border(logs)

        ttk.Label(logs, text="Live Logs", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        tools = ttk.Frame(logs, style="Card.TFrame")
        tools.grid(row=1, column=0, sticky="ew", pady=(4, 8))
        tools.columnconfigure(5, weight=1)

        ttk.Button(tools, text="Clear", style="Ghost.TButton", command=self._clear_log).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(tools, text="Copy", style="Ghost.TButton", command=self._copy_log).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(tools, text="Save Log", style="Ghost.TButton", command=self._save_log).grid(row=0, column=2, padx=(0, 6))
        ttk.Button(tools, text="Open Report", style="Ghost.TButton", command=self._open_last_report).grid(row=0, column=3, padx=(0, 6))
        ttk.Button(tools, text="Open Backups", style="Ghost.TButton", command=self._open_backup_folder).grid(row=0, column=4)

        log_wrap = tk.Frame(logs, bg=self.colors["surface"])
        log_wrap.grid(row=2, column=0, sticky="nsew")
        log_wrap.rowconfigure(0, weight=1)
        log_wrap.columnconfigure(0, weight=1)

        self.log_text = tk.Text(
            log_wrap,
            wrap="word",
            bg="#0B1220",
            fg="#DCE5F1",
            insertbackground="#DCE5F1",
            font=("Cascadia Code", 10),
            relief="flat",
            padx=10,
            pady=10,
            spacing1=1,
            spacing2=1,
        )
        self.log_text.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(log_wrap, orient="vertical", command=self.log_text.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=yscroll.set)

        self.log_text.tag_configure("header", foreground="#7DD3FC")
        self.log_text.tag_configure("warn", foreground="#FDBA74")
        self.log_text.tag_configure("error", foreground="#FDA4AF")
        self.log_text.tag_configure("success", foreground="#6EE7B7")
        self.log_text.tag_configure("muted", foreground="#94A3B8")

        status_bar = tk.Frame(root, bg="#E2E8F0", height=30)
        status_bar.grid(row=4, column=0, sticky="ew", pady=(10, 0))
        status_bar.grid_propagate(False)
        tk.Label(
            status_bar,
            textvariable=self.status_var,
            bg="#E2E8F0",
            fg=self.colors["muted"],
            font=("Segoe UI", 9),
            anchor="w",
            padx=10,
        ).pack(fill="both", expand=True)

        self._append_log(f"[{self._now()}] ToolFix UI ready.", "header")
        if not self.fix_script.exists():
            self._append_log(f"[{self._now()}] fix.py not found next to this file.", "error")
            self.status_var.set("Error: fix.py not found")
            self._set_buttons_enabled(False)

    def _card_border(self, frame: ttk.Frame) -> None:
        frame.configure(style="Card.TFrame")
        frame.update_idletasks()

    def _detect_default_xampp(self) -> str:
        for path in (Path(r"C:\xampp"), Path(r"D:\xampp"), Path(r"E:\xampp")):
            if (path / "mysql").exists() and (path / "apache").exists():
                return str(path)
        return r"C:\xampp"

    def _browse_path(self) -> None:
        selected = filedialog.askdirectory(initialdir=self.path_var.get() or r"C:\\")
        if selected:
            self.path_var.set(selected)

    def _run_quick_diagnose(self) -> None:
        args = ["--yes", "--dry-run", "--mysql-repair-mode", "never"]
        self._run_process(args, "Quick Diagnose")

    def _run_safe_repair(self) -> None:
        args = ["--yes", "--mysql-repair-mode", "auto"]
        self._run_process(args, "Safe Repair")

    def _run_deep_repair(self) -> None:
        if not messagebox.askyesno(
            "Deep Repair",
            "Deep Repair may rebuild MySQL data folder structure.\nBackups are kept automatically.\nContinue?",
            parent=self,
        ):
            return
        args = ["--yes", "--mysql-repair-mode", "always"]
        self._run_process(args, "Deep Repair")

    def _run_custom(self) -> None:
        args = ["--yes"]
        if self.dry_run_var.get():
            args.append("--dry-run")
        if self.auto_kill_var.get():
            args.append("--auto-kill")
        if self.no_remap_var.get():
            args.append("--no-port-remap")
        if self.skip_apache_var.get():
            args.append("--skip-apache")
        if self.skip_mysql_var.get():
            args.append("--skip-mysql")
        args.extend(["--mysql-repair-mode", self.mode_var.get()])
        self._run_process(args, "Custom Run")

    def _run_process(self, extra_args: List[str], mode_name: str) -> None:
        if self.proc is not None and self.proc.poll() is None:
            messagebox.showwarning("Task Running", "Another task is already running.", parent=self)
            return
        if not self.fix_script.exists():
            messagebox.showerror("Missing Script", f"Could not find: {self.fix_script}", parent=self)
            return

        command = [sys.executable, str(self.fix_script)]
        path_value = self.path_var.get().strip()
        if path_value:
            command.extend(["--xampp-path", path_value])
        command.extend(extra_args)

        self._append_log("", "muted")
        self._append_log(f"[{self._now()}] Running {mode_name}", "header")
        self._append_log(" ".join(command), "muted")

        self._set_running_state(True)
        self.status_var.set(f"{mode_name} in progress...")

        self.proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
        )
        self.read_thread = threading.Thread(target=self._read_stdout, daemon=True)
        self.read_thread.start()

    def _read_stdout(self) -> None:
        if self.proc is None or self.proc.stdout is None:
            return
        try:
            for line in self.proc.stdout:
                self.log_queue.put(("line", line.rstrip("\n")))
        finally:
            returncode = self.proc.wait()
            self.log_queue.put(("done", str(returncode)))

    def _drain_log_queue(self) -> None:
        try:
            while True:
                kind, value = self.log_queue.get_nowait()
                if kind == "line":
                    self._consume_process_line(value)
                elif kind == "done":
                    code = int(value)
                    self._on_process_done(code)
        except queue.Empty:
            pass
        self.after(120, self._drain_log_queue)

    def _consume_process_line(self, line: str) -> None:
        tag = "muted"
        lowered = line.lower()
        if "[error]" in lowered or "failed" in lowered:
            tag = "error"
        elif "warning" in lowered or "conflict" in lowered:
            tag = "warn"
        elif "completed" in lowered or "saved" in lowered or "free." in lowered:
            tag = "success"
        elif line.startswith("===") or line.startswith("[MySQL]") or line.startswith("[Apache]"):
            tag = "header"

        if line.strip().startswith("Report saved:"):
            report_text = line.split("Report saved:", 1)[1].strip()
            self.last_report_path = Path(report_text)

        self._append_log(line, tag)

    def _on_process_done(self, returncode: int) -> None:
        if returncode == 0:
            self.status_var.set("Completed successfully")
            self._append_log(f"[{self._now()}] Task completed.", "success")
        else:
            self.status_var.set(f"Exited with code {returncode}")
            self._append_log(f"[{self._now()}] Task failed with exit code {returncode}.", "error")

        self._set_running_state(False)
        self.proc = None
        self.read_thread = None

    def _stop_current_task(self) -> None:
        if self.proc is None or self.proc.poll() is not None:
            return
        try:
            self.proc.terminate()
            self._append_log(f"[{self._now()}] Stop requested...", "warn")
            self.status_var.set("Stopping task...")
        except Exception as exc:
            self._append_log(f"[{self._now()}] Failed to stop process: {exc}", "error")

    def _set_running_state(self, running: bool) -> None:
        run_state = "disabled" if running else "normal"
        stop_state = "normal" if running else "disabled"
        self.quick_button.configure(state=run_state)
        self.safe_button.configure(state=run_state)
        self.deep_button.configure(state=run_state)
        self.custom_button.configure(state=run_state)
        self.stop_button.configure(state=stop_state)

    def _set_buttons_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        self.quick_button.configure(state=state)
        self.safe_button.configure(state=state)
        self.deep_button.configure(state=state)
        self.custom_button.configure(state=state)
        self.stop_button.configure(state="disabled")

    def _append_log(self, message: str, tag: str = "muted") -> None:
        self.log_text.insert("end", message + "\n", tag)
        self.log_text.see("end")

    def _clear_log(self) -> None:
        self.log_text.delete("1.0", "end")
        self._append_log(f"[{self._now()}] Log cleared.", "muted")

    def _copy_log(self) -> None:
        text = self.log_text.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_var.set("Log copied to clipboard")

    def _save_log(self) -> None:
        initial_name = f"toolfix_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        output_file = filedialog.asksaveasfilename(
            title="Save Log",
            defaultextension=".txt",
            initialfile=initial_name,
            filetypes=[("Text File", "*.txt"), ("All Files", "*.*")],
        )
        if not output_file:
            return
        Path(output_file).write_text(self.log_text.get("1.0", "end-1c"), encoding="utf-8")
        self.status_var.set(f"Log saved: {output_file}")

    def _open_last_report(self) -> None:
        if self.last_report_path and self.last_report_path.exists():
            self._open_path(self.last_report_path)
            return
        messagebox.showinfo("No Report", "No report found yet. Run a task first.", parent=self)

    def _open_backup_folder(self) -> None:
        path_value = self.path_var.get().strip()
        if not path_value:
            messagebox.showinfo("Path Required", "Set XAMPP path first.", parent=self)
            return
        backup_dir = Path(path_value) / "auto_fix_backups"
        if backup_dir.exists():
            self._open_path(backup_dir)
            return
        messagebox.showinfo("No Backup Folder", f"Not found: {backup_dir}", parent=self)

    def _open_path(self, path: Path) -> None:
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(path))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror("Open Failed", f"Could not open path:\n{path}\n\n{exc}", parent=self)

    def _on_close(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            if not messagebox.askyesno("Exit", "A task is still running. Stop and exit?", parent=self):
                return
            self._stop_current_task()
        self.destroy()

    @staticmethod
    def _now() -> str:
        return datetime.now().strftime("%H:%M:%S")


def main() -> None:
    app = ToolFixUI()
    app.mainloop()


if __name__ == "__main__":
    main()
