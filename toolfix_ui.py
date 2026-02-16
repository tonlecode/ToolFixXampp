import os
import queue
import subprocess
import sys
import threading
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox
import tkinter as tk
from tkinter import ttk

try:
    import fix as fix_core
except Exception:
    fix_core = None


class QueueLogWriter:
    def __init__(self, put_line_callback):
        self.put_line_callback = put_line_callback
        self._buffer = ""

    def write(self, text):
        if not text:
            return
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            self.put_line_callback(line.rstrip("\r"))

    def flush(self):
        if self._buffer:
            self.put_line_callback(self._buffer.rstrip("\r"))
            self._buffer = ""


class ToolFixUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ToolFix XAMPP - Smart One-Click UI")
        self.geometry("1160x760")
        self.minsize(980, 640)

        self.colors = {
            "bg": "#F4F7FB",
            "surface": "#FFFFFF",
            "surface_soft": "#EEF3F8",
            "text": "#0F172A",
            "muted": "#475569",
            "accent": "#0284C7",
            "accent_dark": "#0369A1",
            "danger": "#BE123C",
            "border": "#D8E2EE",
        }

        self.fix_script = Path(__file__).with_name("fix.py")
        self.proc = None
        self.worker_thread = None
        self.stop_requested = threading.Event()
        self.log_queue = queue.Queue()
        self.last_report_path = None

        self.path_var = tk.StringVar(value=self._detect_default_xampp())
        self.status_var = tk.StringVar(value="Ready")

        self._configure_theme()
        self._build_layout()
        self.after(120, self._drain_log_queue)
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_theme(self):
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
            font=("Segoe UI Semibold", 11),
            foreground="#FFFFFF",
            background=self.colors["accent"],
            borderwidth=0,
            focusthickness=0,
            padding=(16, 11),
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
            padding=(12, 9),
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

    def _build_layout(self):
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
            text="One-click smart recovery for Apache/MySQL with safe backups",
            style="Subtitle.TLabel",
        ).grid(row=1, column=0, sticky="w")

        badge = tk.Label(
            header,
            text="AUTO MODE",
            bg="#E0F2FE",
            fg=self.colors["accent_dark"],
            font=("Segoe UI Semibold", 9),
            padx=10,
            pady=4,
        )
        badge.grid(row=0, column=1, rowspan=2, sticky="e")

        settings = ttk.Frame(root, style="Card.TFrame", padding=14)
        settings.grid(row=1, column=0, sticky="ew", pady=(0, 12))
        settings.columnconfigure(1, weight=1)
        settings.columnconfigure(2, weight=0)

        ttk.Label(settings, text="Settings", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            settings,
            text="Set XAMPP path and press one button. ToolFix will diagnose and repair automatically.",
            style="CardBody.TLabel",
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        ttk.Label(settings, text="XAMPP Path", style="CardBody.TLabel").grid(row=2, column=0, sticky="w", pady=(0, 6))
        self.path_entry = tk.Entry(
            settings,
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
        self.path_entry.grid(row=2, column=1, sticky="ew", padx=(8, 8), pady=(0, 6), ipady=6)
        self.browse_button = ttk.Button(settings, text="Browse", style="Ghost.TButton", command=self._browse_path)
        self.browse_button.grid(row=2, column=2, sticky="ew", pady=(0, 6))

        actions = ttk.Frame(root, style="Card.TFrame", padding=14)
        actions.grid(row=2, column=0, sticky="ew", pady=(0, 12))
        actions.columnconfigure(0, weight=3)
        actions.columnconfigure(1, weight=1)

        ttk.Label(actions, text="One-Click Action", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            actions,
            text="Flow: Diagnose -> Safe Repair -> Deep Repair Fallback (if needed) -> Verify",
            style="CardBody.TLabel",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 10))

        self.auto_button = ttk.Button(
            actions,
            text="Auto Fix Everything",
            style="Primary.TButton",
            command=self._start_auto_fix,
        )
        self.auto_button.grid(row=2, column=0, sticky="ew", padx=(0, 8))

        self.stop_button = ttk.Button(actions, text="Stop", style="Danger.TButton", command=self._stop_current_task, state="disabled")
        self.stop_button.grid(row=2, column=1, sticky="ew")

        logs = ttk.Frame(root, style="Card.TFrame", padding=12)
        logs.grid(row=3, column=0, sticky="nsew")
        logs.columnconfigure(0, weight=1)
        logs.rowconfigure(2, weight=1)

        ttk.Label(logs, text="Live Logs", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        tools = ttk.Frame(logs, style="Card.TFrame")
        tools.grid(row=1, column=0, sticky="ew", pady=(4, 8))

        ttk.Button(tools, text="Clear", style="Ghost.TButton", command=self._clear_log).pack(side="left", padx=(0, 6))
        ttk.Button(tools, text="Copy", style="Ghost.TButton", command=self._copy_log).pack(side="left", padx=(0, 6))
        ttk.Button(tools, text="Save Log", style="Ghost.TButton", command=self._save_log).pack(side="left", padx=(0, 6))
        ttk.Button(tools, text="Open Report", style="Ghost.TButton", command=self._open_last_report).pack(side="left", padx=(0, 6))
        ttk.Button(tools, text="Open Backups", style="Ghost.TButton", command=self._open_backup_folder).pack(side="left")

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

        self._append_log("[%s] ToolFix one-click UI ready." % self._now(), "header")
        if not self.fix_script.exists() and not getattr(sys, "frozen", False):
            self._append_log("[%s] fix.py not found next to this file." % self._now(), "error")
            self.status_var.set("Error: fix.py not found")
            self._set_running_state(False, disabled_all=True)
        elif getattr(sys, "frozen", False) and fix_core is None:
            self._append_log("[%s] Embedded repair engine not available in EXE." % self._now(), "error")
            self.status_var.set("Error: embedded repair engine missing")
            self._set_running_state(False, disabled_all=True)

    def _detect_default_xampp(self):
        for path in (Path(r"C:\xampp"), Path(r"D:\xampp"), Path(r"E:\xampp")):
            if (path / "mysql").exists() and (path / "apache").exists():
                return str(path)
        return r"C:\xampp"

    def _browse_path(self):
        selected = filedialog.askdirectory(initialdir=self.path_var.get() or r"C:\\")
        if selected:
            self.path_var.set(selected)

    def _start_auto_fix(self):
        if self.worker_thread is not None and self.worker_thread.is_alive():
            messagebox.showwarning("Task Running", "Auto-fix is already running.", parent=self)
            return
        if not self.fix_script.exists() and not getattr(sys, "frozen", False):
            messagebox.showerror("Missing Script", "Could not find fix.py", parent=self)
            return
        if getattr(sys, "frozen", False) and fix_core is None:
            messagebox.showerror("Repair Engine Missing", "Embedded fix engine is not available in this EXE.", parent=self)
            return

        path_value = self.path_var.get().strip()
        if not path_value:
            messagebox.showwarning("Path Required", "Please set XAMPP path first.", parent=self)
            return

        self.stop_requested.clear()
        self._set_running_state(True)
        self.status_var.set("Auto-fix in progress...")
        self._append_log("", "muted")
        self._append_log("[%s] START: Smart auto-fix workflow" % self._now(), "header")
        self.worker_thread = threading.Thread(target=self._auto_fix_workflow, daemon=True)
        self.worker_thread.start()

    def _auto_fix_workflow(self):
        path_value = self.path_var.get().strip()
        success = False
        summary = "Unknown state."

        try:
            stages = [
                ("Stage 1/4 - Diagnose", ["--yes", "--dry-run", "--mysql-repair-mode", "never"]),
                ("Stage 2/4 - Safe Repair", ["--yes", "--auto-kill", "--mysql-repair-mode", "auto"]),
            ]
            for name, args in stages:
                code = self._run_fix_stage(name, path_value, args)
                if code != 0:
                    summary = "Workflow stopped: %s failed (exit code %s)." % (name, code)
                    self.log_queue.put(("done", False, summary))
                    return
                if self.stop_requested.is_set():
                    summary = "Workflow stopped by user."
                    self.log_queue.put(("done", False, summary))
                    return

            integrity = self._check_mysql_data_integrity(path_value)
            if not integrity["ok"] and not self.stop_requested.is_set():
                missing = integrity["missing"]
                self.log_queue.put(("line", "[%s] Stage 3/4 - Fallback: Deep MySQL Repair (missing: %s)" % (
                    self._now(),
                    ", ".join(missing),
                )))
                code = self._run_fix_stage(
                    "Stage 3/4 - Deep MySQL Repair",
                    path_value,
                    ["--yes", "--auto-kill", "--mysql-repair-mode", "always"],
                )
                if code != 0:
                    summary = "Deep repair failed (exit code %s)." % code
                    self.log_queue.put(("done", False, summary))
                    return

            code = self._run_fix_stage(
                "Stage 4/4 - Final Verification",
                path_value,
                ["--yes", "--dry-run", "--mysql-repair-mode", "never"],
            )
            if code != 0:
                summary = "Final verification failed."
                self.log_queue.put(("done", False, summary))
                return

            if self.stop_requested.is_set():
                summary = "Workflow stopped by user."
                self.log_queue.put(("done", False, summary))
                return

            success = True
            summary = "Auto-fix completed. Open XAMPP Control Panel and start Apache/MySQL."
            self.log_queue.put(("done", success, summary))
        except Exception as exc:
            self.log_queue.put(("line", "[%s] Unexpected error: %s" % (self._now(), exc)))
            self.log_queue.put(("done", False, "Workflow crashed with unexpected error."))

    def _run_fix_stage(self, stage_name, xampp_path, extra_args):
        if getattr(sys, "frozen", False):
            return self._run_fix_stage_embedded(stage_name, xampp_path, extra_args)

        command = [sys.executable, str(self.fix_script), "--xampp-path", xampp_path]
        command.extend(extra_args)

        self.log_queue.put(("line", "[%s] %s" % (self._now(), stage_name)))
        self.log_queue.put(("line", " ".join(command)))

        try:
            self.proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
        except Exception as exc:
            self.log_queue.put(("line", "[%s] Could not start fix.py: %s" % (self._now(), exc)))
            return 1

        if self.proc.stdout is not None:
            for line in self.proc.stdout:
                if self.stop_requested.is_set():
                    break
                self.log_queue.put(("line", line.rstrip("\n")))

        if self.stop_requested.is_set() and self.proc.poll() is None:
            try:
                self.proc.terminate()
            except Exception:
                pass

        code = self.proc.wait()
        self.proc = None
        self.log_queue.put(("line", "[%s] %s finished with exit code %s" % (self._now(), stage_name, code)))
        return code

    def _run_fix_stage_embedded(self, stage_name, xampp_path, extra_args):
        if fix_core is None:
            self.log_queue.put(("line", "[%s] fix.py module import failed in embedded mode." % self._now()))
            return 1

        args = ["fix.py", "--xampp-path", xampp_path]
        args.extend(extra_args)
        self.log_queue.put(("line", "[%s] %s (embedded mode)" % (self._now(), stage_name)))
        self.log_queue.put(("line", " ".join(args)))

        old_argv = list(sys.argv)
        writer = QueueLogWriter(lambda ln: self.log_queue.put(("line", ln)))
        code = 1
        try:
            sys.argv = args
            with redirect_stdout(writer), redirect_stderr(writer):
                result = fix_core.main()
            code = int(result) if isinstance(result, int) else 0
        except Exception as exc:
            self.log_queue.put(("line", "[%s] Embedded stage failed: %s" % (self._now(), exc)))
            code = 1
        finally:
            writer.flush()
            sys.argv = old_argv

        self.log_queue.put(("line", "[%s] %s finished with exit code %s" % (self._now(), stage_name, code)))
        return code

    def _check_mysql_data_integrity(self, xampp_path):
        state = {"ok": True, "missing": []}
        if fix_core is None:
            self.log_queue.put(("line", "[%s] Integrity check warning: fix.py module import failed." % self._now()))
            return state

        try:
            root = fix_core.find_xampp_root(xampp_path)
            ctx = fix_core.build_context(root, dry_run=True)
            ok, missing = fix_core.mysql_data_structure_status(ctx.mysql_data)
            state["ok"] = ok
            state["missing"] = missing
            return state
        except Exception as exc:
            self.log_queue.put(("line", "[%s] Integrity check error: %s" % (self._now(), exc)))
            return state

    def _stop_current_task(self):
        self.stop_requested.set()
        if self.proc is not None and self.proc.poll() is None:
            try:
                self.proc.terminate()
                self._append_log("[%s] Stop requested..." % self._now(), "warn")
            except Exception as exc:
                self._append_log("[%s] Failed to stop process: %s" % (self._now(), exc), "error")
        elif getattr(sys, "frozen", False):
            self._append_log("[%s] Stop requested. Waiting for current embedded stage to finish..." % self._now(), "warn")
        self.status_var.set("Stopping workflow...")

    def _drain_log_queue(self):
        try:
            while True:
                item = self.log_queue.get_nowait()
                kind = item[0]
                if kind == "line":
                    self._consume_process_line(item[1])
                elif kind == "done":
                    self._on_workflow_done(item[1], item[2])
        except queue.Empty:
            pass
        self.after(120, self._drain_log_queue)

    def _consume_process_line(self, line):
        tag = "muted"
        lowered = line.lower()
        if "[error]" in lowered or "failed" in lowered or "unexpected error" in lowered:
            tag = "error"
        elif "warning" in lowered or "conflict" in lowered or "timed out" in lowered:
            tag = "warn"
        elif "completed" in lowered or "saved" in lowered or "running" in lowered:
            tag = "success"
        elif line.startswith("===") or line.startswith("[MySQL]") or line.startswith("[Apache]") or "stage " in lowered:
            tag = "header"

        if line.strip().startswith("Report saved:"):
            report_text = line.split("Report saved:", 1)[1].strip()
            self.last_report_path = Path(report_text)

        self._append_log(line, tag)

    def _on_workflow_done(self, success, summary):
        self.proc = None
        self.worker_thread = None
        self._set_running_state(False)
        self.status_var.set(summary)
        if success:
            self._append_log("[%s] DONE: %s" % (self._now(), summary), "success")
        else:
            self._append_log("[%s] STOPPED: %s" % (self._now(), summary), "error")

    def _set_running_state(self, running, disabled_all=False):
        if disabled_all:
            self.auto_button.configure(state="disabled")
            self.stop_button.configure(state="disabled")
            self.path_entry.configure(state="disabled")
            self.browse_button.configure(state="disabled")
            return

        if running:
            self.auto_button.configure(state="disabled")
            self.stop_button.configure(state="normal")
            self.path_entry.configure(state="disabled")
            self.browse_button.configure(state="disabled")
        else:
            self.auto_button.configure(state="normal")
            self.stop_button.configure(state="disabled")
            self.path_entry.configure(state="normal")
            self.browse_button.configure(state="normal")

    def _append_log(self, message, tag="muted"):
        self.log_text.insert("end", message + "\n", tag)
        self.log_text.see("end")

    def _clear_log(self):
        self.log_text.delete("1.0", "end")
        self._append_log("[%s] Log cleared." % self._now(), "muted")

    def _copy_log(self):
        text = self.log_text.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(text)
        self.status_var.set("Log copied to clipboard")

    def _save_log(self):
        initial_name = "toolfix_log_%s.txt" % datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = filedialog.asksaveasfilename(
            title="Save Log",
            defaultextension=".txt",
            initialfile=initial_name,
            filetypes=[("Text File", "*.txt"), ("All Files", "*.*")],
        )
        if not output_file:
            return
        Path(output_file).write_text(self.log_text.get("1.0", "end-1c"), encoding="utf-8")
        self.status_var.set("Log saved: %s" % output_file)

    def _open_last_report(self):
        if self.last_report_path and self.last_report_path.exists():
            self._open_path(self.last_report_path)
            return
        messagebox.showinfo("No Report", "No report found yet. Run auto-fix first.", parent=self)

    def _open_backup_folder(self):
        path_value = self.path_var.get().strip()
        if not path_value:
            messagebox.showinfo("Path Required", "Set XAMPP path first.", parent=self)
            return
        backup_dir = Path(path_value) / "auto_fix_backups"
        if backup_dir.exists():
            self._open_path(backup_dir)
            return
        messagebox.showinfo("No Backup Folder", "Not found: %s" % backup_dir, parent=self)

    def _open_path(self, path):
        try:
            if sys.platform.startswith("win"):
                os.startfile(str(path))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(path)])
            else:
                subprocess.Popen(["xdg-open", str(path)])
        except Exception as exc:
            messagebox.showerror("Open Failed", "Could not open path:\n%s\n\n%s" % (path, exc), parent=self)

    def _on_close(self):
        if self.worker_thread is not None and self.worker_thread.is_alive():
            if not messagebox.askyesno("Exit", "Auto-fix is still running. Stop and exit?", parent=self):
                return
            self._stop_current_task()
        self.destroy()

    @staticmethod
    def _now():
        return datetime.now().strftime("%H:%M:%S")


def main():
    app = ToolFixUI()
    app.mainloop()


if __name__ == "__main__":
    main()
