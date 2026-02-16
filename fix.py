import argparse
import csv
import io
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Set, Tuple

SYSTEM_DBS = {"mysql", "performance_schema", "phpmyadmin", "sys", "test"}
REQUIRED_SYSTEM_DB_DIRS = {"mysql", "performance_schema", "phpmyadmin"}
MYSQL_TRANSIENT_EXACT = {"aria_log_control", "ibtmp1", "tc.log"}
MYSQL_TRANSIENT_PREFIXES = ("aria_log", "ib_logfile")
MYSQL_CRASH_PATTERNS = (
    "shutdown unexpectedly",
    "innodb: assertion failure",
    "plugin 'innodb' init function returned error",
    "can't start server: bind on tcp/ip port",
    "table is marked as crashed",
    "got error 11 from storage engine",
)

XAMPP_DEFAULT_PATHS = (
    r"C:\xampp",
    r"D:\xampp",
    r"E:\xampp",
)


@dataclass
class PortOwner:
    pid: int
    process_name: str
    raw_line: str


@dataclass
class Context:
    xampp_root: Path
    mysql_dir: Path
    mysql_ini: Path
    mysql_data: Path
    mysql_backup_template: Path
    apache_httpd_conf: Path
    apache_ssl_conf: Path
    phpmyadmin_config: Path
    session_backup_dir: Path
    dry_run: bool


def run(cmd: str, timeout: int = 20) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        shell=True,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def now_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def detect_newline(text: str) -> str:
    return "\r\n" if "\r\n" in text else "\n"


def write_text_preserve_newline(path: Path, new_lines: Sequence[str], had_trailing_newline: bool, newline: str) -> None:
    content = newline.join(new_lines)
    if had_trailing_newline:
        content += newline
    path.write_text(content, encoding="utf-8", errors="ignore")


def ensure_file_backup(src: Path, backup_root: Path, dry_run: bool) -> Path:
    backup_root.mkdir(parents=True, exist_ok=True)
    dst = backup_root / src.name
    if dst.exists():
        dst = backup_root / f"{src.stem}_{now_stamp()}{src.suffix}"
    if not dry_run:
        shutil.copy2(src, dst)
    return dst


def find_xampp_root(user_path: Optional[str]) -> Path:
    candidates: List[Path] = []
    if user_path:
        candidates.append(Path(user_path))

    try:
        import os

        env_raw = os.environ.get("XAMPP_PATH", "")
    except Exception:
        env_raw = ""

    if env_raw:
        candidates.append(Path(env_raw))

    candidates.extend(Path(p) for p in XAMPP_DEFAULT_PATHS)

    for path in candidates:
        if (path / "mysql").exists() and (path / "apache").exists():
            return path

    joined = ", ".join(str(p) for p in candidates)
    raise FileNotFoundError(f"Could not locate XAMPP root. Checked: {joined}")


def parse_mysql_port(mysql_ini: Path, default: int = 3306) -> int:
    if not mysql_ini.exists():
        return default

    section = ""
    for raw in mysql_ini.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if "=" not in line:
            continue

        key, value = [part.strip() for part in line.split("=", 1)]
        if key.lower() == "port" and section == "mysqld" and value.isdigit():
            return int(value)

    return default


def parse_mysql_datadir(mysql_ini: Path, mysql_dir: Path) -> Path:
    fallback = mysql_dir / "data"
    if not mysql_ini.exists():
        return fallback

    section = ""
    for raw in mysql_ini.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if "=" not in line or section != "mysqld":
            continue

        key, value = [part.strip() for part in line.split("=", 1)]
        if key.lower() != "datadir":
            continue

        cleaned = value.strip('"').replace("/", "\\")
        datadir = Path(cleaned)
        if datadir.is_absolute():
            return datadir
        return (mysql_dir / datadir).resolve()

    return fallback


def parse_apache_ports(httpd_conf: Path, ssl_conf: Path) -> Tuple[int, int]:
    http_port = 80
    https_port = 443

    if httpd_conf.exists():
        for raw in httpd_conf.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^Listen\s+(\d+)$", line, re.IGNORECASE)
            if match:
                http_port = int(match.group(1))
                break

    if ssl_conf.exists():
        for raw in ssl_conf.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r"^Listen\s+(\d+)$", line, re.IGNORECASE)
            if match:
                https_port = int(match.group(1))
                break

    return http_port, https_port


def get_process_table() -> Dict[int, str]:
    result = run("tasklist /FO CSV /NH")
    table: Dict[int, str] = {}
    if result.returncode != 0:
        return table

    reader = csv.reader(io.StringIO(result.stdout))
    for row in reader:
        if len(row) < 2:
            continue
        pid_raw = row[1].strip().strip('"')
        if pid_raw.isdigit():
            table[int(pid_raw)] = row[0].strip()

    return table


def extract_port(local_address: str) -> Optional[int]:
    local = local_address.strip()
    if ":" not in local:
        return None

    try:
        if local.startswith("[") and "]:" in local:
            return int(local.rsplit("]:", 1)[1])
        return int(local.rsplit(":", 1)[1])
    except ValueError:
        return None


def get_listening_ports() -> Dict[int, Set[int]]:
    result = run("netstat -ano -p tcp")
    port_map: Dict[int, Set[int]] = {}
    if result.returncode != 0:
        return port_map

    for raw in result.stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 5:
            continue
        state = parts[3].upper()
        if state != "LISTENING":
            continue

        local_addr = parts[1]
        pid_raw = parts[4]
        if not pid_raw.isdigit():
            continue

        port = extract_port(local_addr)
        if port is None:
            continue

        port_map.setdefault(port, set()).add(int(pid_raw))

    return port_map


def owners_for_port(port: int, port_map: Dict[int, Set[int]], process_map: Dict[int, str]) -> List[PortOwner]:
    owners: List[PortOwner] = []
    for pid in sorted(port_map.get(port, set())):
        proc = process_map.get(pid, "Unknown")
        owners.append(PortOwner(pid=pid, process_name=proc, raw_line=f"PID={pid} PROCESS={proc}"))
    return owners


def find_free_port(start: int, used_ports: Dict[int, Set[int]], fallback_max: int = 65000) -> Optional[int]:
    for port in range(start, fallback_max):
        if port not in used_ports:
            return port
    return None


def kill_pid(pid: int) -> Tuple[bool, str]:
    result = run(f"taskkill /PID {pid} /F")
    ok = result.returncode == 0
    output = (result.stdout or "") + (result.stderr or "")
    return ok, output.strip()


def try_mysqladmin_shutdown(mysql_bin_dir: Path, mysql_port: int) -> Tuple[bool, str]:
    mysqladmin = mysql_bin_dir / "mysqladmin.exe"
    if not mysqladmin.exists():
        return False, f"mysqladmin not found: {mysqladmin}"

    attempts = [
        f'"{mysqladmin}" -u root -P {mysql_port} shutdown',
        f'"{mysqladmin}" --protocol=tcp -h 127.0.0.1 -u root -P {mysql_port} shutdown',
    ]

    for cmd in attempts:
        result = run(cmd, timeout=20)
        output = ((result.stdout or "") + (result.stderr or "")).strip()
        if result.returncode == 0:
            return True, output or "mysqladmin shutdown succeeded."

    return False, output or "mysqladmin shutdown failed."


def patch_mysql_port(mysql_ini: Path, old_port: int, new_port: int, ctx: Context, report: List[str]) -> bool:
    if not mysql_ini.exists():
        report.append(f"MySQL config not found: {mysql_ini}")
        return False

    original = mysql_ini.read_text(encoding="utf-8", errors="ignore")
    lines = original.splitlines()
    newline = detect_newline(original)
    trailing_newline = original.endswith("\n") or original.endswith("\r\n")

    changed = False
    section = ""
    for idx, raw in enumerate(lines):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            continue
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue

        match = re.match(r"^(\s*port\s*=\s*)(\d+)(\s*(?:[#;].*)?)$", raw, re.IGNORECASE)
        if not match:
            continue

        if section in {"mysqld", "client"} and int(match.group(2)) == old_port:
            lines[idx] = f"{match.group(1)}{new_port}{match.group(3)}"
            changed = True

    if not changed:
        report.append(f"No [mysqld]/[client] port={old_port} entry found in {mysql_ini}")
        return False

    backup = ensure_file_backup(mysql_ini, ctx.session_backup_dir / "config_backups", ctx.dry_run)
    report.append(f"MySQL config backup: {backup}")

    if ctx.dry_run:
        report.append(f"[Dry-run] Would update MySQL port {old_port} -> {new_port} in {mysql_ini}")
        return True

    write_text_preserve_newline(mysql_ini, lines, trailing_newline, newline)
    report.append(f"Updated MySQL port {old_port} -> {new_port} in {mysql_ini}")
    return True


def patch_phpmyadmin_port(config_file: Path, new_port: int, ctx: Context, report: List[str]) -> bool:
    if not config_file.exists():
        report.append(f"phpMyAdmin config not found: {config_file}")
        return False

    original = config_file.read_text(encoding="utf-8", errors="ignore")
    newline = detect_newline(original)
    updated = original

    explicit_port_pattern = re.compile(
        r"(\$cfg\['Servers'\]\[\$i\]\['port'\]\s*=\s*')\d+(';\s*)",
        re.IGNORECASE,
    )
    if explicit_port_pattern.search(updated):
        updated = explicit_port_pattern.sub(rf"\g<1>{new_port}\g<2>", updated)
    else:
        host_pattern = re.compile(
            r"(\$cfg\['Servers'\]\[\$i\]\['host'\]\s*=.*?;\s*)",
            re.IGNORECASE,
        )
        if host_pattern.search(updated):
            insertion = rf"\1{newline}$cfg['Servers'][$i]['port'] = '{new_port}';{newline}"
            updated = host_pattern.sub(insertion, updated, count=1)
        else:
            report.append("phpMyAdmin host line not found; skipped phpMyAdmin port patch.")
            return False

    if updated == original:
        return False

    backup = ensure_file_backup(config_file, ctx.session_backup_dir / "config_backups", ctx.dry_run)
    report.append(f"phpMyAdmin config backup: {backup}")

    if ctx.dry_run:
        report.append(f"[Dry-run] Would set phpMyAdmin port to {new_port}")
        return True

    config_file.write_text(updated, encoding="utf-8", errors="ignore")
    report.append(f"Updated phpMyAdmin port to {new_port} in {config_file}")
    return True


def patch_apache_ports(
    httpd_conf: Path,
    ssl_conf: Path,
    old_http: int,
    new_http: int,
    old_https: int,
    new_https: int,
    ctx: Context,
    report: List[str],
) -> bool:
    changed_any = False

    if httpd_conf.exists():
        text = httpd_conf.read_text(encoding="utf-8", errors="ignore")
        updated = text
        updated = re.sub(
            rf"(?im)^(\s*Listen\s+){old_http}(\s*)$",
            rf"\g<1>{new_http}\g<2>",
            updated,
        )
        updated = re.sub(
            rf"(?im)^(\s*ServerName\s+[^:\s]+:){old_http}(\s*)$",
            rf"\g<1>{new_http}\g<2>",
            updated,
        )
        if updated != text:
            backup = ensure_file_backup(httpd_conf, ctx.session_backup_dir / "config_backups", ctx.dry_run)
            report.append(f"Apache httpd.conf backup: {backup}")
            if not ctx.dry_run:
                httpd_conf.write_text(updated, encoding="utf-8", errors="ignore")
            report.append(f"Updated Apache HTTP port {old_http} -> {new_http} in {httpd_conf}")
            changed_any = True

    if ssl_conf.exists():
        text = ssl_conf.read_text(encoding="utf-8", errors="ignore")
        updated = text
        updated = re.sub(
            rf"(?im)^(\s*Listen\s+){old_https}(\s*)$",
            rf"\g<1>{new_https}\g<2>",
            updated,
        )
        updated = re.sub(
            rf"(?im)^(\s*<VirtualHost\s+[^:>]+:){old_https}(\s*>)$",
            rf"\g<1>{new_https}\g<2>",
            updated,
        )
        updated = re.sub(
            rf"(?im)^(\s*ServerName\s+[^:\s]+:){old_https}(\s*)$",
            rf"\g<1>{new_https}\g<2>",
            updated,
        )
        if updated != text:
            backup = ensure_file_backup(ssl_conf, ctx.session_backup_dir / "config_backups", ctx.dry_run)
            report.append(f"Apache httpd-ssl.conf backup: {backup}")
            if not ctx.dry_run:
                ssl_conf.write_text(updated, encoding="utf-8", errors="ignore")
            report.append(f"Updated Apache HTTPS port {old_https} -> {new_https} in {ssl_conf}")
            changed_any = True

    if ctx.dry_run and changed_any:
        report.append("[Dry-run] Apache port remap preview complete.")

    return changed_any


def list_user_databases(data_dir: Path) -> List[Path]:
    dbs: List[Path] = []
    if not data_dir.exists():
        return dbs

    for item in data_dir.iterdir():
        if item.is_dir() and item.name not in SYSTEM_DBS and not item.name.startswith("."):
            dbs.append(item)

    return sorted(dbs, key=lambda p: p.name.lower())


def cleanup_mysql_transient_logs(data_dir: Path, dry_run: bool) -> List[str]:
    removed: List[str] = []
    if not data_dir.exists():
        return removed

    for item in data_dir.iterdir():
        if not item.is_file():
            continue
        if item.name in MYSQL_TRANSIENT_EXACT or item.name.startswith(MYSQL_TRANSIENT_PREFIXES):
            if not dry_run:
                try:
                    item.unlink(missing_ok=True)
                except OSError:
                    continue
            removed.append(item.name)

    return sorted(set(removed))


def mysql_data_structure_status(data_dir: Path) -> Tuple[bool, List[str]]:
    missing: List[str] = []
    for name in sorted(REQUIRED_SYSTEM_DB_DIRS):
        if not (data_dir / name).is_dir():
            missing.append(name)
    return len(missing) == 0, missing


def copy_user_dbs(old_data: Path, new_data: Path, dry_run: bool) -> List[str]:
    copied: List[str] = []
    for db_dir in list_user_databases(old_data):
        destination = new_data / db_dir.name
        if destination.exists():
            continue
        copied.append(db_dir.name)
        if not dry_run:
            shutil.copytree(db_dir, destination)

    return copied


def copy_optional_mysql_files(old_data: Path, new_data: Path, dry_run: bool) -> List[str]:
    copied: List[str] = []
    for filename in ("ibdata1",):
        src = old_data / filename
        dst = new_data / filename
        if src.exists():
            copied.append(filename)
            if not dry_run:
                shutil.copy2(src, dst)

    return copied


def choose_recovery_source(mysql_dir: Path, primary_old_data: Path) -> Path:
    candidates: List[Path] = [primary_old_data]
    historical = sorted(
        [p for p in mysql_dir.glob("data_old_*") if p.is_dir() and p != primary_old_data],
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    candidates.extend(historical)

    for candidate in candidates:
        if list_user_databases(candidate):
            return candidate

    for candidate in candidates:
        if (candidate / "mysql").is_dir():
            return candidate

    return primary_old_data


def read_recent_mysql_errors(data_dir: Path, lines: int = 250) -> Tuple[Optional[Path], str]:
    candidates: List[Path] = []
    named = data_dir / "mysql_error.log"
    if named.exists():
        candidates.append(named)

    err_files = sorted(
        data_dir.glob("*.err"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    candidates.extend(err_files)

    for candidate in candidates:
        try:
            content_lines = candidate.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue

        tail = "\n".join(content_lines[-lines:])
        if tail.strip():
            return candidate, tail.lower()

    return None, ""


def detect_mysql_crash_signal(data_dir: Path) -> Tuple[bool, Optional[Path], List[str]]:
    log_file, tail = read_recent_mysql_errors(data_dir)
    if not log_file or not tail:
        return False, None, []

    matches = [pattern for pattern in MYSQL_CRASH_PATTERNS if pattern in tail]
    return bool(matches), log_file, matches


def safe_mysql_data_rebuild(ctx: Context, report: List[str]) -> bool:
    if not ctx.mysql_data.exists():
        report.append(f"MySQL data dir not found: {ctx.mysql_data}")
        return False
    if not ctx.mysql_backup_template.exists():
        report.append(f"MySQL backup template not found: {ctx.mysql_backup_template}")
        return False

    data_old = ctx.mysql_dir / f"data_old_{now_stamp()}"
    report.append(f"MySQL data rebuild start: {ctx.mysql_data} -> {data_old}")

    if ctx.dry_run:
        report.append("[Dry-run] Would rename current data directory.")
        report.append("[Dry-run] Would restore mysql/backup as new data directory.")
        report.append("[Dry-run] Would copy user databases and ibdata1.")
        report.append("[Dry-run] Would remove transient MySQL logs in new data directory.")
        return True

    try:
        shutil.move(str(ctx.mysql_data), str(data_old))
        shutil.copytree(ctx.mysql_backup_template, ctx.mysql_data)
        donor_data = choose_recovery_source(ctx.mysql_dir, data_old)
        copied_dbs = copy_user_dbs(donor_data, ctx.mysql_data, dry_run=False)
        copied_files = copy_optional_mysql_files(donor_data, ctx.mysql_data, dry_run=False)
        removed_logs = cleanup_mysql_transient_logs(ctx.mysql_data, dry_run=False)
    except Exception as exc:
        report.append(f"MySQL data rebuild failed: {exc}")
        return False

    report.append(f"Data backup kept at: {data_old}")
    if donor_data != data_old:
        report.append(f"Recovery source selected from historical backup: {donor_data}")
    report.append(f"Copied DB folders: {copied_dbs if copied_dbs else '(none)'}")
    report.append(f"Copied core files: {copied_files if copied_files else '(none)'}")
    report.append(f"Removed transient logs: {removed_logs if removed_logs else '(none)'}")
    return True


def write_report(ctx: Context, report_lines: Sequence[str]) -> Path:
    ctx.session_backup_dir.mkdir(parents=True, exist_ok=True)
    report_file = ctx.session_backup_dir / "autofix_report.txt"
    report_file.write_text("\n".join(report_lines) + "\n", encoding="utf-8", errors="ignore")
    return report_file


def build_context(xampp_root: Path, dry_run: bool) -> Context:
    mysql_dir = xampp_root / "mysql"
    mysql_ini = mysql_dir / "bin" / "my.ini"
    mysql_data = parse_mysql_datadir(mysql_ini, mysql_dir)
    apache_dir = xampp_root / "apache" / "conf"
    session_backup_dir = xampp_root / "auto_fix_backups" / now_stamp()

    return Context(
        xampp_root=xampp_root,
        mysql_dir=mysql_dir,
        mysql_ini=mysql_ini,
        mysql_data=mysql_data,
        mysql_backup_template=mysql_dir / "backup",
        apache_httpd_conf=apache_dir / "httpd.conf",
        apache_ssl_conf=apache_dir / "extra" / "httpd-ssl.conf",
        phpmyadmin_config=xampp_root / "phpMyAdmin" / "config.inc.php",
        session_backup_dir=session_backup_dir,
        dry_run=dry_run,
    )


def prompt_yes_no(question: str) -> bool:
    try:
        answer = input(f"{question} [y/N]: ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="XAMPP AutoFix (safe-first): diagnose and repair common Apache/MySQL startup problems.",
    )
    parser.add_argument("--xampp-path", help=r"XAMPP installation path, e.g. C:\xampp")
    parser.add_argument("--yes", action="store_true", help="Run without confirmation prompts.")
    parser.add_argument("--dry-run", action="store_true", help="Show planned changes without modifying files.")
    parser.add_argument(
        "--auto-kill",
        action="store_true",
        help="Force-kill processes blocking required ports.",
    )
    parser.add_argument(
        "--no-port-remap",
        action="store_true",
        help="Do not remap config ports if conflicts are detected.",
    )
    parser.add_argument(
        "--mysql-repair-mode",
        choices=("auto", "always", "never"),
        default="auto",
        help="MySQL data rebuild mode: auto (only on crash signals), always, or never.",
    )
    parser.add_argument("--skip-apache", action="store_true", help="Skip Apache checks/fixes.")
    parser.add_argument("--skip-mysql", action="store_true", help="Skip MySQL checks/fixes.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    report: List[str] = []

    try:
        xampp_root = find_xampp_root(args.xampp_path)
    except FileNotFoundError as exc:
        print(f"[Error] {exc}")
        return 1

    ctx = build_context(xampp_root, dry_run=args.dry_run)
    ctx.session_backup_dir.mkdir(parents=True, exist_ok=True)

    print("=== XAMPP AutoFix (Safe-First) ===")
    print(f"XAMPP root: {ctx.xampp_root}")
    print(f"Backup/report folder: {ctx.session_backup_dir}")
    if ctx.dry_run:
        print("Mode: DRY-RUN (no changes will be written)")
    print()

    report.append(f"Timestamp: {datetime.now().isoformat(timespec='seconds')}")
    report.append(f"XAMPP root: {ctx.xampp_root}")
    report.append(f"Dry-run: {ctx.dry_run}")

    process_map = get_process_table()
    port_map = get_listening_ports()

    if not args.skip_mysql:
        mysql_port = parse_mysql_port(ctx.mysql_ini, default=3306)
        print(f"[MySQL] Configured port: {mysql_port}")

        def refresh_mysql_state() -> Tuple[List[PortOwner], bool]:
            nonlocal process_map, port_map, mysql_port
            process_map = get_process_table()
            port_map = get_listening_ports()
            current_owners = owners_for_port(mysql_port, port_map, process_map)
            current_running = any("mysqld" in o.process_name.lower() for o in current_owners)
            return current_owners, current_running

        owners, mysql_running = refresh_mysql_state()

        if owners:
            owner_text = ", ".join(f"{o.process_name}(PID {o.pid})" for o in owners)
            print(f"[MySQL] Port {mysql_port} owners: {owner_text}")
            report.append(f"MySQL port {mysql_port} owners: {owner_text}")
            external_owners = [o for o in owners if "mysqld" not in o.process_name.lower()]

            if external_owners:
                if args.auto_kill:
                    for owner in external_owners:
                        ok, output = kill_pid(owner.pid)
                        result_text = "OK" if ok else "FAILED"
                        print(f"[MySQL] taskkill PID {owner.pid}: {result_text}")
                        report.append(f"MySQL port blocker PID {owner.pid} kill: {result_text}; {output}")
                    owners, mysql_running = refresh_mysql_state()
                elif args.no_port_remap:
                    print("[MySQL] Conflict detected. No auto action because --no-port-remap is active.")
                    report.append("MySQL conflict detected but remap disabled.")
                else:
                    new_port = find_free_port(max(3307, mysql_port + 1), port_map)
                    if new_port is None:
                        print("[MySQL] No free fallback port found for remap.")
                        report.append("MySQL remap failed: no free port found.")
                    else:
                        changed = patch_mysql_port(ctx.mysql_ini, mysql_port, new_port, ctx, report)
                        if changed:
                            patch_phpmyadmin_port(ctx.phpmyadmin_config, new_port, ctx, report)
                            print(f"[MySQL] Port remapped: {mysql_port} -> {new_port}")
                            mysql_port = new_port
                            owners, mysql_running = refresh_mysql_state()
        else:
            print(f"[MySQL] Port {mysql_port} is free.")
            report.append(f"MySQL port {mysql_port} is free.")

        rebuild_needed = False
        rebuild_reason = ""
        crash_signal, log_file, patterns = detect_mysql_crash_signal(ctx.mysql_data)
        structure_ok, missing_system_dirs = mysql_data_structure_status(ctx.mysql_data)

        if not structure_ok:
            missing_text = ", ".join(missing_system_dirs)
            print(f"[MySQL] Warning: data dir missing system folders: {missing_text}")
            report.append(f"MySQL data structure warning: missing system folders -> {missing_text}")

        if args.mysql_repair_mode == "always":
            rebuild_needed = True
            rebuild_reason = "forced by --mysql-repair-mode always"
        elif args.mysql_repair_mode == "auto":
            auto_reasons: List[str] = []
            if crash_signal:
                auto_reasons.append(f"detected crash signals in {log_file}: {patterns}")
            if not structure_ok:
                auto_reasons.append(f"missing system folders in data dir: {missing_system_dirs}")
            if auto_reasons and not mysql_running:
                rebuild_needed = True
                rebuild_reason = "; ".join(auto_reasons)

        if args.mysql_repair_mode == "auto" and mysql_running and (crash_signal or not structure_ok):
            report.append(
                "Crash/data-structure signal detected, but mysqld is running; auto rebuild skipped to avoid live-data changes."
            )

        if rebuild_needed and mysql_running:
            if not ctx.dry_run:
                print("[MySQL] Trying graceful shutdown via mysqladmin before rebuild...")
                ok, output = try_mysqladmin_shutdown(ctx.mysql_dir / "bin", mysql_port)
                print(f"[MySQL] mysqladmin shutdown: {'OK' if ok else 'FAILED'}")
                report.append(f"mysqladmin shutdown before rebuild: {'OK' if ok else 'FAILED'}; {output}")
                if ok:
                    time.sleep(1)
                    owners, mysql_running = refresh_mysql_state()

            if args.auto_kill and not ctx.dry_run:
                print("[MySQL] Trying to stop running mysqld before rebuild...")
                report.append("Trying to stop mysqld before rebuild.")
                for owner in owners:
                    if "mysqld" not in owner.process_name.lower():
                        continue
                    ok, output = kill_pid(owner.pid)
                    print(f"[MySQL] taskkill PID {owner.pid}: {'OK' if ok else 'FAILED'}")
                    report.append(f"Stop mysqld PID {owner.pid}: {'OK' if ok else 'FAILED'}; {output}")
                time.sleep(1)
                owners, mysql_running = refresh_mysql_state()

            if mysql_running:
                print("[MySQL] Rebuild blocked: mysqld is still running on configured port.")
                report.append("MySQL rebuild blocked because mysqld is still running.")
                rebuild_needed = False

        if rebuild_needed:
            print(f"[MySQL] Data rebuild candidate: {rebuild_reason}")
            report.append(f"MySQL data rebuild candidate: {rebuild_reason}")
            can_run = args.yes or ctx.dry_run or prompt_yes_no("Proceed with safe MySQL data rebuild?")
            if can_run:
                ok = safe_mysql_data_rebuild(ctx, report)
                print(f"[MySQL] Data rebuild {'completed' if ok else 'failed'}.")
            else:
                print("[MySQL] Data rebuild skipped by user.")
                report.append("MySQL data rebuild skipped by user.")
        else:
            print("[MySQL] No rebuild required.")
            report.append("MySQL data rebuild not required.")

        if mysql_running and not ctx.dry_run:
            print("[MySQL] Transient log cleanup skipped because mysqld is running.")
            report.append("Skipped transient log cleanup because mysqld is running.")
        else:
            removed_logs = cleanup_mysql_transient_logs(ctx.mysql_data, ctx.dry_run)
            if removed_logs:
                suffix = "Would remove" if ctx.dry_run else "Removed"
                print(f"[MySQL] {suffix} transient logs: {', '.join(removed_logs)}")
                report.append(f"MySQL transient logs cleanup: {removed_logs}")

    if not args.skip_apache:
        http_port, https_port = parse_apache_ports(ctx.apache_httpd_conf, ctx.apache_ssl_conf)
        print(f"[Apache] Configured ports: HTTP {http_port}, HTTPS {https_port}")
        report.append(f"Apache configured ports: HTTP {http_port}, HTTPS {https_port}")

        http_owners = owners_for_port(http_port, port_map, process_map)
        https_owners = owners_for_port(https_port, port_map, process_map)

        external_http = [o for o in http_owners if "httpd" not in o.process_name.lower()]
        external_https = [o for o in https_owners if "httpd" not in o.process_name.lower()]
        has_conflict = bool(external_http or external_https)

        if has_conflict:
            report.append(
                "Apache conflicts: "
                f"HTTP={[(o.pid, o.process_name) for o in external_http]} "
                f"HTTPS={[(o.pid, o.process_name) for o in external_https]}"
            )
            if args.auto_kill:
                for owner in external_http + external_https:
                    ok, output = kill_pid(owner.pid)
                    print(f"[Apache] taskkill PID {owner.pid}: {'OK' if ok else 'FAILED'}")
                    report.append(f"Apache port blocker PID {owner.pid} kill: {'OK' if ok else 'FAILED'}; {output}")
                port_map = get_listening_ports()
            elif args.no_port_remap:
                print("[Apache] Conflict detected. No auto action because --no-port-remap is active.")
                report.append("Apache conflict detected but remap disabled.")
            else:
                new_http = find_free_port(max(http_port + 1, 8080), port_map)
                new_https = find_free_port(max(https_port + 1, 4433), port_map)
                if new_http is None or new_https is None:
                    print("[Apache] No free fallback port found for remap.")
                    report.append("Apache remap failed: no free fallback ports.")
                else:
                    changed = patch_apache_ports(
                        ctx.apache_httpd_conf,
                        ctx.apache_ssl_conf,
                        http_port,
                        new_http,
                        https_port,
                        new_https,
                        ctx,
                        report,
                    )
                    if changed:
                        print(f"[Apache] Ports remapped: HTTP {http_port}->{new_http}, HTTPS {https_port}->{new_https}")
        else:
            print("[Apache] No external port conflicts detected.")
            report.append("Apache ports look clear (no external blockers).")

    report_file = write_report(ctx, report)
    print()
    print(f"Report saved: {report_file}")
    print("Next: Restart XAMPP Control Panel and start Apache/MySQL.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
