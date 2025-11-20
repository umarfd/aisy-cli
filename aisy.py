#!/usr/bin/env python3
"""
aisy-cli
--------
Utility CLI to manage Linux users, firewall rules, storage, and more.
Most commands wrap native Linux binaries (useradd, ufw, iptables, df, etc.)
so they require root privileges to succeed.
"""

from __future__ import annotations

import argparse
import curses
import grp
import io
import json
import os
import platform
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import redirect_stderr, redirect_stdout, suppress
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


def run_command(
    command: List[str],
    check: bool = True,
    capture_output: bool = False,
) -> subprocess.CompletedProcess:
    """Run a shell command and raise a helpful error if it fails."""
    result = subprocess.run(
        command,
        check=False,
        capture_output=capture_output,
        text=True,
    )
    if check and result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(
            f"Command {' '.join(command)} failed with code {result.returncode}: {stderr}"
        )
    return result


def format_table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for idx, value in enumerate(row):
            widths[idx] = max(widths[idx], len(value))

    def fmt(values: list[str]) -> str:
        return " │ ".join(value.ljust(widths[idx]) for idx, value in enumerate(values))

    line = "─┼─".join("─" * width for width in widths)
    output = [fmt(headers), line]
    output.extend(fmt(row) for row in rows)
    return "\n".join(output)


def usage_bar(pct: float, width: int = 20) -> str:
    pct = max(0.0, min(pct, 100.0))
    filled = int(width * pct / 100)
    bar = "#" * filled + "-" * (width - filled)
    return f"[{bar}]"


def collect_group_memberships() -> Dict[str, List[str]]:
    memberships: Dict[str, List[str]] = {}
    for entry in grp.getgrall():
        for member in entry.gr_mem:
            memberships.setdefault(member, []).append(entry.gr_name)
    return memberships


def primary_group_name(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def read_passwd_entries() -> List[Dict[str, str]]:
    passwd_path = Path("/etc/passwd")
    if not passwd_path.exists():
        raise FileNotFoundError("/etc/passwd not found")

    entries: List[Dict[str, str]] = []
    for line in passwd_path.read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        username, password_placeholder, uid, gid, comment, home, shell = parts[:7]
        entries.append(
            {
                "username": username,
                "password": password_placeholder,
                "uid": uid,
                "gid": gid,
                "comment": comment,
                "home": home,
                "shell": shell,
            }
        )
    return entries


def read_shadow_lock_status() -> Dict[str, bool]:
    shadow_path = Path("/etc/shadow")
    if not shadow_path.exists():
        return {}
    try:
        lines = shadow_path.read_text().splitlines()
    except (PermissionError, OSError):
        return {}
    statuses: Dict[str, bool] = {}
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 2:
            continue
        username, password = parts[0], parts[1]
        locked = False
        if password in {"!", "!!", "*", "*!"}:
            locked = True
        elif password.startswith("!") or password.startswith("*"):
            locked = True
        statuses[username] = locked
    return statuses


def list_users(_: argparse.Namespace) -> None:
    entries = read_passwd_entries()
    memberships = collect_group_memberships()
    rows = []
    for entry in entries:
        username = entry["username"]
        uid = entry["uid"]
        gid = entry["gid"]
        home = entry["home"]
        shell = entry["shell"]
        gid_int = int(gid)
        primary_group = primary_group_name(gid_int)
        user_groups = sorted(set([primary_group] + memberships.get(username, [])))
        home_path = Path(home)
        user_perm = group_perm = "-"
        if home_path.exists():
            try:
                mode = home_path.stat().st_mode
                perm = stat.filemode(mode)
                user_perm = perm[1:4]
                group_perm = perm[4:7]
            except OSError:
                pass
        rows.append(
            [
                username,
                uid,
                primary_group,
                ",".join(user_groups) if user_groups else "-",
                home,
                user_perm,
                group_perm,
                shell,
            ]
        )

    if not rows:
        print("No users found.")
        return

    headers = ["Username", "UID", "Primary Group", "Groups", "Home", "User Perm", "Group Perm", "Shell"]
    print(format_table(headers, rows))


def get_user_stats() -> Dict[str, int]:
    entries = read_passwd_entries()
    total = len(entries)
    regular = sum(1 for entry in entries if int(entry["uid"]) >= 1000)
    system_users = total - regular
    login_shells = sum(
        1
        for entry in entries
        if entry["shell"] not in {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false"}
    )
    home_missing = sum(1 for entry in entries if not Path(entry["home"]).exists())
    return {
        "total": total,
        "regular": regular,
        "system": system_users,
        "login_shells": login_shells,
        "home_missing": home_missing,
    }


def format_duration(seconds: float) -> str:
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, _ = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes or not parts:
        parts.append(f"{minutes}m")
    return " ".join(parts)


def get_system_info() -> Dict[str, str]:
    hostname = platform.node() or "unknown"
    kernel = platform.release()
    now = datetime.now().strftime("%Y-%m-%d %H:%M")
    uptime = "unknown"
    try:
        uptime_raw = Path("/proc/uptime").read_text().split()[0]
        uptime = format_duration(float(uptime_raw))
    except (OSError, ValueError, IndexError):
        pass
    return {
        "hostname": hostname,
        "kernel": kernel,
        "time": now,
        "uptime": uptime,
    }


def get_memory_summary() -> Dict[str, float]:
    meminfo = Path("/proc/meminfo")
    total = available = None
    if meminfo.exists():
        for line in meminfo.read_text().splitlines():
            if line.startswith("MemTotal"):
                total = int(line.split()[1]) / 1024 ** 2
            elif line.startswith("MemAvailable"):
                available = int(line.split()[1]) / 1024 ** 2
            if total is not None and available is not None:
                break
    if total is None or available is None:
        return {"total": 0.0, "available": 0.0, "used": 0.0, "used_pct": 0.0}
    used = max(total - available, 0)
    used_pct = (used / total * 100) if total else 0
    return {
        "total": total,
        "available": available,
        "used": used,
        "used_pct": used_pct,
    }


def get_storage_overview(path: str = "/") -> Dict[str, float]:
    usage = shutil.disk_usage(path)
    total_gb = usage.total / (1024 ** 3)
    used_gb = usage.used / (1024 ** 3)
    free_gb = usage.free / (1024 ** 3)
    used_pct = (usage.used / usage.total * 100) if usage.total else 0
    return {
        "path": path,
        "total_gb": total_gb,
        "used_gb": used_gb,
        "free_gb": free_gb,
        "used_pct": used_pct,
    }


def get_firewall_summary() -> Tuple[str, str]:
    if ufw_available():
        result = run_command(["ufw", "status"], check=False, capture_output=True)
        text = result.stdout.strip() or result.stderr.strip()
        first_line = text.splitlines()[0] if text else "No data"
        return "ufw", first_line
    ensure_command("iptables")
    result = run_command(["iptables", "-L"], check=False, capture_output=True)
    text = result.stdout.strip() or result.stderr.strip()
    first_line = text.splitlines()[0] if text else "No rules reported"
    return "iptables", first_line


def gather_dashboard_data() -> Dict[str, Any]:
    try:
        system = get_system_info()
    except Exception:
        system = {"hostname": "unknown", "kernel": "-", "time": "-", "uptime": "-"}

    try:
        users = get_user_stats()
    except Exception:
        users = {"total": 0, "regular": 0, "system": 0, "login_shells": 0, "home_missing": 0}

    try:
        storage = get_storage_overview("/")
    except Exception:
        storage = {"path": "/", "total_gb": 0, "used_gb": 0, "free_gb": 0, "used_pct": 0}

    try:
        memory = get_memory_summary()
    except Exception:
        memory = {"total": 0, "available": 0, "used": 0, "used_pct": 0}

    try:
        firewall_backend, firewall_status_line = get_firewall_summary()
    except Exception as exc:
        firewall_backend, firewall_status_line = "unknown", f"Unavailable ({exc})"

    try:
        ftp_users = len(ftp_read_userlist())
    except Exception:
        ftp_users = 0

    ftp_state = get_service_state("vsftpd")

    return {
        "system": system,
        "users": users,
        "storage": storage,
        "firewall_backend": firewall_backend,
        "firewall_status": firewall_status_line,
        "memory": memory,
        "ftp_users": ftp_users,
        "ftp_state": ftp_state,
    }


def add_user(args: argparse.Namespace) -> None:
    command = [
        "useradd",
        "-m",
        "-s",
        args.shell,
    ]
    if args.home:
        command.extend(["-d", args.home])
    if args.system:
        command.append("-r")
    command.append(args.username)
    run_command(command)

    if args.password:
        # usermod --password expects a hash; chpasswd works with plaintext.
        subprocess.run(
            ["chpasswd"],
            input=f"{args.username}:{args.password}",
            text=True,
            check=True,
        )
    print(f"User {args.username} created.")
    if args.sudo:
        subprocess.run(["usermod", "-aG", "sudo", args.username], check=True)
        print(f"User {args.username} added to sudo group.")


def delete_user(args: argparse.Namespace) -> None:
    command = ["userdel"]
    if args.remove_home:
        command.append("-r")
    command.append(args.username)
    run_command(command)
    print(f"User {args.username} deleted.")


def lock_unlock_user(args: argparse.Namespace) -> None:
    action = "-L" if args.action == "lock" else "-U"
    run_command(["usermod", action, args.username])
    print(f"User {args.username} {args.action}ed.")


def change_password(args: argparse.Namespace) -> None:
    subprocess.run(
        ["chpasswd"],
        input=f"{args.username}:{args.password}",
        text=True,
        check=True,
    )
    print(f"Password for {args.username} updated.")


def configure_ssh_port(args: argparse.Namespace) -> None:
    sshd_config = Path("/etc/ssh/sshd_config")
    if not sshd_config.exists():
        raise FileNotFoundError("/etc/ssh/sshd_config not found")
    data = sshd_config.read_text().splitlines()
    new_lines = []
    found = False
    for line in data:
        stripped = line.strip()
        if stripped.startswith("Port ") or stripped.lower().startswith("port\t"):
            if not found:
                new_lines.append(f"Port {args.port}")
                found = True
            else:
                continue
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"Port {args.port}")
    sshd_config.write_text("\n".join(new_lines) + "\n")
    run_command(["systemctl", "daemon-reload"])
    if shutil.which("systemctl"):
        socket_result = subprocess.run(
            ["systemctl", "is-enabled", "ssh.socket"],
            capture_output=True,
            text=True,
        )
        if socket_result.returncode == 0 and "enabled" in socket_result.stdout:
            run_command(["systemctl", "restart", "ssh.socket"])
        else:
            run_command(["systemctl", "restart", "ssh"])
    print(f"SSH port updated to {args.port}.")


def package_list_updates(_: argparse.Namespace) -> None:
    packages = pending_upgrade_packages()
    if not packages:
        print("All packages up to date.")
        return
    print("Packages with updates available:\n")
    for line in packages:
        print(line)


def package_install(args: argparse.Namespace) -> None:
    ensure_command("apt-get")
    run_command(["apt-get", "update"])
    run_command(["apt-get", "install", "-y", args.package])
    print(f"Package {args.package} installed.")


def package_remove(args: argparse.Namespace) -> None:
    ensure_command("apt-get")
    run_command(["apt-get", "remove", "-y", args.package])
    print(f"Package {args.package} removed.")


def package_search(args: argparse.Namespace) -> None:
    ensure_command("apt-cache")
    result = run_command(
        ["apt-cache", "search", args.term],
        capture_output=True,
        check=False,
    )
    print(result.stdout.strip() or "No packages found.")


def package_upgrade_all(_: argparse.Namespace) -> None:
    ensure_command("apt-get")
    run_command(["apt-get", "update"])
    run_command(["apt-get", "upgrade", "-y"])
    print("System packages updated to the latest versions.")


def package_upgrade_selected(args: argparse.Namespace) -> None:
    ensure_command("apt-get")
    if not args.packages:
        print("No packages selected.")
        return
    run_command(["apt-get", "update"])
    run_command(["apt-get", "install", "-y", "--only-upgrade", *args.packages])
    print(f"Upgraded: {', '.join(args.packages)}")


def pending_upgrade_packages() -> List[str]:
    ensure_command("apt-get")
    result = run_command(["apt-get", "-s", "upgrade"], capture_output=True, check=False)
    lines = []
    for line in result.stdout.splitlines():
        if line.startswith("Inst "):
            lines.append(line)
    return lines


def monitoring_system_load(_: argparse.Namespace) -> None:
    outputs = []
    for cmd in (["uptime"], ["free", "-h"]):
        try:
            res = run_command(cmd, capture_output=True, check=False)
            outputs.append(res.stdout.strip())
        except Exception as exc:
            outputs.append(f"{' '.join(cmd)} failed: {exc}")
    print("\n\n".join(filter(None, outputs)))


def monitoring_top_processes(_: argparse.Namespace) -> None:
    ensure_command("ps")
    result = run_command(
        ["ps", "-eo", "pid,comm,%cpu,%mem", "--sort=-%cpu"],
        capture_output=True,
        check=False,
    )
    lines = result.stdout.strip().splitlines()[:11]
    print("\n".join(lines))


def monitoring_disk_io(_: argparse.Namespace) -> None:
    if shutil.which("iostat"):
        result = run_command(["iostat", "-xz", "1", "2"], capture_output=True, check=False)
        print(result.stdout.strip())
    else:
        result = run_command(["vmstat", "-d"], capture_output=True, check=False)
        print(result.stdout.strip())


def read_cpu_times() -> Tuple[int, int]:
    stat_file = Path("/proc/stat")
    if not stat_file.exists():
        return 0, 0
    for line in stat_file.read_text().splitlines():
        if line.startswith("cpu "):
            parts = line.split()
            values = list(map(int, parts[1:] ))
            idle = values[3] + values[4]
            total = sum(values)
            return idle, total
    return 0, 0


def read_cpu_core_snapshot() -> Dict[str, Tuple[int, int]]:
    snapshot: Dict[str, Tuple[int, int]] = {}
    stat_file = Path("/proc/stat")
    if not stat_file.exists():
        return snapshot
    for line in stat_file.read_text().splitlines():
        if not line.startswith("cpu"):
            continue
        parts = line.split()
        name = parts[0]
        if not name.startswith("cpu"):
            continue
        values = list(map(int, parts[1:]))
        idle = values[3] + values[4]
        total = sum(values)
        snapshot[name] = (idle, total)
    return snapshot


def compute_cpu_usage_percent(
    current: Dict[str, Tuple[int, int]],
    previous: Dict[str, Tuple[int, int]],
) -> Dict[str, float]:
    usage: Dict[str, float] = {}
    for name, (idle, total) in current.items():
        prev = previous.get(name)
        if prev is None:
            usage[name] = 0.0
            continue
        idle_delta = idle - prev[0]
        total_delta = total - prev[1]
        pct = 0.0
        if total_delta > 0:
            pct = max(0.0, min(100.0, 100 * (1 - idle_delta / total_delta)))
        usage[name] = pct
    return usage


def read_mem_stats() -> Tuple[float, float, float]:
    info = get_memory_summary()
    return info["total"], info["used"], info["used_pct"]


def read_disk_stats() -> Dict[str, float]:
    return get_storage_overview("/")


def read_network_stats() -> Dict[str, float]:
    net_dev = Path("/proc/net/dev")
    stats = {
        "received_mb": 0.0,
        "transmit_mb": 0.0,
    }
    if net_dev.exists():
        for line in net_dev.read_text().splitlines()[2:]:
            parts = line.split()
            if len(parts) >= 17:
                stats["received_mb"] += int(parts[1]) / (1024 ** 2)
                stats["transmit_mb"] += int(parts[9]) / (1024 ** 2)
    return stats


def read_process_table(limit: int = 10) -> List[str]:
    rows = []
    for pid in sorted(Path("/proc").iterdir()):
        if not pid.is_dir() or not pid.name.isdigit():
            continue
        stat_path = pid / "stat"
        if not stat_path.exists():
            continue
        try:
            with stat_path.open() as fh:
                data = fh.read().split()
            comm = data[1].strip("()")
            utime = int(data[13])
            stime = int(data[14])
            total_time = utime + stime
            rows.append((total_time, pid.name, comm))
        except Exception:
            continue
    rows.sort(reverse=True)
    header = "PID      COMMAND            CPU-TICKS"
    lines = [header]
    for total_time, pid_str, comm in rows[:limit]:
        lines.append(f"{pid_str:<8} {comm[:16]:<16} {total_time:<10}")
    return lines


def read_load_average() -> Tuple[float, float, float]:
    try:
        return os.getloadavg()
    except (AttributeError, OSError):
        loadavg_path = Path("/proc/loadavg")
        if loadavg_path.exists():
            parts = loadavg_path.read_text().split()
            try:
                return float(parts[0]), float(parts[1]), float(parts[2])
            except (ValueError, IndexError):
                pass
        return (0.0, 0.0, 0.0)


def read_swap_stats() -> Tuple[float, float, float]:
    meminfo = Path("/proc/meminfo")
    total = free = None
    if meminfo.exists():
        for line in meminfo.read_text().splitlines():
            if line.startswith("SwapTotal"):
                total = int(line.split()[1]) / (1024 ** 2)
            elif line.startswith("SwapFree"):
                free = int(line.split()[1]) / (1024 ** 2)
            if total is not None and free is not None:
                break
    if not total:
        return 0.0, 0.0, 0.0
    if free is None:
        free = 0.0
    used = max(total - free, 0.0)
    pct = (used / total * 100) if total else 0.0
    return total, used, pct


def cron_view(_: argparse.Namespace) -> None:
    ensure_command("crontab")
    process = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    if process.returncode != 0 or not process.stdout.strip():
        print("No cron entries found.")
    else:
        print(process.stdout.strip())


def cron_add(args: argparse.Namespace) -> None:
    ensure_command("crontab")
    existing = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
    current = existing.stdout if existing.returncode == 0 else ""
    new_entry = f"{args.schedule} {args.command}"
    content = "\n".join(
        [line for line in current.splitlines() if line.strip()] + [new_entry]
    ) + "\n"
    subprocess.run(["crontab", "-"], input=content, text=True, check=True)
    print("Cron entry added.")


def backup_directory(args: argparse.Namespace) -> None:
    source = Path(args.source).resolve()
    destination = Path(args.destination).resolve()
    if not source.exists():
        raise FileNotFoundError(f"Source {source} not found.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    tar_cmd = [
        "tar",
        "-czf",
        str(destination),
        "-C",
        str(source.parent),
        source.name,
    ]
    run_command(tar_cmd)
    print(f"Backup created at {destination}")


def view_syslog(_: argparse.Namespace) -> None:
    syslog_path = Path("/var/log/syslog")
    if syslog_path.exists():
        result = run_command(["tail", "-n", "200", str(syslog_path)], capture_output=True, check=False)
        print(result.stdout.strip())
    else:
        print("/var/log/syslog not found.")


def view_journal(_: argparse.Namespace) -> None:
    ensure_command("journalctl")
    result = run_command(["journalctl", "-n", "200", "--no-pager"], capture_output=True, check=False)
    print(result.stdout.strip())


def view_dmesg(_: argparse.Namespace) -> None:
    result = run_command(["dmesg", "-T"], capture_output=True, check=False)
    lines = result.stdout.strip().splitlines()[-200:]
    print("\n".join(lines))


def list_sessions(_: argparse.Namespace) -> None:
    result = run_command(["who"], capture_output=True, check=False)
    output = result.stdout.strip() or "No active sessions."
    print(output)


def kill_session(args: argparse.Namespace) -> None:
    ensure_command("pkill")
    run_command(["pkill", "-KILL", "-t", args.tty])
    print(f"Session on {args.tty} terminated.")


def network_traceroute(args: argparse.Namespace) -> None:
    command = None
    if shutil.which("traceroute"):
        command = ["traceroute", args.host]
    elif shutil.which("tracepath"):
        command = ["tracepath", args.host]
    if command is None:
        raise RuntimeError("traceroute/tracepath not installed.")
    result = run_command(command, capture_output=True, check=False)
    output = result.stdout.strip()
    if not output:
        output = result.stderr.strip()
    if result.returncode != 0 and result.stderr:
        raise RuntimeError(result.stderr.strip() or "Traceroute failed.")
    print(output or "(no output)")


def network_test_port(args: argparse.Namespace) -> None:
    ensure_command("nc")
    result = run_command(
        ["nc", "-vz", args.host, str(args.port)],
        capture_output=True,
        check=False,
    )
    print(result.stdout.strip() or result.stderr.strip())


def ensure_command(cmd: str) -> None:
    if shutil.which(cmd) is None:
        raise RuntimeError(
            f"Command '{cmd}' not found. Install it or adjust your firewall backend."
        )


def ufw_available() -> bool:
    return shutil.which("ufw") is not None


def get_service_state(unit: str) -> str:
    if shutil.which("systemctl") is None:
        return "systemctl unavailable"
    result = subprocess.run(
        ["systemctl", "is-active", unit],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        return result.stdout.strip() or "active"
    return (result.stdout or result.stderr).strip() or "inactive"


def firewall_status(_: argparse.Namespace) -> None:
    if ufw_available():
        result = run_command(["ufw", "status", "verbose"], check=False, capture_output=True)
        print(result.stdout.strip())
    else:
        ensure_command("iptables")
        result = run_command(["iptables", "-L"], check=False, capture_output=True)
        print(result.stdout.strip())


def firewall_toggle(args: argparse.Namespace) -> None:
    if not ufw_available():
        raise RuntimeError("Firewall toggle requires 'ufw'. Install ufw or manage manually.")
    run_command(["ufw", args.state])
    print(f"Firewall {args.state}d.")


def firewall_rule(args: argparse.Namespace) -> None:
    protocol = f"{args.port}/{args.protocol}"
    if ufw_available():
        command = ["ufw", args.action, protocol]
        if getattr(args, "comment", None):
            command.extend(["comment", args.comment])
        run_command(command)
    else:
        ensure_command("iptables")
        rule_action = "-A" if args.action == "allow" else "-D"
        jump = "ACCEPT" if args.action == "allow" else "DROP"
        run_command(
            [
                "iptables",
                rule_action,
                "INPUT",
                "-p",
                args.protocol,
                "--dport",
                str(args.port),
                "-j",
                jump,
            ]
        )
    print(f"Firewall rule updated: {args.action} {protocol}")


def storage_status(args: argparse.Namespace) -> None:
    target = Path(args.path or "/").expanduser()
    if not target.exists():
        raise FileNotFoundError(f"{target} does not exist.")
    usage = shutil.disk_usage(target)
    total_gb = usage.total / (1024 ** 3)
    used_gb = usage.used / (1024 ** 3)
    free_gb = usage.free / (1024 ** 3)
    used_pct = (usage.used / usage.total) * 100 if usage.total else 0.0
    status = "ALERT" if used_pct >= args.threshold else "OK"
    advice = (
        "Consider deleting old logs, tmp files, or extending the disk."
        if status == "ALERT"
        else "Usage looks healthy. Keep monitoring periodically."
    )
    rows = [
        ["Location", str(target)],
        ["Total space", f"{total_gb:.2f} GB"],
        ["Used space", f"{used_gb:.2f} GB"],
        ["Free space", f"{free_gb:.2f} GB"],
        ["Usage", f"{used_pct:.2f}% {usage_bar(used_pct)}"],
        ["Threshold", f"{args.threshold:.0f}%"],
    ]
    table = format_table(["Metric", "Details"], rows)
    print(f"Storage summary for {target}:\n")
    print(table)
    print(f"\nStatus : {status}")
    print(f"Advice : {advice}")


def storage_df(_: argparse.Namespace) -> None:
    ensure_command("df")
    result = run_command(["df", "-h"], capture_output=True, check=False)
    output = result.stdout.strip() or result.stderr.strip() or "(no output)"
    print("Filesystem usage (df -h):\n")
    print(output)


def network_show_interfaces(_: argparse.Namespace) -> None:
    ensure_command("ip")
    result = run_command(["ip", "-brief", "address"], capture_output=True, check=False)
    print(result.stdout.strip())


def network_show_routes(_: argparse.Namespace) -> None:
    ensure_command("ip")
    result = run_command(["ip", "route"], capture_output=True, check=False)
    print(result.stdout.strip())


def network_show_connections(_: argparse.Namespace) -> None:
    ensure_command("ss")
    result = run_command(["ss", "-tunlp"], capture_output=True, check=False)
    print(result.stdout.strip())


def network_show_dns(_: argparse.Namespace) -> None:
    resolv = Path("/etc/resolv.conf")
    if not resolv.exists():
        print("/etc/resolv.conf not found.")
        return
    lines = [line.strip() for line in resolv.read_text().splitlines() if line.strip()]
    if not lines:
        print("No DNS entries found.")
    else:
        print("\n".join(lines))


def network_interface_show_detail(iface: str) -> str:
    ensure_command("ip")
    result = run_command(["ip", "address", "show", iface], capture_output=True, check=False)
    return result.stdout.strip() or result.stderr.strip() or f"No details for {iface}"


def network_interface_up_down(args: argparse.Namespace) -> None:
    ensure_command("ip")
    action = "up" if args.state == "up" else "down"
    run_command(["ip", "link", "set", args.interface, action])
    print(f"Interface {args.interface} set {action}.")


def network_interface_assign(args: argparse.Namespace) -> None:
    ensure_command("ip")
    run_command(
        ["ip", "address", "add", args.address, "dev", args.interface],
        capture_output=False,
        check=True,
    )
    print(f"Assigned {args.address} to {args.interface}.")


def network_interface_remove(args: argparse.Namespace) -> None:
    ensure_command("ip")
    run_command(
        ["ip", "address", "del", args.address, "dev", args.interface],
        capture_output=False,
        check=True,
    )
    print(f"Removed {args.address} from {args.interface}.")


def network_interface_request_dhcp(args: argparse.Namespace) -> None:
    dhclient = shutil.which("dhclient")
    if not dhclient:
        raise RuntimeError("dhclient not found. Install it to request automatic IP.")
    result = run_command(
        [dhclient, "-v", "-1", args.interface],
        capture_output=True,
        check=False,
    )
    output = result.stdout.strip() or result.stderr.strip() or "DHCP request issued."
    print(output)


def network_check_connectivity(_: argparse.Namespace) -> None:
    ensure_command("curl")
    result = run_command(
        [
            "curl",
            "-I",
            "--silent",
            "--max-time",
            "5",
            "https://www.google.com",
        ],
        capture_output=True,
        check=False,
    )
    output = result.stdout.strip() or result.stderr.strip()
    print(output or "No response captured.")


def network_ping_host(args: argparse.Namespace) -> None:
    ensure_command("ping")
    command = ["ping", "-c", str(args.count), args.host]
    result = run_command(command, capture_output=True, check=False)
    output = result.stdout.strip() or result.stderr.strip()
    print(output or "Ping command produced no output.")


def system_show_info(_: argparse.Namespace) -> None:
    uname = platform.uname()
    lines = [
        f"System : {uname.system}",
        f"Node   : {uname.node}",
        f"Release: {uname.release}",
        f"Version: {uname.version}",
        f"Machine: {uname.machine}",
        f"Processor: {uname.processor or '-'}",
    ]
    print("\n".join(lines))


def system_running_services(_: argparse.Namespace) -> None:
    ensure_command("systemctl")
    result = run_command(
        ["systemctl", "--type=service", "--state=running", "--no-pager"],
        capture_output=True,
        check=False,
    )
    print(result.stdout.strip() or result.stderr.strip())


def get_all_service_units() -> List[Dict[str, str]]:
    ensure_command("systemctl")
    result = run_command(
        [
            "systemctl",
            "list-units",
            "--type=service",
            "--all",
            "--no-legend",
            "--no-pager",
        ],
        capture_output=True,
        check=False,
    )
    entries: List[Dict[str, str]] = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split(None, 4)
        name = parts[0]
        load = parts[1] if len(parts) > 1 else "-"
        active = parts[2] if len(parts) > 2 else "-"
        sub = parts[3] if len(parts) > 3 else "-"
        description = parts[4] if len(parts) > 4 else ""
        entries.append(
            {
                "name": name,
                "load": load,
                "active": active,
                "sub": sub,
                "description": description,
            }
        )
    entries.sort(key=lambda item: (item["active"] != "active", item["name"]))
    return entries


def system_stop_service(args: argparse.Namespace) -> None:
    ensure_command("systemctl")
    run_command(["systemctl", "stop", args.service])
    print(f"Service {args.service} stopped.")


def system_start_service(args: argparse.Namespace) -> None:
    ensure_command("systemctl")
    run_command(["systemctl", "start", args.service])
    print(f"Service {args.service} started.")


def system_kill_service(args: argparse.Namespace) -> None:
    ensure_command("systemctl")
    run_command(["systemctl", "kill", args.service])
    print(f"Service {args.service} killed.")


def system_restart_service(args: argparse.Namespace) -> None:
    ensure_command("systemctl")
    run_command(["systemctl", "restart", args.service])
    print(f"Service {args.service} restarted.")


def system_recent_logins(_: argparse.Namespace) -> None:
    ensure_command("last")
    result = run_command(["last", "-n", "10"], capture_output=True, check=False)
    print(result.stdout.strip() or result.stderr.strip())


def system_auth_log(_: argparse.Namespace) -> None:
    ensure_command("journalctl")
    result = run_command(
        ["journalctl", "-u", "ssh", "-n", "50", "--no-pager"],
        capture_output=True,
        check=False,
    )
    print(result.stdout.strip() or "No SSH journal entries.")


def system_kernel_modules(_: argparse.Namespace) -> None:
    ensure_command("lsmod")
    result = run_command(["lsmod"], capture_output=True, check=False)
    print(result.stdout.strip())


def system_security_updates(_: argparse.Namespace) -> None:
    ensure_command("apt")
    result = run_command(
        ["apt", "list", "--upgradable"],
        capture_output=True,
        check=False,
    )
    print(result.stdout.strip() or result.stderr.strip() or "No updates listed.")


def ftp_install(_: argparse.Namespace) -> None:
    ensure_command("apt-get")
    run_command(["apt-get", "update"])
    run_command(["apt-get", "install", "-y", "vsftpd"])
    print("vsftpd installed.")


def ftp_control(args: argparse.Namespace) -> None:
    ensure_command("systemctl")
    run_command(["systemctl", args.state, "vsftpd"])
    print(f"vsftpd {args.state}ed.")


def ftp_status(_: argparse.Namespace) -> None:
    ensure_command("systemctl")
    result = run_command(["systemctl", "status", "vsftpd"], capture_output=True, check=False)
    print(result.stdout.strip() or result.stderr.strip())


def ftp_configure_anonymous(args: argparse.Namespace) -> None:
    config_path = Path("/etc/vsftpd.conf")
    if not config_path.exists():
        raise FileNotFoundError("/etc/vsftpd.conf not found. Install vsftpd first.")
    data = config_path.read_text().splitlines()
    new_lines = []
    updated = False
    target = f"anonymous_enable={'YES' if args.enabled else 'NO'}"
    for line in data:
        if line.startswith("anonymous_enable="):
            if not updated:
                new_lines.append(target)
                updated = True
        else:
            new_lines.append(line)
    if not updated:
        new_lines.append(target)
    config_path.write_text("\n".join(new_lines) + "\n")
    run_command(["systemctl", "restart", "vsftpd"])
    state = "enabled" if args.enabled else "disabled"
    print(f"Anonymous FTP {state}.")


def ftp_get_current_port(config_path: Path = Path("/etc/vsftpd.conf")) -> int:
    if not config_path.exists():
        return 21
    for line in config_path.read_text().splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("listen_port"):
            parts = stripped.split("=", 1)
            if len(parts) == 2:
                with suppress(ValueError):
                    return int(parts[1].strip())
    return 21


def ftp_set_port(args: argparse.Namespace) -> None:
    port = int(args.port)
    if not (1 <= port <= 65535):
        raise ValueError("Port must be between 1 and 65535.")
    config_path = Path("/etc/vsftpd.conf")
    if not config_path.exists():
        raise FileNotFoundError("/etc/vsftpd.conf not found. Install vsftpd first.")
    lines = config_path.read_text().splitlines()
    new_lines = []
    updated = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("listen_port"):
            if not updated:
                new_lines.append(f"listen_port={port}")
                updated = True
            continue
        new_lines.append(line)
    if not updated:
        new_lines.append(f"listen_port={port}")
    config_path.write_text("\n".join(new_lines) + "\n")
    ensure_command("systemctl")
    run_command(["systemctl", "restart", "vsftpd"])
    print(f"FTP port updated to {port} and vsftpd restarted.")


def ftp_apply_recommended(_: argparse.Namespace) -> None:
    config_path = Path("/etc/vsftpd.conf")
    if not config_path.exists():
        raise FileNotFoundError("/etc/vsftpd.conf not found. Install vsftpd first.")
    desired = {
        "local_enable": "YES",
        "write_enable": "YES",
        "userlist_enable": "YES",
        "userlist_file": "/etc/vsftpd.userlist",
        "userlist_deny": "NO",
    }
    lines = config_path.read_text().splitlines()
    new_lines = []
    applied = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            new_lines.append(line)
            continue
        key = stripped.split("=", 1)[0]
        if key in desired:
            new_lines.append(f"{key}={desired[key]}")
            applied.add(key)
        else:
            new_lines.append(line)
    for key, value in desired.items():
        if key not in applied:
            new_lines.append(f"{key}={value}")
    config_path.write_text("\n".join(new_lines) + "\n")
    userlist = Path("/etc/vsftpd.userlist")
    userlist.touch(exist_ok=True)
    run_command(["systemctl", "restart", "vsftpd"])
    print("Applied recommended vsftpd configuration and restarted service.")


def ftp_test_connection(args: argparse.Namespace) -> None:
    if shutil.which("curl"):
        cmd = ["curl", f"ftp://{args.host}:{args.port}", "--max-time", "5", "-I"]
    elif shutil.which("nc"):
        cmd = ["nc", "-vz", args.host, str(args.port)]
    else:
        raise RuntimeError("Install curl or netcat to test FTP connectivity.")
    result = run_command(cmd, capture_output=True, check=False)
    print(result.stdout.strip() or result.stderr.strip())


def ftp_show_users(_: argparse.Namespace) -> None:
    entries = ftp_read_userlist()
    output = "\n".join(entries) if entries else "(no FTP users registered)"
    print("FTP allowlist:\n" + output)


def ftp_read_userlist() -> List[str]:
    userlist = Path("/etc/vsftpd.userlist")
    if not userlist.exists():
        userlist.parent.mkdir(parents=True, exist_ok=True)
        userlist.touch()
        return []
    return [line.strip() for line in userlist.read_text().splitlines() if line.strip()]


def ftp_write_userlist(entries: List[str]) -> None:
    userlist = Path("/etc/vsftpd.userlist")
    userlist.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(entries)
    userlist.write_text((content + "\n") if content else "")


def ftp_add_user(args: argparse.Namespace) -> None:
    command = ["useradd", "-m", "-s", "/usr/sbin/nologin"]
    if args.home:
        command.extend(["-d", args.home])
    command.append(args.username)
    run_command(command)
    subprocess.run(
        ["chpasswd"],
        input=f"{args.username}:{args.password}",
        text=True,
        check=True,
    )
    shells = Path("/etc/shells")
    shell_path = "/usr/sbin/nologin"
    if shells.exists():
        shell_lines = [line.strip() for line in shells.read_text().splitlines() if line.strip()]
        if shell_path not in shell_lines:
            shell_lines.append(shell_path)
            shells.write_text("\n".join(shell_lines) + "\n")
    else:
        shells.write_text("\n".join(["/bin/sh", shell_path]) + "\n")
    if args.append_userlist:
        entries = ftp_read_userlist()
        if args.username not in entries:
            entries.append(args.username)
            ftp_write_userlist(entries)
    print(f"FTP user {args.username} created.")


def ftp_remove_user(args: argparse.Namespace) -> None:
    command = ["userdel"]
    if args.remove_home:
        command.append("-r")
    command.append(args.username)
    run_command(command)
    if args.remove_userlist:
        entries = ftp_read_userlist()
        if args.username in entries:
            entries = [line for line in entries if line != args.username]
            ftp_write_userlist(entries)
    print(f"FTP user {args.username} removed.")


def run_action(handler, **kwargs) -> tuple[bool, str]:
    """Execute a handler and capture stdout/stderr for display inside the TUI."""
    buffer_out = io.StringIO()
    buffer_err = io.StringIO()

    def _call() -> None:
        handler(argparse.Namespace(**kwargs))

    try:
        with redirect_stdout(buffer_out), redirect_stderr(buffer_err):
            _call()
    except Exception as exc:
        stderr_text = buffer_err.getvalue().strip()
        payload = "\n".join(filter(None, [stderr_text, f"Error: {exc}"]))
        return False, payload or f"Error: {exc}"

    stdout_text = buffer_out.getvalue().strip()
    stderr_text = buffer_err.getvalue().strip()
    combined = "\n".join(filter(None, [stdout_text, stderr_text]))
    return True, combined or "(no output)"


class AisyCliTUI:
    FOOTER = "Use ↑/↓ (or j/k) to navigate, Enter to select, q to go back."
    CANCEL_TOKEN = ":b"
    ACTION_SECTIONS = {
        "User management",
        "Firewall",
        "Storage",
        "Network & Internet",
        "System & Security",
        "Package Manager",
        "Monitoring",
        "Scheduler & Backup",
        "Logs & Sessions",
        "FTP",
    }

    def __init__(self, stdscr: Any) -> None:
        self.stdscr = stdscr
        curses.curs_set(0)
        curses.noecho()
        curses.cbreak()
        self.stdscr.keypad(True)
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
        curses.mouseinterval(0)
        self.has_color = False
        if curses.has_colors():
            curses.start_color()
            curses.use_default_colors()
            curses.init_pair(1, curses.COLOR_CYAN, -1)
            curses.init_pair(2, curses.COLOR_YELLOW, -1)
            curses.init_pair(3, curses.COLOR_GREEN, -1)
            curses.init_pair(4, curses.COLOR_RED, -1)
            self.has_color = True
        self._sidebar_width = 0
        self._sidebar_top = 0
        self._action_panel_meta: Optional[Dict[str, Any]] = None
        self._pending_hint = ""
        self._saved_interface_ips: Dict[str, List[str]] = {}

    def run(self) -> None:
        menu_items = [
            "Dashboard",
            "User management",
            "Firewall",
            "Storage",
            "Network & Internet",
            "System & Security",
            "Package Manager",
            "Monitoring",
            "Scheduler & Backup",
            "Logs & Sessions",
            "FTP",
            "About",
            "Exit",
        ]
        active = 0
        active_mode: Optional[str] = None
        op_index = 0
        while True:
            self.render_layout(menu_items, active, active_mode, op_index)
            key = self.stdscr.getch()
            if key == curses.KEY_MOUSE:
                active, active_mode, handled, should_exit = self._handle_mouse_input(menu_items, active, active_mode)
                if should_exit:
                    return
                if handled:
                    op_index = 0
                continue
            if active_mode:
                operations = self.get_operations(active_mode)
                if not operations:
                    active_mode = None
                    continue
                if key in (curses.KEY_UP, ord("k")):
                    op_index = (op_index - 1) % len(operations)
                elif key in (curses.KEY_DOWN, ord("j")):
                    op_index = (op_index + 1) % len(operations)
                elif key in (10, 13):
                    operations[op_index][1]()
                elif key in (ord("q"), ord("Q"), 27, curses.KEY_LEFT, ord("h")):
                    active_mode = None
                    op_index = 0
                continue

            if key in (curses.KEY_UP, ord("k")):
                active = (active - 1) % len(menu_items)
            elif key in (curses.KEY_DOWN, ord("j")):
                active = (active + 1) % len(menu_items)
            elif key in (10, 13, curses.KEY_RIGHT, ord("l")):
                label = menu_items[active]
                if label == "Dashboard":
                    continue
                if label == "Exit":
                    if not self._confirm_exit():
                        continue
                    return
                active_mode = label
                op_index = 0
            elif key in (ord("q"), ord("Q")):
                if self._confirm_exit():
                    return

    def render_layout(self, items: List[str], active: int, active_mode: Optional[str], op_index: int) -> None:
        self.stdscr.clear()
        height, width = self.stdscr.getmaxyx()
        if not self._has_min_space(height, width):
            self._show_resize_warning(height, width)
            return
        sidebar_width = max(20, min(30, width // 4))
        self._sidebar_width = sidebar_width
        left = 1
        right = sidebar_width - 1
        top = 1
        bottom = top + 2
        inner = max(0, right - left - 1)
        if inner > 0:
            self.stdscr.hline(top, left + 1, curses.ACS_HLINE, inner)
            self.stdscr.hline(bottom, left + 1, curses.ACS_HLINE, inner)
            self.stdscr.vline(top + 1, left, curses.ACS_VLINE, bottom - top - 1)
            self.stdscr.vline(top + 1, right, curses.ACS_VLINE, bottom - top - 1)
            self.stdscr.addch(top, left, curses.ACS_ULCORNER)
            self.stdscr.addch(top, right, curses.ACS_URCORNER)
            self.stdscr.addch(bottom, left, curses.ACS_LLCORNER)
            self.stdscr.addch(bottom, right, curses.ACS_LRCORNER)
            title = "aisy-cli"
            title_x = left + 1 + max(0, (inner - len(title)) // 2)
            self._safe_addstr(top + 1, title_x, title[: inner], curses.A_BOLD | self._color(1))
        start_y = bottom + 2
        self._sidebar_top = start_y
        self._sidebar_count = len(items)
        for idx, label in enumerate(items):
            attr = curses.A_REVERSE if idx == active else curses.A_NORMAL
            self._safe_addstr(start_y + idx, 2, label.ljust(sidebar_width - 4)[: sidebar_width - 4], attr)
        for y in range(1, height - 1):
            try:
                self.stdscr.addch(y, sidebar_width, curses.ACS_VLINE)
            except curses.error:
                pass
        content_x = sidebar_width + 2
        content_width = width - content_x - 3
        self._pending_hint = ""
        self.draw_view_content(items[active], content_x, content_width, active_mode, op_index)
        if active_mode is None:
            hint = "Sidebar: ↑/↓ · Enter=open · q=exit"
        else:
            hint = self._pending_hint
        self._show_hint(hint)
        self.stdscr.refresh()

    def draw_view_content(self, label: str, start_x: int, width: int, active_mode: Optional[str], op_index: int) -> None:
        y = 2
        self._action_panel_meta = None
        if label == "Dashboard":
            data = gather_dashboard_data()
            self._render_dashboard(start_x, width, data)
            return
        elif label in self.ACTION_SECTIONS:
            info = self._section_port_status(label)
            if info:
                y = self._draw_lines(start_x, y, info, width)
            operations = self.get_operations(label)
            self._draw_action_panel(
                label,
                start_x,
                y,
                width,
                operations,
                active_mode == label,
                op_index,
            )
        elif label == "About":
            self._render_about_panel(start_x, width)
        elif label == "Exit":
            lines = [
                "Exit aisy-cli",
                "",
                "Press Enter to close the application or use q.",
            ]
            self._draw_lines(start_x, y, lines, width)

    def get_operations(self, label: str) -> List[tuple[str, Callable[[], None]]]:
        if label == "User management":
            return [
                ("List & manage users", self.user_manage_flow),
                ("Add user", self.add_user_flow),
                ("Change password", self.change_password_flow),
                ("Change SSH port", self.user_change_port_flow),
            ]
        if label == "Firewall":
            return [
                ("Show firewall status", lambda: self.execute(firewall_status, output_title="Firewall status")),
                ("Enable firewall", lambda: self.firewall_toggle_flow("enable")),
                ("Disable firewall", lambda: self.firewall_toggle_flow("disable")),
                ("Allow port", lambda: self.firewall_rule_flow("allow")),
                ("Deny port", lambda: self.firewall_rule_flow("deny")),
            ]
        if label == "Storage":
            return [
                ("Show friendly disk summary", self.storage_status_flow),
                ("View classic df -h output", lambda: self.execute(storage_df, output_title="Filesystem usage")),
            ]
        if label == "Network & Internet":
            return [
                ("Show IP addresses", lambda: self.execute(network_show_interfaces, output_title="IP addresses")),
                ("Show routing table", lambda: self.execute(network_show_routes, output_title="Routing table")),
                ("Show listening ports", lambda: self.execute(network_show_connections, output_title="Listening ports")),
                ("Show DNS resolvers", lambda: self.execute(network_show_dns, output_title="DNS resolvers")),
                ("Manage interfaces", self.network_interface_manager_flow),
                ("Manage netplan", self.netplan_manager_flow),
                ("Ping host", self.network_ping_flow),
                ("Traceroute host", self.network_traceroute_flow),
                ("Test TCP port", self.network_port_test_flow),
                ("Check HTTPS connectivity", lambda: self.execute(network_check_connectivity, output_title="HTTPS connectivity")),
            ]
        if label == "System & Security":
            return [
                ("Show system info", lambda: self.execute(system_show_info, output_title="System information")),
                ("Manage services", self.system_manage_services_flow),
                ("Configure SSH port", self.system_configure_ssh_port),
                ("Manage authorized_keys", self.system_authorized_keys_flow),
                ("Manage SSH private keys", self.system_private_keys_flow),
                ("Manage known_hosts", self.system_known_hosts_flow),
                ("Recent logins", lambda: self.execute(system_recent_logins, output_title="Recent logins")),
                ("SSH auth logs", lambda: self.execute(system_auth_log, output_title="SSH authentication log")),
                ("Kernel modules", lambda: self.execute(system_kernel_modules, output_title="Kernel modules")),
                ("Check security updates", lambda: self.execute(system_security_updates, output_title="Security updates")),
            ]
        if label == "Package Manager":
            return [
                ("List available updates", lambda: self.execute(package_list_updates, output_title="Available package updates")),
                ("Install package", self.package_install_flow),
                ("Remove package", self.package_remove_flow),
                ("Search package", self.package_search_flow),
                ("Upgrade selected package", self.package_upgrade_selected_flow),
                ("Upgrade all packages", self.package_upgrade_all_flow),
            ]
        if label == "Monitoring":
            return [
                ("Live metrics dashboard", self.monitoring_live_flow),
            ]
        if label == "Scheduler & Backup":
            return [
                ("View cron entries", lambda: self.execute(cron_view, output_title="Cron entries")),
                ("Add cron entry", self.cron_add_flow),
                ("Create tar backup", self.backup_flow),
            ]
        if label == "Logs & Sessions":
            return [
                ("Tail syslog", lambda: self.execute(view_syslog, allow_reverse=True, output_title="Syslog tail")),
                ("Tail journalctl", lambda: self.execute(view_journal, allow_reverse=True, output_title="Journal tail")),
                ("Tail dmesg", lambda: self.execute(view_dmesg, allow_reverse=True, output_title="dmesg tail")),
                ("List active sessions", lambda: self.execute(list_sessions, allow_reverse=True, output_title="Active sessions")),
                ("Terminate session", self.kill_session_flow),
            ]
        if label == "FTP":
            return [
                ("Manage vsftpd service", self.ftp_service_flow),
                ("Manage FTP user list", self.ftp_userlist_flow),
                ("Manage FTP port", self.ftp_port_flow),
                ("Apply recommended config", self.ftp_apply_recommended_flow),
                ("Configure anonymous FTP", self.ftp_anonymous_flow),
                ("Test FTP connectivity", self.ftp_test_flow),
            ]
        return []

    def _confirm_exit(self) -> bool:
        choice = self.select_option(
            "Exit aisy-cli?",
            ["Yes", "No"],
            footer="Enter=select · q=cancel",
            exit_with_q=True,
        )
        if choice is None:
            return False
        return choice == 0
    def _color(self, idx: int) -> int:
        return curses.color_pair(idx) if self.has_color else curses.A_NORMAL

    def _usage_bar(self, pct: float) -> str:
        return usage_bar(pct)

    def _draw_lines(self, start_x: int, start_y: int, lines: List[str], width: int) -> int:
        y = start_y
        for line in lines:
            self._safe_addstr(y, start_x, line[: width])
            y += 1
        return y + 1

    def _draw_action_panel(
        self,
        section: str,
        start_x: int,
        start_y: int,
        width: int,
        operations: List[tuple[str, Callable[[], None]]],
        interactive: bool,
        selected: int,
    ) -> None:
        header = f"{section} actions"
        self._safe_addstr(start_y, start_x, header, curses.A_BOLD)
        y = start_y + 2
        for idx, (label, _) in enumerate(operations):
            if interactive:
                attr = curses.A_REVERSE if idx == selected else curses.A_NORMAL
                prefix = "→ " if idx == selected else "  "
            else:
                attr = curses.A_DIM
                prefix = "• "
            self._safe_addstr(y + idx, start_x, (prefix + label)[: width], attr)
        y += len(operations) + 1
        if interactive:
            hint = "Enter=run · ←/q=back"
        else:
            hint = "Press → or Enter to focus actions."
        self._pending_hint = hint
        if interactive:
            self._action_panel_meta = {
                "start_x": start_x,
                "start_y": start_y + 2,
                "width": width,
                "count": len(operations),
                "operations": operations,
            }

    def _draw_all_services(self, services: List[Dict[str, str]], index: int) -> None:
        height, width = self.stdscr.getmaxyx()
        if height < 14 or width < 60:
            self.show_status("Increase terminal size to manage services.")
            return
        win_height = min(max(len(services), 1) + 6, height - 2)
        win_width = min(100, width - 4)
        start_y = max(2, (height - win_height) // 2)
        start_x = max(2, (width - win_width) // 2)
        window = curses.newwin(win_height, win_width, start_y, start_x)
        window.clear()
        self._box_border(window)
        window.addstr(1, 2, "Manage services", curses.A_BOLD)
        visible = win_height - 4
        if services:
            index = max(0, min(index, len(services) - 1))
            offset = max(0, min(index - visible + 1, max(len(services) - visible, 0)))
            for i in range(visible):
                pos = offset + i
                if pos >= len(services):
                    break
                entry = services[pos]
                attr = curses.A_REVERSE if pos == index else curses.A_NORMAL
                window.addstr(3 + i, 2, self._format_service_entry(entry, win_width - 4), attr)
        else:
            window.addstr(3, 2, "(no services detected)"[: win_width - 4])
        window.refresh()
        instructions = "Up/Down select · S start/stop · R restart · X kill · q back"
        self._show_hint(instructions)

    def _format_service_entry(self, entry: Dict[str, str], width: int) -> str:
        active = entry["active"].upper()
        sub = entry["sub"]
        desc = entry["description"]
        label = f"[{active:5}] {entry['name']} ({sub}) - {desc}"
        return label[: width]

    def _handle_service_action(
        self,
        service: Dict[str, str],
        action: str,
        handler: Callable[[argparse.Namespace], None],
    ) -> bool:
        return self._confirm_then_run(
            f"{action} {service['name']}?",
            handler,
            service=service["name"],
        )

    def _draw_userlist_manager(self, entries: List[str], index: int) -> None:
        height, width = self.stdscr.getmaxyx()
        win_height = min(max(len(entries), 1) + 6, height - 2)
        win_width = min(60, width - 4)
        start_y = max(2, (height - win_height) // 2)
        start_x = max(2, (width - win_width) // 2)
        window = curses.newwin(win_height, win_width, start_y, start_x)
        window.clear()
        self._box_border(window)
        window.addstr(1, 2, "FTP allowlist", curses.A_BOLD)
        instructions = "↑/↓ select · Enter=manage · a add · d delete · q back"
        visible = win_height - 4
        if entries:
            index = max(0, min(index, len(entries) - 1))
            offset = max(0, min(index - visible + 1, max(len(entries) - visible, 0)))
            for i in range(visible):
                pos = offset + i
                if pos >= len(entries):
                    break
                attr = curses.A_REVERSE if pos == index else curses.A_NORMAL
                window.addstr(3 + i, 2, entries[pos][: win_width - 4], attr)
        else:
            window.addstr(3, 2, "(no FTP users)"[: win_width - 4])
        window.refresh()
        self._show_hint(instructions)

    def _draw_line_manager(
        self,
        title: str,
        entries: List[str],
        index: int,
        instructions: str,
        empty_label: str,
    ) -> None:
        height, width = self.stdscr.getmaxyx()
        win_height = min(max(len(entries), 1) + 6, height - 2)
        win_width = min(80, width - 4)
        start_y = max(2, (height - win_height) // 2)
        start_x = max(2, (width - win_width) // 2)
        window = curses.newwin(win_height, win_width, start_y, start_x)
        window.clear()
        self._box_border(window)
        window.addstr(1, 2, title[: win_width - 4], curses.A_BOLD)
        window.refresh()
        self._show_hint(instructions)
        visible = win_height - 4
        if entries:
            index = max(0, min(index, len(entries) - 1))
            offset = max(0, min(index - visible + 1, max(len(entries) - visible, 0)))
            for i in range(visible):
                pos = offset + i
                if pos >= len(entries):
                    break
                attr = curses.A_REVERSE if pos == index else curses.A_NORMAL
                window.addstr(3 + i, 2, entries[pos][: win_width - 4], attr)
        else:
            window.addstr(3, 2, empty_label[: win_width - 4])
        window.refresh()

    def _summary_input(self, title: str, lines: List[str], prompt: str = ": ") -> Optional[str]:
        while True:
            self.stdscr.clear()
            height, width = self.stdscr.getmaxyx()
            if not self._has_min_space(height, width):
                self._show_resize_warning(height, width)
                self.stdscr.getch()
                continue
            self._safe_addstr(1, 2, title, curses.A_BOLD)
            y = 3
            for line in lines:
                self._safe_addstr(y, 2, line[: width - 4])
                y += 1
            self._safe_addstr(y + 1, 2, prompt[: width - 4])
            self.stdscr.refresh()
            curses.echo()
            raw = self.stdscr.getstr(y + 2, 2, width - 4)
            curses.noecho()
            text = raw.decode("utf-8").strip() if raw else ""
            if text.lower() == self.CANCEL_TOKEN:
                return None
            return text

    def _edit_text(self, title: str, initial: str) -> Optional[str]:
        editor = os.environ.get("EDITOR", "nano")
        with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
            tmp.write(initial)
            tmp_path = tmp.name
        curses.endwin()
        try:
            subprocess.run([editor, tmp_path], check=False)
        except Exception as exc:
            print(f"Failed to run editor {editor}: {exc}")
            return None
        finally:
            self.stdscr.clear()
            self.stdscr.refresh()
        try:
            content = Path(tmp_path).read_text()
        finally:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
        return content

    def _select_user_entry(self, title: str) -> Optional[Dict[str, str]]:
        entries = read_passwd_entries()
        if not entries:
            self.show_status("No users found.")
            return None
        options = [
            f"{entry['username']} (uid {entry['uid']}, home {entry['home']})" for entry in entries
        ]
        choice = self.select_option(
            title,
            options,
            footer="Enter=select | q=back",
            exit_with_q=True,
            footer_external=True,
        )
        if choice is None:
            return None
        return entries[choice]

    def _prepare_ssh_dir(self, home: Path) -> Path:
        ssh_dir = home.expanduser() / ".ssh"
        ssh_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(ssh_dir, 0o700)
        return ssh_dir

    def _prepare_ssh_file(self, home: Path, filename: str, mode: int = 0o600) -> Path:
        ssh_dir = self._prepare_ssh_dir(home)
        path = ssh_dir / filename
        if not path.exists():
            path.touch()
        os.chmod(path, mode)
        return path

    def _read_text_lines(self, path: Path) -> List[str]:
        if not path.exists():
            return []
        lines = []
        for line in path.read_text().splitlines():
            if line.strip():
                lines.append(line.rstrip())
        return lines

    def _write_text_lines(self, path: Path, lines: List[str], mode: int = 0o600) -> None:
        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + ("\n" if lines else ""))
        os.chmod(path, mode)

    def _manage_text_list_file(
        self,
        title: str,
        path: Path,
        add_prompt: str,
        empty_label: str,
        mode: int = 0o600,
    ) -> None:
        entries = self._read_text_lines(path)
        index = 0 if entries else -1
        instructions = "Up/Down select | a add | d delete | q back"
        while True:
            self._draw_line_manager(title, entries, index, instructions, empty_label)
            key = self.stdscr.getch()
            if key in (ord("q"), ord("Q"), 27):
                break
            if key in (curses.KEY_UP, ord("k")) and entries:
                index = (index - 1) % len(entries)
            elif key in (curses.KEY_DOWN, ord("j")) and entries:
                index = (index + 1) % len(entries)
            elif key in (ord("a"), ord("A")):
                new_value = self.prompt_text(add_prompt, allow_cancel=True)
                if new_value:
                    entries.append(new_value)
                    self._write_text_lines(path, entries, mode=mode)
                    index = len(entries) - 1
            elif key in (ord("d"), ord("D")) and entries:
                confirm = self.prompt_bool("Remove selected entry?", default=False, allow_cancel=True)
                if confirm:
                    entries.pop(index)
                    self._write_text_lines(path, entries, mode=mode)
                    if entries:
                        index %= len(entries)
                    else:
                        index = -1


    def _confirm_then_run(self, message: str, func: Callable, **kwargs) -> bool:
        prompt = message if message.endswith("?") else f"{message}?"
        confirm = self.prompt_bool(prompt, default=False, allow_cancel=True)
        if confirm is None or not confirm:
            return False
        self.execute(func, **kwargs)
        return True

    def _render_dashboard(self, start_x: int, width: int, data: Dict[str, Any]) -> None:
        columns = 1 if width < 70 else 2
        card_width = max(30, (width - 2) // columns)
        cards = [
            (
                "System",
                [
                    f"Host     : {data['system']['hostname']}",
                    f"Kernel   : {data['system']['kernel']}",
                    f"Time     : {data['system']['time']}",
                    f"Uptime   : {data['system']['uptime']}",
                ],
            ),
            (
                "Users",
                [
                    f"Total    : {data['users']['total']} (regular {data['users']['regular']})",
                    f"System   : {data['users']['system']}",
                    f"Logins   : {data['users']['login_shells']}",
                    f"Homes ✕  : {data['users']['home_missing']}",
                ],
            ),
            (
                "Memory",
                [
                    f"Total    : {data['memory']['total']:.1f} GB",
                    f"Used     : {data['memory']['used']:.1f} GB",
                    f"Free     : {data['memory']['available']:.1f} GB",
                    f"Usage    : {data['memory']['used_pct']:.1f}% {self._usage_bar(data['memory']['used_pct'])}",
                ],
            ),
            (
                "Storage",
                [
                    f"Mount    : {data['storage']['path']}",
                    f"Total    : {data['storage']['total_gb']:.1f} GB",
                    f"Used     : {data['storage']['used_gb']:.1f} GB",
                    f"Usage    : {data['storage']['used_pct']:.1f}% {self._usage_bar(data['storage']['used_pct'])}",
                ],
            ),
            (
                "Security",
                [
                    f"Firewall : {data['firewall_backend']}",
                    f"Status   : {data['firewall_status']}",
                    f"VSFTPD   : {data['ftp_state']}",
                ],
            ),
            (
                "FTP",
                [
                    f"Allowlist users : {data['ftp_users']}",
                    "Use FTP menu to manage accounts and config.",
                ],
            ),
        ]

        y = 2
        if columns == 1:
            for title, lines in cards:
                y = self._draw_card(y, start_x, width, title, lines) + 1
        else:
            idx = 0
            while idx < len(cards):
                left_title, left_lines = cards[idx]
                right = cards[idx + 1] if idx + 1 < len(cards) else None
                left_end = self._draw_card(y, start_x, card_width, left_title, left_lines)
                if right is not None:
                    right_end = self._draw_card(y, start_x + card_width + 2, card_width, right[0], right[1])
                    idx += 2
                else:
                    right_end = y
                    idx += 1
                y = max(left_end, right_end) + 1

    def _render_about_panel(self, start_x: int, width: int) -> None:
        y = 2
        panel_width = min(70, width - 4)

        def draw_centered(line: str, bold: bool = False) -> None:
            padding = max(0, (panel_width - len(line)) // 2)
            text = " " * padding + line
            attr = curses.A_BOLD if bold else curses.A_NORMAL
            self._safe_addstr(y, start_x, text[: width], attr)

        banner = [
            "════════════════════════════════════════════════════",
            "                   aisy-cli                         ",
            "    Comprehensive Linux administration companion     ",
            "════════════════════════════════════════════════════",
        ]
        for line in banner:
            draw_centered(line, bold=True)
            y += 1
        y += 1

        info_rows = [
            ("Author", "Umarul Fiddin"),
            ("Version", "1.0.1"),
            ("Repository", "https://github.com/umarfd/aisy-cli.git"),
            ("Contact", "umar.edm@gmail.com"),
        ]
        for label, value in info_rows:
            line = f"{label:<10}: {value}"
            self._safe_addstr(y, start_x + 2, line[: width])
            y += 1
        y += 1

        summary = [
            "Mission",
            "  Deliver dependable tooling for Linux administrators",
            "  by consolidating daily operations into a single",
            "  keyboard-first interface.",
            "",
            "Highlights",
            "  • Structured menus for user, network, and security tasks",
            "  • Context-aware prompts and confirmations",
            "  • Live monitoring inspired by htop/btop",
            "  • Netplan and interface managers for network agility",
            "  • FTP and package automation with audit-friendly logs",
            "",
            "Support",
            "  Submit feedback or contributions through GitHub issues.",
            "  Commercial support available on request.",
        ]
        for line in summary:
            style = curses.A_BOLD if line and not line.startswith("  ") else curses.A_NORMAL
            self._safe_addstr(y, start_x + 2, line[: width], style)
            y += 1

    def _draw_card(self, y: int, x: int, width: int, title: str, lines: List[str]) -> int:
        width = max(24, width)
        top = "╭" + "─" * (width - 2) + "╮"
        bottom = "╰" + "─" * (width - 2) + "╯"
        self._safe_addstr(y, x, top)
        title_text = f" {title.upper()} "
        title_line = "│" + title_text[: width - 2].ljust(width - 2) + "│"
        self._safe_addstr(y + 1, x, title_line, curses.A_BOLD)
        for idx, line in enumerate(lines, start=2):
            self._safe_addstr(y + idx, x, "│" + line[: width - 2].ljust(width - 2) + "│")
        self._safe_addstr(y + len(lines) + 2, x, bottom)
        return y + len(lines) + 2

    def select_option(
        self,
        title: str,
        options: List[str],
        footer: str = "",
        initial: int = 0,
        exit_with_q: bool = False,
        footer_external: bool = False,
    ) -> Optional[int]:
        height, width = self.stdscr.getmaxyx()
        win_height = min(len(options) + 6, height - 2)
        content_width = max(len(title), *(len(o) for o in options)) + 6
        win_width = min(max(content_width, len(footer) + 4), width - 4)
        start_y = max(1, (height - win_height) // 2)
        start_x = max(2, (width - win_width) // 2)
        window = curses.newwin(win_height, win_width, start_y, start_x)
        window.keypad(True)
        index = max(0, min(initial, len(options) - 1))
        if index >= len(options):
            index = 0
        if not options:
            return None

        while True:
            window.clear()
            window.clear()
            self._box_border(window)
            window.addstr(1, 2, title[: win_width - 4], curses.A_BOLD)
            visible = win_height - 4
            offset = max(0, min(index - visible + 1, max(len(options) - visible, 0)))
            for i in range(visible):
                pos = offset + i
                if pos >= len(options):
                    break
                attr = curses.A_REVERSE if pos == index else curses.A_NORMAL
                window.addstr(3 + i, 2, options[pos][: win_width - 4], attr)
            if footer:
                self._show_hint(footer)
            else:
                self._show_hint("")
            window.refresh()
            key = window.getch()
            if key in (curses.KEY_UP, ord("k")):
                index = (index - 1) % len(options)
            elif key in (curses.KEY_DOWN, ord("j")):
                index = (index + 1) % len(options)
            elif key in (10, 13):
                self._show_hint("")
                return index
            elif key in (ord("q"), ord("Q"), 27):
                if exit_with_q:
                    self._show_hint("")
                    return None


    def _safe_addstr(self, y: int, x: int, text: str, attr: int = curses.A_NORMAL) -> None:
        height, width = self.stdscr.getmaxyx()
        if y < 0 or y >= height or x >= width:
            return
        available = width - x
        if available <= 0:
            return
        try:
            self.stdscr.addstr(y, x, text[: available], attr)
        except curses.error:
            pass

    def _show_hint(self, text: str) -> None:
        height, width = self.stdscr.getmaxyx()
        row = max(0, height - 1)
        # Clear line first
        try:
            self.stdscr.move(row, 1)
            self.stdscr.clrtoeol()
        except curses.error:
            pass
        if text:
            self._safe_addstr(row, 2, text[: max(0, width - 4)], self._color(2))

    def _box_border(self, window: curses.window) -> None:
        window.border(
            curses.ACS_VLINE,
            curses.ACS_VLINE,
            curses.ACS_HLINE,
            curses.ACS_HLINE,
            curses.ACS_ULCORNER,
            curses.ACS_URCORNER,
            curses.ACS_LLCORNER,
            curses.ACS_LRCORNER,
        )

    def _has_min_space(self, height: int, width: int) -> bool:
        return height >= 18 and width >= 60

    def _show_resize_warning(self, height: int, width: int) -> None:
        self.stdscr.clear()
        msg = "Terminal too small. Increase size to at least 60x18."
        y = max(0, height // 2)
        x = max(0, (width - len(msg)) // 2)
        self._safe_addstr(y, x, msg, curses.A_BOLD | self._color(4))
        self.stdscr.refresh()

    def show_output(self, title: str, content: str, success: bool = True, allow_reverse: bool = False) -> bool:
        if success and not allow_reverse:
            self._show_success_popup(title, content)
            return False
        lines = content.splitlines() or ["(no output)"]
        descending = allow_reverse
        y_offset = 0
        x_offset = 0
        cancelled = False
        while True:
            current_lines = lines[::-1] if descending else lines
            max_line = max(len(line) for line in current_lines)
            self.stdscr.clear()
            height, width = self.stdscr.getmaxyx()
            color = self._color(3 if success else 4)
            self._safe_addstr(1, 2, title, curses.A_BOLD | color)
            visible = height - 5
            for idx in range(visible):
                line_idx = y_offset + idx
                if line_idx >= len(current_lines):
                    break
                segment = current_lines[line_idx]
                padded = segment[x_offset : x_offset + width - 4]
                self._safe_addstr(3 + idx, 2, padded)
            footer = "Up/Down=scroll | Left/Right=pan | q=back"
            if allow_reverse:
                footer += " | r=toggle order"
            self._show_hint(footer)
            self.stdscr.refresh()
            key = self.stdscr.getch()
            if key in (ord("q"), ord("Q"), 27):
                cancelled = True
                break
            if key in (curses.KEY_ENTER, 10, 13):
                break
            elif key == curses.KEY_DOWN and y_offset < max(len(current_lines) - visible, 0):
                y_offset += 1
            elif key == curses.KEY_UP and y_offset > 0:
                y_offset -= 1
            elif key == curses.KEY_NPAGE:
                y_offset = min(y_offset + visible, max(len(current_lines) - visible, 0))
            elif key == curses.KEY_PPAGE:
                y_offset = max(y_offset - visible, 0)
            elif key in (curses.KEY_RIGHT, ord("l")):
                x_offset = min(
                    max(0, max_line - (width - 4)),
                    x_offset + max(1, (width - 4) // 2),
                )
            elif key in (curses.KEY_LEFT, ord("h")):
                x_offset = max(0, x_offset - max(1, (width - 4) // 2))
            elif allow_reverse and key in (ord("r"), ord("R")):
                descending = not descending
                y_offset = 0
                x_offset = 0
        self._show_hint("")
        return cancelled

    def _show_success_popup(self, title: str, content: str) -> None:
        """Display a modal popup with an OK button for success messages."""
        lines = content.splitlines() or ["(no output)"]
        height, width = self.stdscr.getmaxyx()
        max_line = min(max(len(line) for line in lines), width - 10)
        win_height = min(len(lines) + 6, height - 4)
        win_width = min(max(max_line + 6, len(title) + 6, 20), width - 4)
        start_y = max(2, (height - win_height) // 2)
        start_x = max(2, (width - win_width) // 2)
        window = curses.newwin(win_height, win_width, start_y, start_x)
        window.keypad(True)
        while True:
            window.clear()
            self._box_border(window)
            window.addstr(1, 2, title[: win_width - 4], curses.A_BOLD | self._color(3))
            visible = win_height - 6
            for idx in range(visible):
                if idx >= len(lines):
                    break
                window.addstr(3 + idx, 2, lines[idx][: win_width - 4])
            button = "[ OK ]"
            btn_x = max(2, (win_width - len(button)) // 2)
            window.addstr(win_height - 2, btn_x, button, curses.A_REVERSE)
            window.refresh()
            key = window.getch()
            if key in (curses.KEY_ENTER, 10, 13, ord(" "), ord("q"), ord("Q"), 27):
                break

    def prompt_text(
        self,
        title: str,
        default: Optional[str] = None,
        allow_empty: bool = False,
        secret: bool = False,
        allow_cancel: bool = False,
    ) -> Optional[str]:
        while True:
            self.stdscr.clear()
            height, width = self.stdscr.getmaxyx()
            self._safe_addstr(1, 2, title, curses.A_BOLD)
            if default is not None:
                self._safe_addstr(3, 2, f"Default: {default}")
            if allow_cancel:
                self._safe_addstr(4, 2, f"Type '{self.CANCEL_TOKEN}' to cancel.")
            if secret:
                self._safe_addstr(5 if allow_cancel else 4, 2, "Input is hidden; type and press Enter.")
            input_y = height // 2
            prompt_label = "> "
            self._safe_addstr(input_y, 2, prompt_label)
            self.stdscr.refresh()
            if secret:
                value = self._read_secret(input_y, 2 + len(prompt_label), width - 4).strip()
            else:
                curses.echo()
                raw = self.stdscr.getstr(input_y, 2 + len(prompt_label), width - 6)
                curses.noecho()
                value = raw.decode("utf-8").strip() if raw else ""

            if allow_cancel and value.lower() == self.CANCEL_TOKEN:
                return None
            if not value and default is not None:
                return default
            if value or allow_empty:
                return value
            self.show_status("Input is required. Press any key to continue.")

    def prompt_int(self, title: str, default: Optional[int] = None, allow_cancel: bool = False) -> Optional[int]:
        while True:
            raw = self.prompt_text(
                title,
                str(default) if default is not None else None,
                allow_cancel=allow_cancel,
            )
            if raw is None:
                return None
            try:
                return int(raw)
            except ValueError:
                self.show_status("Enter a valid number.")

    def prompt_float(
        self,
        title: str,
        default: Optional[float] = None,
        allow_cancel: bool = False,
    ) -> Optional[float]:
        while True:
            raw = self.prompt_text(
                title,
                str(default) if default is not None else None,
                allow_cancel=allow_cancel,
            )
            if raw is None:
                return None
            try:
                return float(raw)
            except ValueError:
                self.show_status("Enter a valid decimal value.")

    def prompt_bool(self, title: str, default: bool = False, allow_cancel: bool = False) -> Optional[bool]:
        initial = 0 if default else 1
        opt = self.select_option(
            title,
            ["Yes", "No"],
            footer="Enter to confirm, q to cancel (defaults to previous choice).",
            initial=initial,
            exit_with_q=allow_cancel,
        )
        if opt is None:
            if allow_cancel:
                return None
            return default
        return opt == 0

    def show_status(self, message: str) -> None:
        self._show_hint(message)
        self.stdscr.refresh()
        self.stdscr.getch()
        self._show_hint("")

    def _read_secret(self, y: int, x: int, width: int) -> str:
        chars: list[str] = []
        while True:
            self._render_input(y, x, "*" * len(chars), width)
            key = self.stdscr.getch()
            if key in (10, 13):
                break
            if key in (curses.KEY_BACKSPACE, 127, curses.KEY_DC, 8):
                if chars:
                    chars.pop()
                continue
            if 32 <= key <= 126 and len(chars) < width - 1:
                chars.append(chr(key))
        self._render_input(y, x, "*" * len(chars), width)
        return "".join(chars)

    def _render_input(self, y: int, x: int, text: str, width: int) -> None:
        self.stdscr.move(y, x)
        self.stdscr.clrtoeol()
        self.stdscr.addstr(y, x, text[: width])
        self.stdscr.refresh()

    def execute(
        self,
        handler,
        *,
        allow_reverse: bool = False,
        loading_message: Optional[str] = None,
        output_title: Optional[str] = None,
        **kwargs,
    ) -> None:
        if loading_message:
            result_holder: list[Optional[tuple[bool, str]]] = [None]
            error_holder: list[Optional[BaseException]] = [None]

            def _worker() -> None:
                try:
                    result_holder[0] = run_action(handler, **kwargs)
                except BaseException as exc:  # capture all to re-raise later
                    error_holder[0] = exc

            thread = threading.Thread(target=_worker, daemon=True)
            thread.start()
            spinner = "|/-\\"
            idx = 0
            while thread.is_alive():
                self._show_hint(f"{loading_message} {spinner[idx % len(spinner)]} · q=cancel")
                self.stdscr.refresh()
                idx += 1
                time.sleep(0.1)
            thread.join()
            self._show_hint("")
            if error_holder[0]:
                raise error_holder[0]
            success, output = result_holder[0] if result_holder[0] is not None else (False, "(no output)")
        else:
            success, output = run_action(handler, **kwargs)
        title = output_title if success and output_title else ("Success" if success else "Error")
        self.show_output(title, output, success=success, allow_reverse=allow_reverse)

    def user_menu(self) -> None:
        options = [
            ("List & manage users", self.user_manage_flow),
            ("Add user", self.add_user_flow),
            ("Change password", self.change_password_flow),
            ("Change SSH port", self.user_change_port_flow),
        ]
        self.menu_loop("User management", options)

    def add_user_flow(self) -> None:
        username = self.prompt_text("Username", allow_cancel=True)
        if username is None:
            return
        shell = self.prompt_text("Shell", default="/bin/bash", allow_cancel=True)
        if shell is None:
            return
        home = self.prompt_text("Home directory (leave blank for default)", allow_empty=True, allow_cancel=True)
        if home is None:
            return
        password = self.prompt_text(
            "Password (leave empty to skip)",
            allow_empty=True,
            secret=True,
            allow_cancel=True,
        )
        if password is None:
            return
        sudo_answer = self.prompt_text("Should the user be allowed to use sudo? (type 'yes' or 'no')", allow_cancel=True)
        if sudo_answer is None:
            return
        sudo_allowed = sudo_answer.strip().lower() == "yes"
        self.execute(
            add_user,
            username=username,
            shell=shell,
            home=home or None,
            password=password or None,
            system=False,
            sudo=sudo_allowed,
        )

    def change_password_flow(self) -> None:
        username = self.prompt_text("Username to update", allow_cancel=True)
        if username is None:
            return
        self._change_password_for_user(username)

    def user_manage_flow(self) -> None:
        initial = 0
        while True:
            entries = read_passwd_entries()
            if not entries:
                self.show_status("No users found.")
                return
            lock_status = read_shadow_lock_status()
            for entry in entries:
                entry["locked"] = lock_status.get(entry["username"])
            user_w, status_w, shell_w, home_w = self._calc_user_option_widths(entries)
            exit_menu, initial, needs_refresh = self._user_manage_popup(entries, initial, user_w, status_w, shell_w, home_w)
            if exit_menu:
                break
            if not needs_refresh:
                continue

    def _user_manage_actions(self, entry: Dict[str, str]) -> bool:
        username = entry["username"]
        options = [
            "View details",
            "Delete user",
            "Lock user",
            "Unlock user",
            "Change password",
            "Back",
        ]
        height, width = self.stdscr.getmaxyx()
        win_height = min(len(options) + 6, height - 4)
        win_width = min(50, width - 4)
        start_y = max(2, (height - win_height) // 2)
        start_x = max(2, (width - win_width) // 2)
        window = curses.newwin(win_height, win_width, start_y, start_x)
        window.keypad(True)
        index = 0
        while True:
            window.clear()
            self._box_border(window)
            title = f"Manage {username}"
            window.addstr(1, 2, title[: win_width - 4], curses.A_BOLD)
            for i, label in enumerate(options):
                attr = curses.A_REVERSE if i == index else curses.A_NORMAL
                window.addstr(3 + i, 2, label[: win_width - 4], attr)
            hint = "Enter=select · q=back"
            self._show_hint(hint)
            window.refresh()
            key = window.getch()
            if key in (curses.KEY_UP, ord("k")):
                index = (index - 1) % len(options)
            elif key in (curses.KEY_DOWN, ord("j")):
                index = (index + 1) % len(options)
            elif key in (10, 13):
                if index == 0:
                    self._show_user_details(entry)
                elif index == 1:
                    result = self._delete_user_from_list(username)
                    if result:
                        self._show_hint("")
                    return result
                elif index == 2:
                    confirmed = self.prompt_bool(
                        f"Lock user {username}?",
                        default=False,
                        allow_cancel=True,
                    )
                    if confirmed:
                        self._lock_unlock_user(username, "lock")
                        self._show_hint("")
                        return True
                elif index == 3:
                    confirmed = self.prompt_bool(
                        f"Unlock user {username}?",
                        default=False,
                        allow_cancel=True,
                    )
                    if confirmed:
                        self._lock_unlock_user(username, "unlock")
                        self._show_hint("")
                        return True
                elif index == 4:
                    self._change_password_for_user(username)
                    return False
                else:
                    return False
            elif key in (ord("q"), ord("Q"), 27):
                self._show_hint("")
                return False

    def _user_manage_popup(
        self,
        entries: List[Dict[str, str]],
        initial: int,
        user_w: int,
        status_w: int,
        shell_w: int,
        home_w: int,
    ) -> tuple[bool, int, bool]:
        options = [self._format_user_option(entry, user_w, status_w, shell_w, home_w) for entry in entries]
        options.append("+ Add new user")
        options.append("Refresh list")
        total = len(options)
        height, width = self.stdscr.getmaxyx()
        win_height = min(total + 6, height - 2)
        content_width = max(len("System users"), *(len(opt) for opt in options)) + 6
        win_width = min(max(content_width, len("Enter=manage user | q=back") + 4), width - 4)
        start_y = max(1, (height - win_height) // 2)
        start_x = max(2, (width - win_width) // 2)
        window = curses.newwin(win_height, win_width, start_y, start_x)
        window.keypad(True)
        index = max(0, min(initial, total - 1))
        footer = "Enter=manage user | q=back"
        while True:
            window.clear()
            self._box_border(window)
            window.addstr(1, 2, "System users"[: win_width - 4], curses.A_BOLD)
            visible = win_height - 4
            offset = max(0, min(index - visible + 1, max(total - visible, 0)))
            for i in range(visible):
                pos = offset + i
                if pos >= total:
                    break
                attr = curses.A_REVERSE if pos == index else curses.A_NORMAL
                window.addstr(3 + i, 2, options[pos][: win_width - 4], attr)
            window.refresh()
            self._show_hint(footer)
            key = window.getch()
            if key in (curses.KEY_UP, ord("k")):
                index = (index - 1) % total
            elif key in (curses.KEY_DOWN, ord("j")):
                index = (index + 1) % total
            elif key in (10, 13):
                if index < len(entries):
                    refresh = self._user_manage_actions(entries[index])
                    if refresh:
                        self._show_hint("")
                        return False, min(index, len(entries) - 1), True
                    continue
                if index == len(entries):
                    self.add_user_flow()
                    self._show_hint("")
                    return False, 0, True
                if index == len(entries) + 1:
                    self._show_hint("")
                    return False, min(index, len(entries) - 1), True
            elif key in (ord("q"), ord("Q"), 27):
                self._show_hint("")
                return True, index, False

    def _show_user_details(self, entry: Dict[str, str]) -> None:
        memberships = collect_group_memberships()
        groups = ", ".join(sorted(memberships.get(entry["username"], []))) or "(none)"
        locked = entry.get("locked")
        if locked is None:
            status_label = "Unknown"
        else:
            status_label = "Locked" if locked else "Unlocked"
        lines = [
            f"Username : {entry['username']}",
            f"UID      : {entry['uid']}",
            f"GID      : {entry['gid']}",
            f"Home     : {entry['home']}",
            f"Shell    : {entry['shell']}",
            f"Comment  : {entry['comment'] or '(empty)'}",
            f"Status   : {status_label}",
            f"Groups   : {groups}",
        ]
        self.show_output("User details", "\n".join(lines))

    def _calc_user_option_widths(
        self,
        entries: List[Dict[str, str]],
        *,
        max_width: Optional[int] = None,
    ) -> Tuple[int, int, int, int]:
        _, term_width = self.stdscr.getmaxyx()
        budget = max_width or term_width
        usernames = [len(entry["username"]) for entry in entries]
        shells = [len(Path(entry["shell"]).name or entry["shell"]) for entry in entries]
        user_w = min(22, max(10, (max(usernames) if usernames else 10) + 2))
        shell_w = min(16, max(8, (max(shells) if shells else 8) + 2))
        status_w = 10
        reserved = user_w + status_w + shell_w + 35  # separators + labels + UID field
        home_budget = max(16, budget - reserved)
        home_w = min(48, home_budget)
        return user_w, status_w, shell_w, home_w

    def _format_user_option(
        self,
        entry: Dict[str, str],
        user_w: int,
        status_w: int,
        shell_w: int,
        home_w: int,
    ) -> str:
        username = entry["username"]
        uid = entry["uid"]
        shell_name = Path(entry["shell"]).name or entry["shell"]
        if len(shell_name) > shell_w:
            shell_name = shell_name[: shell_w - 3] + "..."
        home = entry["home"]
        if len(home) > home_w:
            home = home[: home_w - 3] + "..."
        locked = entry.get("locked")
        if locked is None:
            status_label = "Unknown"
        else:
            status_label = "Locked" if locked else "Unlocked"
        return (
            f"{username:<{user_w}} | UID {uid:<5} | Status {status_label:<{status_w}}"
            f" | Shell {shell_name:<{shell_w}} | Home {home}"
        )

    def _collect_private_keys(self, ssh_dir: Path) -> List[Path]:
        if not ssh_dir.exists():
            return []
        keys = []
        for path in sorted(ssh_dir.glob("id_*")):
            if path.suffix == ".pub" or not path.is_file():
                continue
            keys.append(path)
        return keys

    def _format_private_key_option(self, path: Path) -> str:
        try:
            stat_info = path.stat()
            size_kb = stat_info.st_size / 1024
            mtime = datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M")
            perms = stat.filemode(stat_info.st_mode)
        except OSError:
            size_kb = 0
            mtime = "unknown"
            perms = "?????????"
        return f"{path.name:<18} | {size_kb:6.1f} KB | {mtime} | {perms}"

    def _private_key_menu(self, username: str, ssh_dir: Path) -> None:
        while True:
            keys = self._collect_private_keys(ssh_dir)
            options = [self._format_private_key_option(path) for path in keys]
            options.append("+ Generate new keypair")
            options.append("Refresh list")
            choice = self.select_option(
                f"Private keys for {username}",
                options,
                footer="Enter=select | q=back",
                exit_with_q=True,
                footer_external=True,
            )
            if choice is None:
                break
            if choice == len(keys):
                self._generate_private_key(ssh_dir)
                continue
            if choice == len(keys) + 1:
                continue
            if self._private_key_actions(keys[choice]):
                continue

    def _private_key_actions(self, path: Path) -> bool:
        options = [
            "Show fingerprint",
            "View private key",
            "Delete keypair",
            "Back",
        ]
        while True:
            choice = self.select_option(
                f"{path.name} actions",
                options,
                footer="Enter=select | q=back",
                exit_with_q=True,
                footer_external=True,
            )
            if choice is None or choice == len(options) - 1:
                return False
            if choice == 0:
                ensure_command("ssh-keygen")
                result = run_command(
                    ["ssh-keygen", "-lf", str(path)],
                    capture_output=True,
                    check=False,
                )
                output = result.stdout.strip() or result.stderr.strip() or "(no output)"
                self.show_output("SSH fingerprint", output)
            elif choice == 1:
                try:
                    content = path.read_text()
                except OSError as exc:
                    self.show_status(f"Failed to read key: {exc}")
                    continue
                self.show_output(path.name, content or "(empty)")
            elif choice == 2:
                confirm = self.prompt_bool(
                    f"Delete {path.name} and its public key?",
                    default=False,
                    allow_cancel=True,
                )
                if not confirm:
                    continue
                try:
                    path.unlink(missing_ok=True)
                    pub = path.with_suffix(path.suffix + ".pub") if path.suffix else Path(str(path) + ".pub")
                    if pub.exists():
                        pub.unlink()
                except OSError as exc:
                    self.show_status(f"Failed to delete key: {exc}")
                    continue
                self.show_status("Key removed.")
                return True

    def _generate_private_key(self, ssh_dir: Path) -> None:
        default_name = "id_ed25519"
        if (ssh_dir / default_name).exists():
            default_name = "id_rsa"
        name = self.prompt_text(
            "Private key filename (e.g., id_ed25519)",
            default=default_name,
            allow_cancel=True,
        )
        if name is None:
            return
        name = name.strip()
        if not name or "/" in name:
            self.show_status("Invalid key filename.")
            return
        path = ssh_dir / name
        if path.exists():
            confirm = self.prompt_bool(f"Overwrite {name}?", default=False, allow_cancel=True)
            if not confirm:
                return
        key_type = self.prompt_text("Key type (ed25519/rsa)", default="ed25519", allow_cancel=True)
        if key_type is None:
            return
        key_type = key_type.strip().lower()
        if key_type not in {"ed25519", "rsa"}:
            self.show_status("Key type must be ed25519 or rsa.")
            return
        passphrase = self.prompt_text(
            "Passphrase (leave empty for none)",
            allow_empty=True,
            secret=True,
            allow_cancel=True,
        )
        if passphrase is None:
            return
        ensure_command("ssh-keygen")
        command = ["ssh-keygen", "-t", key_type, "-f", str(path), "-N", passphrase]
        if key_type == "rsa":
            command.extend(["-b", "4096"])
        run_command(command)
        self.show_status(f"Generated {name}.")

    def _delete_user_from_list(self, username: str) -> bool:
        confirm = self.prompt_bool(f"Delete user {username}?", default=False, allow_cancel=True)
        if not confirm:
            return False
        remove_home = self.prompt_bool("Remove the user's home directory?", default=False, allow_cancel=True)
        if remove_home is None:
            return False
        if remove_home:
            typed = self.prompt_text(
                f"Type 'Delete {username} Directory' to confirm",
                allow_cancel=True,
            )
            if typed is None:
                return False
            if typed.strip() != f"Delete {username} Directory":
                self.show_status("Confirmation phrase did not match. Aborting removal.")
                return False
        self.execute(delete_user, username=username, remove_home=remove_home)
        return True

    def _lock_unlock_user(self, username: str, action: str) -> None:
        self.execute(lock_unlock_user, username=username, action=action)

    def _change_password_for_user(self, username: str) -> None:
        while True:
            new_password = self.prompt_text(
                "New password",
                secret=True,
                allow_cancel=True,
            )
            if new_password is None:
                return
            confirm = self.prompt_text(
                "Confirm new password",
                secret=True,
                allow_cancel=True,
            )
            if confirm is None:
                return
            if new_password != confirm:
                self.show_status("Passwords do not match. Try again.")
                continue
            break
        self.execute(change_password, username=username, password=new_password)

    def user_change_port_flow(self) -> None:
        self.system_configure_ssh_port()

    def firewall_menu(self) -> None:
        options = [
            ("Show firewall status", lambda: self.execute(firewall_status, output_title="Firewall status")),
            ("Enable firewall", lambda: self.firewall_toggle_flow("enable")),
            ("Disable firewall", lambda: self.firewall_toggle_flow("disable")),
            ("Allow port", lambda: self.firewall_rule_flow("allow")),
            ("Deny port", lambda: self.firewall_rule_flow("deny")),
        ]
        self.menu_loop("Firewall", options)

    def firewall_toggle_flow(self, state: str) -> None:
        confirm = self.prompt_bool(
            f"Really {state} the firewall?",
            default=False,
            allow_cancel=True,
        )
        if not confirm:
            return
        self.execute(firewall_toggle, state=state)

    def firewall_rule_flow(self, action: str) -> None:
        port = self.prompt_int("Port", default=22, allow_cancel=True)
        if port is None:
            return
        protocol = self.prompt_text("Protocol (tcp/udp)", default="tcp", allow_cancel=True)
        if protocol is None:
            return
        protocol = protocol.lower()
        if protocol not in {"tcp", "udp"}:
            self.show_status("Protocol must be tcp or udp.")
            return
        comment = self.prompt_text("Optional comment", allow_empty=True, allow_cancel=True)
        if comment is None:
            return
        self.execute(firewall_rule, port=port, protocol=protocol, action=action, comment=comment or None)

    def storage_menu(self) -> None:
        options = [
            ("Show friendly disk summary", self.storage_status_flow),
            ("View classic df -h output", lambda: self.execute(storage_df, output_title="Filesystem usage")),
        ]
        self.menu_loop("Storage", options)

    def storage_status_flow(self) -> None:
        path = self.prompt_text("Path to inspect", default="/", allow_cancel=True)
        if path is None:
            return
        threshold = self.prompt_float("Alert threshold (%)", default=80.0, allow_cancel=True)
        if threshold is None:
            return
        self.execute(
            storage_status,
            path=path,
            threshold=threshold,
            output_title=f"Storage status for {path}",
        )

    def network_ping_flow(self) -> None:
        host = self.prompt_text("Host to ping", default="8.8.8.8", allow_cancel=True)
        if host is None:
            return
        count = self.prompt_int("Number of packets", default=4, allow_cancel=True)
        if count is None:
            return
        self.execute(
            network_ping_host,
            host=host,
            count=count,
            loading_message="Pinging host...",
            output_title=f"Ping {host}",
        )

    def network_traceroute_flow(self) -> None:
        host = self.prompt_text("Host to trace", default="8.8.8.8", allow_cancel=True)
        if host is None:
            return
        self.execute(
            network_traceroute,
            host=host,
            loading_message="Tracing route...",
            output_title=f"Traceroute {host}",
        )

    def network_port_test_flow(self) -> None:
        host = self.prompt_text("Host to test", default="127.0.0.1", allow_cancel=True)
        if host is None:
            return
        port = self.prompt_int("Port", default=22, allow_cancel=True)
        if port is None:
            return
        self.execute(
            network_test_port,
            host=host,
            port=port,
            loading_message="Testing TCP port...",
            output_title=f"Port test {host}:{port}",
        )

    def package_install_flow(self) -> None:
        pkg = self.prompt_text("Package to install", allow_cancel=True)
        if pkg is None:
            return
        self.execute(package_install, package=pkg)

    def package_remove_flow(self) -> None:
        pkg = self.prompt_text("Package to remove", allow_cancel=True)
        if pkg is None:
            return
        self.execute(package_remove, package=pkg)

    def package_search_flow(self) -> None:
        term = self.prompt_text("Search term", allow_cancel=True)
        if term is None:
            return
        self.execute(package_search, term=term, output_title=f"Search results for '{term}'")

    def package_upgrade_all_flow(self) -> None:
        confirm = self.prompt_bool("Upgrade all packages now?", default=False, allow_cancel=True)
        if not confirm:
            return
        self.execute(package_upgrade_all, output_title="Upgrade all packages")

    def package_upgrade_selected_flow(self) -> None:
        entries = pending_upgrade_packages()
        if not entries:
            self.show_status("No packages to upgrade.")
            return
        labels = []
        names = []
        for line in entries:
            parts = line.split()
            name = parts[1] if len(parts) > 1 else line
            labels.append(line[:80])
            names.append(name)
        choice = self.select_option(
            "Select package to upgrade",
            labels,
            footer="Enter=upgrade · q=back",
            exit_with_q=True,
        )
        if choice is None:
            return
        pkg = names[choice]
        self.execute(package_upgrade_selected, packages=[pkg], output_title=f"Upgrade {pkg}")

    def cron_add_flow(self) -> None:
        schedule = self.prompt_text("Cron expression (e.g., */5 * * * *)", allow_cancel=True)
        if schedule is None:
            return
        command = self.prompt_text("Command to execute", allow_cancel=True)
        if command is None:
            return
        self.execute(cron_add, schedule=schedule, command=command)

    def backup_flow(self) -> None:
        source = self.prompt_text("Source directory/file", allow_cancel=True)
        if source is None:
            return
        destination = self.prompt_text("Destination archive (e.g., /tmp/backup.tar.gz)", allow_cancel=True)
        if destination is None:
            return
        self.execute(backup_directory, source=source, destination=destination)

    def kill_session_flow(self) -> None:
        tty = self.prompt_text("TTY to terminate (e.g., pts/0)", allow_cancel=True)
        if tty is None:
            return
        self.execute(kill_session, tty=tty)

    def system_manage_services_flow(self) -> None:
        services = get_all_service_units()
        if not services:
            self.show_output("Services", "No services found.")
            return
        index = 0
        while True:
            self._draw_all_services(services, index)
            key = self.stdscr.getch()
            updated = False
            if key in (curses.KEY_UP, ord("k")):
                index = (index - 1) % len(services)
            elif key in (curses.KEY_DOWN, ord("j")):
                index = (index + 1) % len(services)
            elif key in (ord("s"), ord("S")):
                if services[index]['active'] == 'active':
                    updated = self._handle_service_action(services[index], "Stop", system_stop_service)
                else:
                    updated = self._handle_service_action(services[index], "Start", system_start_service)
            elif key in (ord("x"), ord("X")):
                updated = self._handle_service_action(services[index], "Kill", system_kill_service)
            elif key in (ord("r"), ord("R")):
                updated = self._handle_service_action(services[index], "Restart", system_restart_service)
            elif key in (ord("q"), ord("Q"), ord("h"), curses.KEY_LEFT, 27):
                break
            if updated:
                services = get_all_service_units()
                if not services:
                    self.show_output("Services", "No services found.")
                    return
                index %= len(services)

    def system_configure_ssh_port(self) -> None:
        current = self._read_current_ssh_port()
        prompt = f"New SSH port (current {current})"
        port = self.prompt_int(prompt, default=current, allow_cancel=True)
        if port is None:
            return
        if not (1 <= port <= 65535):
            self.show_status("Port must be between 1 and 65535.")
            return
        self.execute(configure_ssh_port, port=port)

    def system_authorized_keys_flow(self) -> None:
        entry = self._select_user_entry("Select user (authorized_keys)")
        if entry is None:
            return
        home = Path(entry["home"]).expanduser()
        path = self._prepare_ssh_file(home, "authorized_keys", mode=0o600)
        self._manage_text_list_file(
            f"authorized_keys for {entry['username']}",
            path,
            add_prompt="Paste public key line",
            empty_label="No authorized keys.",
            mode=0o600,
        )

    def system_known_hosts_flow(self) -> None:
        entry = self._select_user_entry("Select user (known_hosts)")
        if entry is None:
            return
        home = Path(entry["home"]).expanduser()
        path = self._prepare_ssh_file(home, "known_hosts", mode=0o644)
        self._manage_text_list_file(
            f"known_hosts for {entry['username']}",
            path,
            add_prompt="Enter known_hosts line",
            empty_label="No known hosts stored.",
            mode=0o644,
        )

    def system_private_keys_flow(self) -> None:
        entry = self._select_user_entry("Select user (private keys)")
        if entry is None:
            return
        home = Path(entry["home"]).expanduser()
        ssh_dir = self._prepare_ssh_dir(home)
        self._private_key_menu(entry["username"], ssh_dir)

    def ftp_anonymous_flow(self) -> None:
        enabled = self.prompt_bool("Enable anonymous FTP?", allow_cancel=True)
        if enabled is None:
            return
        self.execute(ftp_configure_anonymous, enabled=enabled)

    def ftp_apply_recommended_flow(self) -> None:
        summary_lines = [
            "Recommended vsftpd settings:",
            "- local_enable=YES",
            "- write_enable=YES",
            "- userlist_enable=YES",
            "- userlist_file=/etc/vsftpd.userlist",
            "- userlist_deny=NO",
            "- restart vsftpd",
            "",
            "Type 'apply' to proceed or ':b' to cancel.",
        ]
        confirm = self._summary_input("FTP Config Summary", summary_lines, prompt="Confirm: ")
        if confirm is None:
            return
        if confirm.strip().lower() != "apply":
            self.show_status("FTP configuration update cancelled.")
            return
        self.execute(ftp_apply_recommended)

    def ftp_test_flow(self) -> None:
        host = self.prompt_text("FTP host", default="127.0.0.1", allow_cancel=True)
        if host is None:
            return
        port = self.prompt_int("FTP port", default=21, allow_cancel=True)
        if port is None:
            return
        self.execute(
            ftp_test_connection,
            host=host,
            port=port,
            output_title=f"FTP test {host}:{port}",
        )

    def ftp_service_flow(self) -> None:
        actions = [
            ("Install vsftpd", lambda: self._confirm_then_run("Install vsftpd now?", ftp_install)),
            ("Service status", lambda: self.execute(ftp_status, output_title="vsftpd status")),
            ("Start service", lambda: self._confirm_then_run("Start vsftpd service?", ftp_control, state="start")),
            ("Stop service", lambda: self._confirm_then_run("Stop vsftpd service?", ftp_control, state="stop")),
            ("Restart service", lambda: self._confirm_then_run("Restart vsftpd service?", ftp_control, state="restart")),
        ]
        labels = [label for label, _ in actions]
        initial = 0
        while True:
            choice = self.select_option(
                "vsftpd Service",
                labels,
                footer="Enter=run · q=back",
                initial=initial,
                exit_with_q=True,
            )
            if choice is None:
                break
            result = actions[choice][1]()
            if result is not False:
                initial = choice

    def ftp_port_flow(self) -> None:
        try:
            current = ftp_get_current_port()
        except Exception as exc:
            self.show_status(f"Failed to read current port: {exc}")
            return
        label = f"FTP port to use (current {current})"
        port = self.prompt_int(label, allow_cancel=True)
        if port is None:
            return
        if not (1 <= port <= 65535):
            self.show_status("Port must be between 1 and 65535.")
            return
        confirm = self.prompt_bool(
            f"Apply port {port}? vsftpd will restart.",
            default=False,
            allow_cancel=True,
        )
        if not confirm:
            return
        self.execute(ftp_set_port, port=port)

    def ftp_userlist_flow(self) -> None:
        entries = ftp_read_userlist()
        index = 0 if entries else -1
        while True:
            self._draw_userlist_manager(entries, index)
            key = self.stdscr.getch()
            if key in (ord("q"), ord("Q"), 27, curses.KEY_LEFT, ord("h")):
                break
            if key in (curses.KEY_UP, ord("k")) and entries:
                index = (index - 1) % len(entries)
            elif key in (curses.KEY_DOWN, ord("j")) and entries:
                index = (index + 1) % len(entries)
            elif key in (10, 13) and entries:
                changed = self._ftp_manage_userlist_entry(entries[index])
                if changed:
                    entries = ftp_read_userlist()
                    if entries:
                        index = min(index, len(entries) - 1)
                    else:
                        index = -1
                continue
            elif key in (ord("a"), ord("A")):
                self.ftp_add_user_flow()
                entries = ftp_read_userlist()
                index = len(entries) - 1 if entries else -1
                continue
            elif key in (ord("d"), ord("D")):
                if not entries:
                    self.show_status("No entries to delete.")
                    continue
                confirm = self.prompt_bool(f"Remove {entries[index]}?", default=False, allow_cancel=True)
                if confirm:
                    entries.pop(index)
                    ftp_write_userlist(entries)
                    if entries:
                        index %= len(entries)
                    else:
                        index = -1
                    self.show_status("FTP user entry removed.")
        self._show_hint("")

    def _show_ftp_allowlist_preview(self) -> None:
        entries = ftp_read_userlist()
        height, width = self.stdscr.getmaxyx()
        win_height = min(max(len(entries), 1) + 6, height - 2)
        win_width = min(60, width - 4)
        start_y = max(2, (height - win_height) // 2)
        start_x = max(2, (width - win_width) // 2)
        window = curses.newwin(win_height, win_width, start_y, start_x)
        window.keypad(True)
        index = len(entries) - 1 if entries else 0
        while True:
            window.clear()
            self._box_border(window)
            window.addstr(1, 2, "FTP allowlist", curses.A_BOLD)
            visible = win_height - 4
            if entries:
                offset = max(0, min(index - visible + 1, max(len(entries) - visible, 0)))
                for i in range(visible):
                    pos = offset + i
                    if pos >= len(entries):
                        break
                    attr = curses.A_REVERSE if pos == index else curses.A_NORMAL
                    window.addstr(3 + i, 2, entries[pos][: win_width - 4], attr)
            else:
                window.addstr(3, 2, "(no FTP users)"[: win_width - 4])
            window.refresh()
            self._show_hint("FTP allowlist · Enter/q=close")
            key = window.getch()
            if key in (10, 13, ord("q"), ord("Q"), 27):
                self._show_hint("")
                break
            if key in (curses.KEY_UP, ord("k")) and entries:
                index = (index - 1) % len(entries)
            elif key in (curses.KEY_DOWN, ord("j")) and entries:
                index = (index + 1) % len(entries)

    def _ftp_manage_userlist_entry(self, username: str) -> bool:
        options = [
            "Show entry info",
            "Delete entry",
            "Back",
        ]
        while True:
            choice = self.select_option(
                f"FTP entry {username}",
                options,
                footer="Enter=select · q=back",
                exit_with_q=True,
            )
            if choice is None or choice == len(options) - 1:
                return False
            if choice == 0:
                lines = [
                    f"Userlist entry : {username}",
                    "",
                    "Users listed here are permitted to authenticate when",
                    "vsftpd is configured with userlist_enable=YES and",
                    "userlist_deny=NO.",
                ]
                self.show_output(f"{username} info", "\n".join(lines))
            elif choice == 1:
                confirm = self.prompt_bool(
                    f"Delete {username} from vsftpd.userlist?",
                    default=False,
                    allow_cancel=True,
                )
                if not confirm:
                    continue
                current = ftp_read_userlist()
                removed = False
                new_entries: List[str] = []
                for entry in current:
                    if entry == username and not removed:
                        removed = True
                        continue
                    new_entries.append(entry)
                if removed:
                    ftp_write_userlist(new_entries)
                    self.show_status(f"{username} removed from vsftpd.userlist.")
                    return True
                self.show_status(f"{username} was not present in vsftpd.userlist.")

    def monitoring_live_flow(self) -> None:
        prev_idle, prev_total = read_cpu_times()
        prev_core_snapshot = read_cpu_core_snapshot()
        last_net = read_network_stats()
        self.stdscr.timeout(1000)
        while True:
            self.stdscr.clear()
            height, width = self.stdscr.getmaxyx()
            if height < 24 or width < 80:
                self._show_resize_warning(height, width)
                key = self.stdscr.getch()
                if key in (ord("q"), ord("Q"), 27):
                    break
                continue

            system = get_system_info()
            load1, load5, load15 = read_load_average()
            mem_summary = get_memory_summary()
            mem_total = mem_summary["total"]
            mem_used = mem_summary["used"]
            mem_pct = mem_summary["used_pct"]
            swap_total, swap_used, swap_pct = read_swap_stats()
            disk = read_disk_stats()
            net = read_network_stats()
            net_rx = max(net["received_mb"] - last_net["received_mb"], 0.0)
            net_tx = max(net["transmit_mb"] - last_net["transmit_mb"], 0.0)
            last_net = net
            procs = read_process_table(limit=10)
            core_snapshot = read_cpu_core_snapshot()
            core_usage = compute_cpu_usage_percent(core_snapshot, prev_core_snapshot)
            prev_core_snapshot = core_snapshot

            idle, total = read_cpu_times()
            idle_delta = idle - prev_idle
            total_delta = total - prev_total
            cpu_pct = 0.0
            if total_delta > 0:
                cpu_pct = max(0.0, min(100.0, 100 * (1 - idle_delta / total_delta)))
            prev_idle, prev_total = idle, total

            self._safe_addstr(1, 2, "Live metrics dashboard", curses.A_BOLD)
            header = f"Host {system['hostname']} · Kernel {system['kernel']} · Time {system['time']} · Uptime {system['uptime']}"
            self._safe_addstr(2, 2, header[: width - 4])
            load_line = f"Load averages: {load1:.2f} {load5:.2f} {load15:.2f}"
            self._safe_addstr(3, 2, load_line[: width - 4])

            y = 5
            cpu_line = f"CPU avg {cpu_pct:5.1f}% {usage_bar(cpu_pct, 30)}"
            self._safe_addstr(y, 2, cpu_line[: width - 4])
            y += 1
            mem_line = (
                f"Mem {mem_used:5.2f}/{mem_total:5.2f} GB ({mem_pct:5.1f}%) "
                f"{usage_bar(mem_pct, 30)} · Avail {mem_summary['available']:5.2f} GB"
            )
            self._safe_addstr(y, 2, mem_line[: width - 4])
            y += 1
            swap_line = f"Swap {swap_used:5.2f}/{swap_total:5.2f} GB ({swap_pct:5.1f}%) {usage_bar(swap_pct, 30)}"
            self._safe_addstr(y, 2, swap_line[: width - 4])
            y += 1
            disk_line = (
                f"Disk {disk['used_gb']:5.2f}/{disk['total_gb']:5.2f} GB ({disk['used_pct']:5.1f}%) "
                f"{usage_bar(disk['used_pct'], 30)}"
            )
            self._safe_addstr(y, 2, disk_line[: width - 4])
            y += 1
            net_line = (
                f"Network Δ RX {net_rx:5.2f} MB/s · TX {net_tx:5.2f} MB/s · Total RX {net['received_mb']:6.1f} MB · TX {net['transmit_mb']:6.1f} MB"
            )
            self._safe_addstr(y, 2, net_line[: width - 4])
            y += 2

            core_lines = []
            for name in sorted(core_usage):
                if name == "cpu":
                    continue
                pct = core_usage[name]
                core_lines.append(f"{name.upper():<5} {usage_bar(pct, 18)} {pct:5.1f}%")
            if core_lines:
                self._safe_addstr(y, 2, "Per-core usage", curses.A_BOLD)
                y += 1
                cols = max(1, min(len(core_lines), max(1, (width - 4) // 24)))
                rows = (len(core_lines) + cols - 1) // cols
                col_width = max(24, (width - 4) // cols)
                for row in range(rows):
                    for col in range(cols):
                        idx = row + col * rows
                        if idx >= len(core_lines):
                            continue
                        text = core_lines[idx]
                        x = 2 + col * col_width
                        self._safe_addstr(y + row, x, text[: col_width - 2])
                y += rows + 1

            if y < height - 5:
                self._safe_addstr(y, 2, "Top processes", curses.A_BOLD)
                for idx, row in enumerate(procs):
                    if y + 1 + idx >= height - 2:
                        break
                    self._safe_addstr(y + 1 + idx, 2, row[: width - 4])

            self._show_hint("Live monitoring · q=exit")
            self.stdscr.refresh()
            key = self.stdscr.getch()
            if key in (ord("q"), ord("Q"), 27):
                break
        self._show_hint("")
        self.stdscr.timeout(-1)

    def network_interface_manager_flow(self) -> None:
        ensure_command("ip")
        interfaces = self._read_interfaces()
        if not interfaces:
            self.show_status("No interfaces detected.")
            return
        index = 0
        while True:
            self._draw_interface_manager(interfaces, index)
            key = self.stdscr.getch()
            if key in (ord("q"), ord("Q"), 27, curses.KEY_LEFT, ord("h")):
                break
            if key in (curses.KEY_UP, ord("k")):
                index = (index - 1) % len(interfaces)
            elif key in (curses.KEY_DOWN, ord("j")):
                index = (index + 1) % len(interfaces)
            elif key in (ord("u"), ord("U")):
                iface = interfaces[index]["name"]
                confirm = self.prompt_text(
                    f"Type 'yes' to bring {iface} UP",
                    allow_cancel=True,
                )
                if not (confirm and confirm.lower() == "yes"):
                    continue
                self._run_simple_command(
                    network_interface_up_down,
                    f"Bringing {iface} up...",
                    interface=iface,
                    state="up",
                )
                restored = self._restore_interface_ips(iface)
                if not restored:
                    self._run_simple_command(
                        network_interface_request_dhcp,
                        f"Requesting DHCP on {iface}...",
                        interface=iface,
                    )
                interfaces = self._read_interfaces()
            elif key in (ord("d"), ord("D")):
                iface = interfaces[index]["name"]
                confirm = self.prompt_text(
                    f"Type 'yes' to bring {iface} DOWN",
                    allow_cancel=True,
                )
                if not (confirm and confirm.lower() == "yes"):
                    continue
                self._saved_interface_ips[iface] = interfaces[index].get("addr_list", [])
                self._run_simple_command(
                    network_interface_up_down,
                    f"Bringing {iface} down...",
                    interface=iface,
                    state="down",
                )
                interfaces = self._read_interfaces()
            elif key in (ord("a"), ord("A")):
                iface = interfaces[index]["name"]
                cidr = self.prompt_text(f"IP/CIDR to add on {iface}", allow_cancel=True)
                if cidr:
                    self._run_simple_command(
                        network_interface_assign,
                        f"Assigning {cidr} to {iface}...",
                        interface=iface,
                        address=cidr,
                    )
                    interfaces = self._read_interfaces()
            elif key in (ord("r"), ord("R")):
                iface = interfaces[index]["name"]
                cidr = self.prompt_text(f"IP/CIDR to remove from {iface}", allow_cancel=True)
                if cidr:
                    self._run_simple_command(
                        network_interface_remove,
                        f"Removing {cidr} from {iface}...",
                        interface=iface,
                        address=cidr,
                    )
                    interfaces = self._read_interfaces()
            elif key in (ord("g"), ord("G")):
                iface = interfaces[index]["name"]
                self._run_simple_command(
                    network_interface_request_dhcp,
                    f"Requesting DHCP on {iface}...",
                    interface=iface,
                )
                interfaces = self._read_interfaces()
            elif key in (ord("m"), ord("M")):
                iface = interfaces[index]["name"]
                cidr = self.prompt_text(f"Manual IP/CIDR for {iface}", allow_cancel=True)
                if cidr:
                    self._run_simple_command(
                        network_interface_assign,
                        f"Assigning {cidr} to {iface}...",
                        interface=iface,
                        address=cidr,
                    )
                    interfaces = self._read_interfaces()
            elif key in (10, 13):
                iface = interfaces[index]["name"]
                detail = network_interface_show_detail(iface)
                self.show_output(f"{iface} detail", detail, allow_reverse=True)

    def netplan_manager_flow(self) -> None:
        base = Path("/etc/netplan")
        files = sorted(base.glob("*.yaml")) + sorted(base.glob("*.yml"))
        entries = [path for path in files if path.is_file()]
        if not entries:
            self.show_status("No netplan YAML files under /etc/netplan.")
            return
        index = 0
        while True:
            self._draw_netplan_list(entries, index)
            key = self.stdscr.getch()
            if key in (ord("q"), ord("Q"), 27, curses.KEY_LEFT, ord("h")):
                break
            if key in (curses.KEY_UP, ord("k")):
                index = (index - 1) % len(entries)
            elif key in (curses.KEY_DOWN, ord("j")):
                index = (index + 1) % len(entries)
            elif key in (ord("a"), ord("A")):
                self._run_netplan_command(["generate"])
            elif key in (ord("p"), ord("P")):
                self._run_netplan_command(["apply"])
            elif key in (ord("v"), ord("V")):
                path = entries[index]
                content = path.read_text()
                self.show_output(path.name, content or "(empty)", allow_reverse=True)
            elif key in (ord("e"), ord("E")):
                path = entries[index]
                backup = path.read_text()
                updated = self._edit_text(path.name, backup)
                if updated is None:
                    continue
                path.write_text(updated)
                self.show_output("Netplan", f"Saved {path}")
            elif key in (ord("g"), ord("G")):
                self._run_netplan_command(["try"])
            elif key in (ord("n"), ord("N")):
                name = self.prompt_text("New netplan filename (e.g. 50-new.yaml)", allow_cancel=True)
                if not name:
                    continue
                path = base / name
                if path.exists():
                    self.show_status("File already exists.")
                    continue
                path.write_text("# netplan configuration\n")
                entries = sorted(base.glob("*.yaml")) + sorted(base.glob("*.yml"))
                index = entries.index(path)
            elif key in (ord("d"), ord("D")):
                path = entries[index]
                confirm = self.prompt_bool(f"Delete {path.name}?", default=False, allow_cancel=True)
                if confirm:
                    path.unlink()
                    entries = sorted(base.glob("*.yaml")) + sorted(base.glob("*.yml"))
                    if not entries:
                        self.show_status("No netplan files remaining.")
                        return
                    index %= len(entries)

    def _draw_netplan_list(self, entries: List[Path], index: int) -> None:
        height, width = self.stdscr.getmaxyx()
        win_height = min(max(len(entries), 1) + 6, height - 2)
        win_width = min(80, width - 4)
        start_y = max(2, (height - win_height) // 2)
        start_x = max(2, (width - win_width) // 2)
        window = curses.newwin(win_height, win_width, start_y, start_x)
        window.keypad(True)
        window.clear()
        self._box_border(window)
        window.addstr(1, 2, "Netplan configurations", curses.A_BOLD)
        instructions = "↑/↓ select · v view · e edit · n new · d delete · a gen · p apply · g try · q back"
        window.addstr(win_height - 2, 2, instructions[: win_width - 4], self._color(2))
        visible = win_height - 4
        if entries:
            index = max(0, min(index, len(entries) - 1))
            offset = max(0, min(index - visible + 1, max(len(entries) - visible, 0)))
            for i in range(visible):
                pos = offset + i
                if pos >= len(entries):
                    break
                entry = entries[pos]
                label = f"{entry.name:<30} {entry.stat().st_size} bytes"
                attr = curses.A_REVERSE if pos == index else curses.A_NORMAL
                window.addstr(3 + i, 2, label[: win_width - 4], attr)
        else:
            window.addstr(3, 2, "(no netplan files detected)"[: win_width - 4])
        window.refresh()

    def _run_netplan_command(self, args: List[str]) -> None:
        ensure_command("netplan")
        result = run_command(["netplan", *args], capture_output=True, check=False)
        output = result.stdout.strip() or result.stderr.strip() or "(no output)"
        success = result.returncode == 0
        self.show_output(f"netplan {' '.join(args)}", output, success=success, allow_reverse=True)

    def _read_interfaces(self) -> List[Dict[str, Any]]:
        ensure_command("ip")
        result = run_command(["ip", "-json", "address"], capture_output=True, check=False)
        try:
            data = json.loads(result.stdout or "[]")
        except json.JSONDecodeError:
            lines = network_show_interfaces(argparse.Namespace())
            return [
                {"name": line.split()[0], "state": "unknown", "ips": ""}
                for line in (lines or "").splitlines()
            ]
        interfaces = []
        for entry in data:
            name = entry.get("ifname", "?")
            state = entry.get("operstate", "unknown")
            addrs = []
            for addr in entry.get("addr_info", []):
                local = addr.get("local")
                prefix = addr.get("prefixlen")
                if local and prefix is not None:
                    addrs.append(f"{local}/{prefix}")
            interfaces.append({"name": name, "state": state, "ips": ", ".join(addrs) or "(no IPs)", "addr_list": addrs})
        return interfaces

    def _draw_interface_manager(self, interfaces: List[Dict[str, Any]], index: int) -> None:
        height, width = self.stdscr.getmaxyx()
        win_height = min(max(len(interfaces), 1) + 6, height - 2)
        win_width = min(80, width - 4)
        start_y = max(2, (height - win_height) // 2)
        start_x = max(2, (width - win_width) // 2)
        window = curses.newwin(win_height, win_width, start_y, start_x)
        window.keypad(True)
        window.clear()
        self._box_border(window)
        window.addstr(1, 2, "Interface manager", curses.A_BOLD)
        instructions = "↑/↓ select · Enter=detail · u up · d down · a add IP · r remove IP · g dhcp · m manual IP · q back"
        window.addstr(win_height - 2, 2, instructions[: win_width - 4], self._color(2))
        visible = win_height - 4
        if interfaces:
            index = max(0, min(index, len(interfaces) - 1))
            offset = max(0, min(index - visible + 1, max(len(interfaces) - visible, 0)))
            for i in range(visible):
                pos = offset + i
                if pos >= len(interfaces):
                    break
                entry = interfaces[pos]
                label = f"{entry['name']:<10} [{entry['state']:<7}] {entry['ips']}"
                attr = curses.A_REVERSE if pos == index else curses.A_NORMAL
                window.addstr(3 + i, 2, label[: win_width - 4], attr)
        else:
            window.addstr(3, 2, "(no interfaces detected)"[: win_width - 4])
        window.refresh()
        self._show_hint("Interface manager · q=back")

    def _run_simple_command(
        self,
        handler: Callable[[argparse.Namespace], None],
        message: str,
        **kwargs,
    ) -> None:
        self._show_hint(message + " q=cancel")
        success, output = run_action(handler, **kwargs)
        self._show_hint("")
        title = "Sukses" if success else "Gagal"
        body = output or ("Sukses" if success else "Gagal")
        self.show_output(title, body, success=success)

    def _restore_interface_ips(self, iface: str) -> bool:
        addrs = self._saved_interface_ips.pop(iface, [])
        if not addrs:
            return False
        for cidr in addrs:
            self._run_simple_command(
                network_interface_assign,
                f"Restoring {cidr} on {iface}...",
                interface=iface,
                address=cidr,
            )
        return True
    def ftp_add_user_flow(self) -> None:
        username = self.prompt_text("FTP username", allow_cancel=True)
        if username is None:
            return
        home = self.prompt_text(
            "Home directory (leave empty for default)",
            allow_empty=True,
            allow_cancel=True,
        )
        if home is None:
            return
        while True:
            password = self.prompt_text(
                "User password",
                secret=True,
                allow_cancel=True,
            )
            if password is None:
                return
            confirm = self.prompt_text(
                "Confirm password",
                secret=True,
                allow_cancel=True,
            )
            if confirm is None:
                return
            if password != confirm:
                self.show_status("Passwords do not match. Try again.")
                continue
            break
        append_userlist = self.prompt_bool("Add to vsftpd.userlist?", default=True, allow_cancel=True)
        if append_userlist is None:
            return
        self.execute(
            ftp_add_user,
            username=username,
            home=home or None,
            password=password,
            append_userlist=append_userlist,
        )
        self._show_ftp_allowlist_preview()

    def ftp_remove_user_flow(self) -> None:
        username = self.prompt_text("FTP username to remove", allow_cancel=True)
        if username is None:
            return
        remove_home = self.prompt_bool("Remove home directory?", allow_cancel=True)
        if remove_home is None:
            return
        remove_userlist = self.prompt_bool("Remove user from vsftpd.userlist?", allow_cancel=True)
        if remove_userlist is None:
            return
        self.execute(
            ftp_remove_user,
            username=username,
            remove_home=remove_home,
            remove_userlist=remove_userlist,
        )

    def _read_current_ssh_port(self) -> int:
        sshd_config = Path("/etc/ssh/sshd_config")
        if sshd_config.exists():
            for line in sshd_config.read_text().splitlines():
                stripped = line.strip()
                if stripped.startswith("Port "):
                    try:
                        return int(stripped.split()[1])
                    except (ValueError, IndexError):
                        continue
        include_dir = Path("/etc/ssh/sshd_config.d")
        if include_dir.exists():
            for path in sorted(include_dir.glob("*.conf")):
                for line in path.read_text().splitlines():
                    stripped = line.strip()
                    if stripped.startswith("Port "):
                        try:
                            return int(stripped.split()[1])
                        except (ValueError, IndexError):
                            continue
        return 22

    def _section_port_status(self, label: str) -> List[str]:
        if label == "User management":
            port = self._read_current_ssh_port()
            return [f"Current SSH port : {port}", ""]
        if label == "FTP":
            try:
                port = ftp_get_current_port()
                return [f"Current FTP port : {port}", ""]
            except Exception as exc:
                return [f"FTP port status : {exc}", ""]
        return []

    def _handle_mouse_input(
        self,
        menu_items: List[str],
        active: int,
        active_mode: Optional[str],
    ) -> tuple[int, Optional[str], bool, bool]:
        try:
            _, mx, my, _, bstate = curses.getmouse()
        except curses.error:
            return active, active_mode, False, False
        if not (bstate & (curses.BUTTON1_CLICKED | curses.BUTTON1_RELEASED | curses.BUTTON1_PRESSED)):
            return active, active_mode, False, False

        # Sidebar click
        if mx < self._sidebar_width and self._sidebar_top <= my < self._sidebar_top + len(menu_items):
            idx = max(0, min(my - self._sidebar_top, len(menu_items) - 1))
            label = menu_items[idx]
            active = idx
            if label == "Exit":
                return active, active_mode, True, True
            if label == "Dashboard":
                active_mode = None
            else:
                active_mode = label
            return active, active_mode, True, False

        # Action panel click
        meta = self._action_panel_meta
        if active_mode and meta:
            sx = meta["start_x"]
            sy = meta["start_y"]
            width = meta["width"]
            count = meta["count"]
            if sx <= mx < sx + width and sy <= my < sy + count:
                idx = my - sy
                if 0 <= idx < len(meta["operations"]):
                    meta["operations"][idx][1]()
                    return active, active_mode, True, False
        return active, active_mode, False, False


def interactive_main() -> None:
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print("Interactive mode requires running inside a terminal.")
        return
    try:
        curses.wrapper(lambda stdscr: AisyCliTUI(stdscr).run())
    except curses.error as exc:
        print(f"Failed to start interactive interface: {exc}")
    else:
        print("Thanks for using aisy-cli. See you again soon!")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aisy",
        description="Linux administration helper CLI (interactive only).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="(Reserved) No-op placeholder for future simulation mode.",
    )
    return parser


def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.dry_run:
        print("Dry run is not yet implemented.")
        return

    interactive_main()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
