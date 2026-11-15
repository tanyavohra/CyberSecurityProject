#!/usr/bin/env python3
"""Read-only Linux process and listening-port cross-checker for isolated labs."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path


def run(command: list[str]) -> str | None:
    """Run an installed inventory utility; return None when unavailable/failing."""
    try:
        result = subprocess.run(command, text=True, capture_output=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return result.stdout if result.returncode == 0 else None


def proc_processes(proc_root: Path = Path("/proc")) -> dict[int, str]:
    found: dict[int, str] = {}
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return found
    for entry in entries:
        if not entry.name.isdecimal():
            continue
        try:
            name = (entry / "comm").read_text(errors="replace").strip()
        except OSError:
            continue  # Process exited or access was restricted during the snapshot.
        found[int(entry.name)] = name or "?"
    return found


def ps_processes() -> dict[int, str] | None:
    output = run(["ps", "-e", "-o", "pid=,comm="])
    if output is None:
        return None
    result: dict[int, str] = {}
    for line in output.splitlines():
        match = re.match(r"\s*(\d+)\s+(.*)$", line)
        if match:
            result[int(match.group(1))] = match.group(2).strip()
    return result


def socket_inventory() -> tuple[set[tuple[str, str]], set[tuple[str, str]]]:
    """Return TCP/UDP listening endpoints from ss (TCP, UDP)."""
    output = run(["ss", "-H", "-lntu"])
    tcp: set[tuple[str, str]] = set()
    udp: set[tuple[str, str]] = set()
    if output is None:
        return tcp, udp
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        protocol, local = fields[0].lower(), fields[4]
        # Bracketed IPv6 and IPv4 wildcard endpoints both end in :port.
        host, sep, port = local.rpartition(":")
        if not sep:
            continue
        endpoint = (host.strip("[]") or "*", port)
        (tcp if protocol.startswith("tcp") else udp).add(endpoint)
    return tcp, udp


def lsof_listeners() -> set[tuple[str, str]] | None:
    output = run(["lsof", "-nP", "-i", "-sTCP:LISTEN"])
    if output is None:
        return None
    endpoints: set[tuple[str, str]] = set()
    for line in output.splitlines()[1:]:
        # Typical NAME: TCP *:22 (LISTEN), [::1]:8000 (LISTEN)
        match = re.search(r"(?:\*|\[[^]]+\]|[^\s:]+):(\d+)\s+\(LISTEN\)", line)
        if match:
            endpoints.add(("*", match.group(1)))
    return endpoints


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--proc", default="/proc", help="procfs path (for isolated fixtures)")
    args = parser.parse_args()
    if not sys.platform.startswith("linux"):
        parser.error("This auditor requires Linux and procfs.")

    print("Linux Hidden Process & Port Auditor")
    print("Read-only snapshot; findings are leads for manual review, not proof of a rootkit.\n")
    proc = proc_processes(Path(args.proc))
    ps = ps_processes()
    print(f"Processes visible in {args.proc}: {len(proc)}")
    if ps is None:
        print("[INFO] ps unavailable; process cross-check skipped.")
    else:
        proc_only, ps_only = sorted(proc.keys() - ps.keys()), sorted(ps.keys() - proc.keys())
        if not proc_only and not ps_only:
            print("[OK] /proc and ps report the same process IDs.")
        for pid in proc_only:
            print(f"[REVIEW] PID {pid} appears in procfs but not ps ({proc[pid]!r}).")
        for pid in ps_only:
            print(f"[REVIEW] PID {pid} appears in ps but not procfs ({ps[pid]!r}).")

    if shutil.which("ss") is None:
        print("\n[INFO] ss unavailable; port inventory skipped.")
        return 0
    tcp, udp = socket_inventory()
    print(f"\nListening endpoints from ss: TCP {len(tcp)}, UDP {len(udp)}")
    for proto, endpoints in (("TCP", tcp), ("UDP", udp)):
        for host, port in sorted(endpoints):
            print(f"  {proto} {host}:{port}")
    lsof = lsof_listeners() if shutil.which("lsof") else None
    if lsof is None:
        print("[INFO] lsof unavailable or lacked permission; TCP cross-check skipped.")
    else:
        ss_tcp_ports = {port for _, port in tcp}
        lsof_ports = {port for _, port in lsof}
        for port in sorted(ss_tcp_ports - lsof_ports, key=int):
            print(f"[REVIEW] TCP port {port} appears in ss but not lsof.")
        for port in sorted(lsof_ports - ss_tcp_ports, key=int):
            print(f"[REVIEW] TCP port {port} appears in lsof but not ss.")
        if ss_tcp_ports == lsof_ports:
            print("[OK] ss and lsof report the same TCP listening ports.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
