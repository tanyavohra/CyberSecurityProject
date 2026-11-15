#!/usr/bin/env python3
"""Compare process and listening-port information from Linux tools."""

import re
import subprocess
import os


def get_processes_from_proc():
    processes = {}
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            file = open("/proc/" + entry + "/comm")
            processes[int(entry)] = file.read().strip()
            file.close()
    return processes


def get_processes_from_ps():
    output = subprocess.run(
        ["ps", "-e", "-o", "pid=,comm="], capture_output=True, text=True
    ).stdout
    processes = {}
    for line in output.splitlines():
        match = re.match(r"\s*(\d+)\s+(.*)", line)
        if match:
            processes[int(match.group(1))] = match.group(2).strip()
    return processes


def get_ports_from_ss():
    output = subprocess.run(
        ["ss", "-H", "-lntu"], capture_output=True, text=True
    ).stdout
    tcp_ports = set()
    udp_ports = set()

    for line in output.splitlines():
        fields = line.split()
        protocol = fields[0].lower()
        address = fields[4]
        host, port = address.rsplit(":", 1)
        endpoint = (host.strip("[]") or "*", port)
        if protocol.startswith("tcp"):
            tcp_ports.add(endpoint)
        else:
            udp_ports.add(endpoint)
    return tcp_ports, udp_ports


def get_ports_from_lsof():
    output = subprocess.run(
        ["lsof", "-nP", "-i", "-sTCP:LISTEN"], capture_output=True, text=True
    ).stdout
    ports = set()
    for line in output.splitlines()[1:]:
        match = re.search(r"(?:\*|\[[^]]+\]|[^\s:]+):(\d+)\s+\(LISTEN\)", line)
        if match:
            ports.add(match.group(1))
    return ports


def main():
    print("Read-only snapshot; findings are leads for manual review, not proof of a rootkit.\n")

    proc_processes = get_processes_from_proc()
    ps_processes = get_processes_from_ps()
    print(f"Processes visible in /proc: {len(proc_processes)}")

    proc_only = proc_processes.keys() - ps_processes.keys()
    ps_only = ps_processes.keys() - proc_processes.keys()
    if not proc_only and not ps_only:
        print("[OK] /proc and ps report the same process IDs.")
    for pid in sorted(proc_only):
        print(f"[REVIEW] PID {pid} appears in procfs but not ps ({proc_processes[pid]!r}).")
    for pid in sorted(ps_only):
        print(f"[REVIEW] PID {pid} appears in ps but not procfs ({ps_processes[pid]!r}).")

    tcp_ports, udp_ports = get_ports_from_ss()
    print(f"\nListening endpoints from ss: TCP {len(tcp_ports)}, UDP {len(udp_ports)}")
    for protocol, endpoints in (("TCP", tcp_ports), ("UDP", udp_ports)):
        for host, port in sorted(endpoints):
            print(f"  {protocol} {host}:{port}")

    lsof_ports = get_ports_from_lsof()
    ss_tcp_ports = {port for host, port in tcp_ports}
    for port in sorted(ss_tcp_ports - lsof_ports, key=int):
        print(f"[REVIEW] TCP port {port} appears in ss but not lsof.")
    for port in sorted(lsof_ports - ss_tcp_ports, key=int):
        print(f"[REVIEW] TCP port {port} appears in lsof but not ss.")
    if ss_tcp_ports == lsof_ports:
        print("[OK] ss and lsof report the same TCP listening ports.")


if __name__ == "__main__":
    main()
