# Live demo: process and port inventory

This demonstration uses only a disposable Linux VM you own or are authorized to use. Keep the VM's network adapter disconnected or host-only. The test web server binds to loopback (`127.0.0.1`), so it is not exposed to the LAN.

## Before the presentation

1. Copy `auditor.py` into the Linux VM (for example, using a shared folder).
2. Open a terminal in the folder containing it. Check availability:

   ```bash
   python3 --version
   command -v ps ss
   command -v lsof || true
   ```

   On an Ubuntu/Debian lab VM, if tools are missing, install only the standard utilities:

   ```bash
   sudo apt update
   sudo apt install python3 procps iproute2 lsof
   ```

3. Keep two terminals open in that folder. Run as a normal user; do not use `sudo` for the auditor.

## Presentation sequence

### 1. Baseline

In Terminal 1:

```bash
python3 auditor.py
```

Point out the process count and the TCP/UDP listening endpoints. Explain that these are the tools' current view, not a definitive security verdict.

### 2. Start a harmless local listener

In Terminal 2:

```bash
python3 -m http.server 8765 --bind 127.0.0.1
```

Leave it running. This serves files from the current directory to loopback only. Do not open it to the network.

### 3. Observe the change

Back in Terminal 1:

```bash
python3 auditor.py
```

Show the new Python process in the process count and `TCP 127.0.0.1:8765` in the `ss` inventory. If `lsof` is installed and has sufficient visibility, its TCP listener list should include port `8765` too.

### 4. Stop and confirm

Press **Ctrl+C** in Terminal 2, then run the auditor again in Terminal 1. The test listener should no longer appear. A process count can change between snapshots because operating system processes start and exit normally.

## What to say about findings

- The program cross-checks process IDs from `/proc` and `ps`, then compares TCP listener ports from `ss` and `lsof` when available.
- A mismatch is a prompt for manual review, not proof of a hidden process or rootkit. Permissions, namespaces, process timing, and differences between utilities can explain it.
- This demonstrates user-space inventory only. It does not install or emulate a rootkit, inspect kernel integrity, or guarantee that a system is clean.
- The tool is read-only and performs no remediation.

## Short viva answers

**Why compare multiple tools?** Independent views can reveal an enumeration discrepancy worth checking.

**Does a matching result prove there is no rootkit?** No. These are user-space tools and can share blind spots; the comparison is not proof of absence.

**Why use loopback?** `127.0.0.1` limits the demo service to the VM itself and avoids exposing it to the campus or other networks.

**Why can results vary between runs?** Process and socket state changes continuously, and permissions or namespaces can affect what each utility sees.

## If the `lsof` comparison is skipped

The auditor reports that `lsof` is unavailable or lacks permission. You can still demonstrate the `ss` listener and process inventory. Do not elevate privileges just to force matching output.
