# Linux Hidden Process & Port Auditor

Mini project for **Cyber Security Lab (7CS4-22), Experiment 5 – Rootkits & System Integrity**.

This read-only command-line tool cross-checks the process IDs visible through `/proc` against `ps`, and TCP listening ports reported by `ss` against `lsof`. It is intended to help students understand how user-space enumeration can disagree. A mismatch is a lead for investigation, not evidence that a rootkit is present. Normal process exit timing, permissions, namespaces, and tool differences can all cause mismatches. This is not a kernel integrity checker and cannot guarantee detection of rootkits.

## Ethical and legal scope

- Run only on a machine, VM, Docker container, or isolated lab network that you own or are authorized to use.
- Do not run demonstrations on college networks, public Wi-Fi, websites, or other people's devices.
- Use test accounts and dummy data. No real passwords, personal data, or user accounts are needed.
- This project does not install, hide, or execute a rootkit, alter processes, scan networks, or change firewall or system settings. Do not download or run live malware. For any separate safe-sample exercise, use only the instructor-approved EICAR test file.
- Include the signed Ethical Declaration supplied with the report front-page template. Misuse is the student's responsibility; the lab brief cites Sections 43 and 66 of the Information Technology Act, 2000.

## Requirements

- Linux with Python 3.10 or newer
- `ps` (usually from procps)
- `ss` (usually from iproute2)
- Optional: `lsof`

No third-party Python packages are required. Run as a normal user first; elevated access is not required for the basic comparison. Permissions may limit visibility.

## Run

```bash
python3 auditor.py
```

To check command options:

```bash
python3 auditor.py --help
```

The output shows a point-in-time snapshot. Re-run it and investigate any `[REVIEW]` line using trusted system utilities and instructor guidance. The auditor performs no remediation.

## Suggested isolated demo

Follow the step-by-step [live demo guide](LIVE_DEMO.md). It uses Python's built-in HTTP server bound to `127.0.0.1` on port `8765`, so the demo listener stays local to the Linux VM.

Do not bind the demo service to a public interface or forward its port outside the isolated lab.

## Report and submission

Suggested report sections: objective, ethical scope, requirements, method, screenshots/output from the isolated demo, findings and limitations, conclusion, source listing, and signed Ethical Declaration. Use the supplied front page and follow the lab brief's required hard-copy/PDF/source-ZIP naming convention: `RollNo_Name_ProjectCode`. Add the GitHub link as required, then prepare for the live demo and viva. Do not include passwords, personal data, or real account details in the report.

## Implementation notes

- `/proc/<pid>/comm` supplies process names; inaccessible or already-exited entries are skipped.
- `ps -e -o pid=,comm=` provides the second process listing.
- `ss -H -lntu` inventories listening TCP and UDP endpoints.
- `lsof -nP -i -sTCP:LISTEN` supplies an optional TCP comparison.
- Only inventory commands are run. The program does not inspect or modify executable memory, hide activity, or alter the host.
