# MITRE ATT&CK mapping

Source: section 07 and Appendix C of the v4.0 report. ATT&CK Enterprise, accessed 2026-10-31.

The core chain (section 07): T1190, T1053.003, T1078, T1213.006, T1048.002 (attempted), T1136.001.

## Observed

Each technique below is supported by a finding.

| Tactic | Technique (ID) | Finding |
|---|---|---|
| Reconnaissance | Active Scanning: Wordlist Scanning (T1595.003) | F1 |
| Initial Access | Exploit Public-Facing Application (T1190) | F2, F3 |
| Execution | Scheduled Task/Job: Cron, one run observed (T1053.003) | F3 |
| Execution | Command and Scripting Interpreter: Python (T1059.006) | F3 |
| Command and Control | Non-Application Layer Protocol (T1095) | F3 |
| Discovery | File and Directory Discovery (T1083) | F4 |
| Defense Evasion | Valid Accounts (T1078) | F5 to F7 |
| Collection | Data from Information Repositories: Databases (T1213.006) | F5 |
| Collection | Data Staged: Local Data Staging (T1074.001) | F8 |
| Collection | Archive Collected Data: Archive via Utility (T1560.001) | F8 |
| Exfiltration (attempted) | Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Non-C2 Protocol (T1048.002) | F8 |
| Persistence | Create Account: Local Account (T1136.001) | F9 |

## Inferred

These rest on inference, not a direct record.

| Technique (ID) | Basis | Confidence | Finding |
|---|---|---|---|
| Non-Standard Port (T1571) | Raw socket on 443, from the payload | Not stated | F3 |
| Unsecured Credentials: Credentials In Files (T1552.001) | Settings file displayed; command output not logged (G4) | Medium | F4 |
| Obtain Capabilities: Artificial Intelligence (T1588.007) | From the separate agent log | Medium | F10 |

## Mapping notes

- **T1048.002**: an HTTPS upload to a dedicated endpoint, distinct from the raw-socket C2 channel. No web-service platform was established. The upload is attempted; delivery is unproven (F8, G2).
- **Not mapped: T1098.004** (SSH authorized keys). No key registration was logged (N-10).
- **Not mapped: Lateral Movement.** The stolen-password logins establish nothing beyond T1078.

## Detection coverage

| Rule | Technique |
|---|---|
| C-D1 | T1190 |
| C-D2 | T1053.003, T1059.006 |
| C-D3 | T1136.001 |
| C-D4 | T1213.006 |
| C-D5 | T1078 |

C-D6 (archive, encrypt, upload) is proposed in recommendation 6 but not built or tested.
