---
title: "Operation QUARTZFANG: Impact, Root Cause and Response"
---

# Operation QUARTZFANG: Impact, Root Cause and Response

> Sections 08 to 14 of the *QUARTZFANG Incident Response Report*, version 4.0 (TLP:CLEAR), by Jenna Frank, converted from the [PDF](https://github.com/jennafrank/quartzfang-incident-response/blob/main/report/QUARTZFANG_IR_Report_JennaFrank_v4.0.pdf) (pages 8 to 10) without rewording. Indicators are defanged.
>
> **Status of the response sections:** the report is based on an investigation of the supplied logs. No containment, eradication or recovery has been carried out; the response sections are proposed.
>
> References: F1 to F10 are findings ([findings.md](https://github.com/jennafrank/quartzfang-incident-response/blob/main/investigation/findings.md)), G1 to G9 are evidence gaps ([gaps.md](https://github.com/jennafrank/quartzfang-incident-response/blob/main/investigation/gaps.md)), A-01 to A-49 are [hunting queries](https://github.com/jennafrank/quartzfang-incident-response/tree/main/hunting-queries), C-D1 to C-D5 are [detections](https://github.com/jennafrank/quartzfang-incident-response/tree/main/detections), and AH, N and R refer to the registers in the report's Appendix B.
>
> [Back to the project page](index.md)

## 08 Impact and Dwell Time

| | |
|---|---|
| **First activity · first alert (UTC)** | 2026-09-20 06:30:00 scan (F1) · 06:52, known only to the minute (case brief) |
| **Time to detection** | About 22 minutes from first scan to alert. The break-in (06:52:48) falls in the alert minute, so a precise compromise-to-detection time cannot be given. |
| **Time to containment** | Not contained. Activity after the break-in runs 06:52:48 to 08:30:00 UTC, about 97 minutes; total dwell time is unknown because containment and removal of access are not evidenced. |
| **What the attacker reached** | The portal settings file (contents not recorded, G9) and the database, build store and admin platform requests in F5 to F7. What came back is not logged (G1). |
| **Confirmed compromise and unconfirmed disclosure** | Two service passwords were obtained and reused (F4, High). Customer-data disclosure is unconfirmed: the database responses and archive contents were not captured, and delivery of the attempted upload to `198.51.100[.]210` at 08:15 is unproven (F8). |
| **Business impact** | Treat customer contact details and portal users' password hashes as possibly in the attacker's hands. It also queried `pg_shadow`, which holds database login details and stored password-verification values; the results were not captured. Presume it knows two production service passwords; changing every database password is a precaution, not proof each was taken. No outage is shown (R-03). |

## 09 Root Cause

The root cause is that **the preview feature failed to stop an attacker-controlled request aimed at an internal service**. The request carried instructions to plant a scheduled task through Redis, followed within seconds by administrator-level execution (F2, F3). The file write is inferred from that sequence; Redis's configuration was not available.

| # | Contributing factor | Effect |
|---|---|---|
| C1 | Redis could be made to save its data into root's scheduled-task folder (inferred from the outcome) | A web flaw becomes full control of the server |
| C2 | Database and build store passwords are kept on the portal, suspected in plain text in the settings file | One server opens three more |
| C3 | The same service account (`portal_svc`) works on both the database and the admin platform | One stolen password crosses system boundaries (F5, F7) |
| C4 | Both observed attacker destinations were reachable on port 443; no outbound filtering is evident for them | Nothing blocked the remote session or the upload |
| C5 | No response to the 06:52 alert, and no later detection, appears in the data | Attacker activity continued for about 97 minutes |

## 10 Indicators of Compromise

Behaviours first, because addresses change quickly. Not indicators: the times, counts and scan list, which are measurements of this run.

| Type | Indicator (defanged) | Context | Confidence |
|---|---|---|---|
| Behaviour | Preview request with a non-http(s) format or a self-pointing address | Break-in (C-D1) | High |
| Behaviour | Python started by a scheduled task, opening a connection and shell | Remote control (C-D2) | High |
| Behaviour | Whole-table, `pg_shadow` or table-list queries on sc-db01 in seconds | DB searching (C-D4) | High |
| Behaviour | Build-server account used from anywhere but the build server | Password reuse (C-D5) | High |
| IPv4 | `203.0.113[.]87` | Break-in source; remote control (443) | High |
| IPv4 | `198.51.100[.]210` | Upload destination (`/upload`, 443) | High |
| IPv4 | `198.51.100[.]31`, `[.]45`, `[.]62` | Scanning addresses | High |
| HTTP header | `X-Session: qf-c062-9e4a` | In the upload command; may change per session | Medium |
| Account | `svc_monitor` (`sudo` group) | Attacker-created account on the portal | High |
| File | `/tmp/.portal-cache/report.tar.gz.enc`; `/home/svc_monitor/.ssh/id_ed25519` | Encrypted bundle; passphrase-less login key. File hashes not acquired. | High |

## 11 Containment

Proposed; not yet carried out. Containment stops the attacker, eradication removes what it left, recovery restores the portal and verifies it meets the documented return-to-service checks. Root-cause fixes are recommendations 1 and 2.

| # | Action | Why | Owner |
|---|---|---|---|
| 1 | Isolate sc-portal01 now; capture memory if it causes no delay, then copy the disk | Stops the attacker without losing evidence that exists only while the server runs (G5) | SOC |
| 2 | Stop the attacker's program (PID 4401) and everything it started | Ends the remote session if isolation is delayed | SOC |
| 3 | Block `203.0.113[.]87` and `198.51.100[.]210` at the firewall | Cuts the remote session and upload address for every server | Network |
| 4 | Disable `svc_monitor` | Blocks use of the attacker-created account | Platform |
| 5 | Block the preview feature (`/api/v1/preview`) at the edge | Stops a repeat break-in when the portal is restored | Application owner |

**The obvious move and why it fails.** Disabling `portal_svc` breaks the portal and leaves the remote session and attacker-created account in place. Changing passwords while the attacker controls the server risks exposing the replacements. Isolate first.

## 12 Eradication

| # | Action | Why | Owner |
|---|---|---|---|
| 1 | Delete `svc_monitor` and keys; check all `authorized_keys` | Unlogged key additions possible (F9) | Platform |
| 2 | Check `/var/spool/cron/root` and all scheduled tasks | Ran once (A-20); file state unlogged (G3) | Platform |
| 3 | Hash, then remove `/tmp/.portal-cache/` | Attacker's working folder (F8) | SOC |

## 13 Recovery

| # | Action | How we know it worked | Owner |
|---|---|---|---|
| 1 | Rebuild the portal from a known-clean copy (trusted image); if kept, record why and how integrity was verified | Passes configuration and software integrity checks | Platform |
| 2 | Change `portal_svc`, `ci-builder` and all database role passwords; reset portal user passwords (hashes requested, F5) | Old passwords fail; no unexpected logins from `10.5.0.10` | Platform, App owner |

**Ready to trust again when:** no unknown accounts, keys or scheduled tasks; the preview fix passes a live test; stolen passwords changed; detections live; legal review of whether notification is required underway. None of this is done yet.

## 14 Recommendations

| # | Recommendation | Addresses | Priority | Owner |
|---|---|---|---|---|
| 1 | Preview feature: allow only `http`/`https`; block internal and self-pointing addresses after name lookup; verify with a live test of the attack request | Root cause · F2 | P1 | App owner |
| 2 | Restrict Redis: block the application's configuration and save commands; run it as an account that cannot write `/var/spool/cron` | C1 · F3 | P1 | Platform |
| 3 | Route the existing alert and C-D1 to C-D5 to an on-call responder; verify that test events trigger alerts and reach the responder; investigate every alert for 30 days | C5 | P1 | SOC |
| 4 | Move service passwords into a secrets vault; one account per service | C2, C3 · F4, F7 | P1 | Platform |
| 5 | Let the portal connect out only to the outside services it needs | C4 · F3, F8 | P2 | Network |
| 6 | Tune C-D4, C-D5 on 30 days of data; build and test C-D6 (archive, encrypt, upload) | F5, F6, F8 | P2 | Detection eng. |
| 7 | Log Redis commands and cron changes; record outbound and reply sizes | G2, G3; G1 in part | P2 | Platform, Network |
