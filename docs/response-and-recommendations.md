---
title: "Operation QUARTZFANG: Impact, Root Cause and Response"
---

# Operation QUARTZFANG: Impact, Root Cause and Response

> Sections 08 to 14 of the *QUARTZFANG Incident Response Report*, version 5.0 (public edition, TLP:CLEAR), by Jenna Frank, converted from the [PDF](https://github.com/jennafrank/quartzfang-incident-response/blob/main/report/QUARTZFANG_IR_Report_JennaFrank_v5.0_public.pdf) (pages 8 to 10) without rewording. Indicators are defanged.
>
> **Status of the response sections:** the report is based on an investigation of the supplied logs. No containment, eradication or recovery has been carried out. The response sections are recommendations.
>
> References: F1 to F10 are findings ([findings.md](https://github.com/jennafrank/quartzfang-incident-response/blob/main/investigation/findings.md)), G1 to G13 are evidence gaps ([gaps.md](https://github.com/jennafrank/quartzfang-incident-response/blob/main/investigation/gaps.md)), A-01 to A-49 are [hunting queries](https://github.com/jennafrank/quartzfang-incident-response/tree/main/hunting-queries), C-D1 to C-D5 are [detections](https://github.com/jennafrank/quartzfang-incident-response/tree/main/detections), and N and R refer to the registers in the report's Appendix B ([what I ruled out](https://github.com/jennafrank/quartzfang-incident-response/blob/main/investigation/what-i-ruled-out.md)).
>
> [Back to the project page](index.md)

## 08 Impact, Dwell Time and Containment

| | |
|---|---|
| **Reconnaissance undetected** | About 22 minutes. Scanning began at 06:30:00 (F1) and nothing fired on it. Scanning is low-priority on its own, but it was this attack's first signal. |
| **Dwell time (intrusion to detection)** | About 12 seconds or less: the exploit landed at 06:52:48 and the alert fired in the same minute. The alert's exact timestamp would confirm this, but the record is not in the data (G12). |
| **Time to containment** | Not contained. Attacker activity runs 06:52:48 to 08:30:00 UTC, about 97 minutes after the alert, and the end of access is unknown. |
| **What the attacker reached** | The portal settings file (contents not recorded, G9) and the database, build store and admin platform requests in F5 to F7. What came back is not logged (G1). |
| **Confirmed compromise** | Two service passwords were obtained and reused (F4, high confidence). |
| **Unconfirmed disclosure** | Customer data. The database responses and archive contents were not captured, and delivery of the 08:15 upload to `198.51.100[.]210` is unproven (F8). |
| **Business impact** | Treat customer contact details and portal password hashes as possibly in the attacker's hands, along with `pg_shadow` login details. Presume it knows two production service passwords. Changing every database password is a precaution, not proof each was taken. No outage is shown (R-03). |

## 09 Root Cause

The root cause is that **the preview feature failed to stop an attacker-controlled request aimed at an internal service**. The request carried instructions to plant a scheduled task through Redis, and administrator-level execution followed within seconds (F2, F3). The file write is inferred from that sequence. Redis's configuration was not available.

| # | Contributing factor | Effect |
|---|---|---|
| C1 | Redis could be made to save data into root's scheduled-task folder (inferred) | A web flaw becomes full control of the server |
| C2 | Database and build store passwords sit on the portal, likely in plain text in the settings file | One server opens three more |
| C3 | The same service account (`portal_svc`) works on both the database and the admin platform | One stolen password crosses system boundaries (F5, F7) |
| C4 | Both attacker destinations were reachable on port 443 with no outbound filtering evident | Nothing blocked the remote session or the upload |
| C5 | No response to the 06:52 alert, and no later detection, appears in the data | Attacker activity continued for about 97 minutes |

## 10 Indicators of Compromise

Behaviors first, because addresses change quickly. Not indicators: the times, counts and scan list, which are measurements of this run.

| Type | Indicator (defanged) | Context | Confidence |
|---|---|---|---|
| Behavior | Preview request with a non-http(s) format or a self-pointing address | Break-in (C-D1) | High |
| Behavior | Python started by a scheduled task, opening a connection and shell | Remote control (C-D2) | High |
| Behavior | Whole-table, `pg_shadow` or table-list queries on sc-db01 in seconds | DB searching (C-D4) | High |
| Behavior | Build-server account used from anywhere but the build server | Password reuse (C-D5) | High |
| IPv4 | `203.0.113[.]87` | Break-in source; remote control (443) | High |
| IPv4 | `198.51.100[.]210` | Upload destination (`/upload`, 443) | High |
| IPv4 | `198.51.100[.]31`, `[.]45`, `[.]62` | Scanning addresses | High |
| HTTP header | `X-Session: qf-c062-9e4a` | In the upload command; may change per session | Moderate |
| Account | `svc_monitor` (`sudo` group) | Attacker-created account on the portal | High |
| File | `/tmp/.portal-cache/report.tar.gz.enc`; `/home/svc_monitor/.ssh/id_ed25519` | Encrypted archive; login key with no passphrase (hashes not acquired) | High |

## 11 Containment

Recommended, not yet carried out. Containment stops the attacker, eradication removes what it left, recovery restores the portal.

| # | Action | Risk if not done |
|---|---|---|
| 1 | Isolate sc-portal01 now; capture memory if it causes no delay, then copy the disk | Attacker keeps control; memory-only evidence is lost |
| 2 | Stop the attacker's process (PID 4401) and everything it started | The remote session stays open if isolation is delayed |
| 3 | Block `203.0.113[.]87` and `198.51.100[.]210` at the firewall | Other servers can still reach both addresses |
| 4 | Disable `svc_monitor` | The attacker keeps an account in the administrators group |
| 5 | Block the preview feature (`/api/v1/preview`) at the edge | The same request works again on restore |

**The obvious move and why it fails.** Disabling `portal_svc` breaks the portal and leaves the remote session and the attacker's account in place. Isolate first.

## 12 Eradication

| # | Action | Risk if not done |
|---|---|---|
| 1 | Delete `svc_monitor` and its keys; check every `authorized_keys` file | An unlogged key stays usable (F9) |
| 2 | Check `/var/spool/cron/root` and all scheduled tasks | The planted task may still run (A-20, G3) |
| 3 | Hash, then remove `/tmp/.portal-cache/` | The attacker's staged archive stays on disk (F8) |

## 13 Recovery

| # | Action | How to verify it worked |
|---|---|---|
| 1 | Rebuild the portal from a known-clean (trusted) image, or record why not | Passes integrity checks |
| 2 | Change `portal_svc`, `ci-builder` and database passwords; reset user passwords (F5) | Old passwords fail |

**Ready to trust again when:** no unknown accounts, keys or scheduled tasks remain, the preview fix passes a live test, stolen passwords are changed, detections are live and the notification review is underway. None of this is done yet.

## 14 Recommendations

In priority order.

| # | Recommendation | Risk if not done | Addresses |
|---|---|---|---|
| 1 | Preview: allow only `http`/`https`, block internal addresses after name lookup, retest | One request gives root again | Root cause · F2 |
| 2 | Redis: block the app's config and save commands; deny it write access to `/var/spool/cron` | Any request reaching Redis can write system files | C1 · F3 |
| 3 | Route the alert and C-D1 to C-D5 to an on-call responder; verify test events reach them | Alerts fire and nobody acts | C5 |
| 4 | Move service passwords into a secrets vault, one account per service | One server keeps exposing passwords for others | C2, C3 · F4, F7 |
| 5 | Let the portal connect out only to the services it needs | Remote control and uploads leave freely | C4 · F3, F8 |
| 6 | Tune C-D4 and C-D5 on 30 days of data; build C-D6 (archive, encrypt, upload) | Noise hides alerts; staging stays unseen | F5, F6, F8 |
| 7 | Log Redis commands, cron changes, transfer sizes and script content | What was taken still cannot be proven | G1 to G3, G13 |
