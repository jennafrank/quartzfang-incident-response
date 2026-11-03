# Gaps G1 to G11

Source: section 04 of the v4.0 report. These are the things the logs could not show. They are why the findings say "requested" or "attempted" rather than "stolen" or "sent". The fixes are in section 14 of the report (recommendation 7 covers G2, G3 and part of G1).

| Gap | Not visible | What that means for the findings | Owner |
|---|---|---|---|
| G1 | What the portal, database, build store and admin platform sent back | We know what was asked for, not what was handed over | Platform |
| G2 | Data volume and web address of connections | Upload completion and size unproven | Network |
| G3 | The data store (Redis) writing the scheduled task | That step is inferred from the attack request and timing | Platform |
| G4 | Command output (e.g. `env`, which lists stored settings) | Other exposed passwords cannot be ruled out | Security engineering |
| G5 | File reads; no writes to staging folder `.portal-cache` logged 06:52 to 08:02:05 (A-21) | Bundle contents unknown | Security engineering |
| G6 | The portal application's own internal connections | Only the attacker's internal connections are visible; app internet traffic is (A-33) | Security engineering |
| G7 | A connection record for the 07:43:01 database login | Burst 2 is linked by pattern, not a direct trace | Security engineering |
| G8 | Logins other than SSH | "No attacker login" covers SSH only | Identity |
| G9 | Contents of `/etc/semicrest/portal.conf` | A "file changed" record at 07:05:16 may be a read or a change (AH-10) | Security engineering |
| G10 | A separate shell process for the remote session | Commands appear under PID 4401 (A-38); likely a logging quirk | Security engineering |
| G11 | Anything before 2026-09-19 00:00 UTC | Earlier probing not examined | SOC |

## Where each gap bites

- **G1** is why F5, F6 and F7 describe requests, not data taken. Customer contacts and password hashes were requested. Whether they were returned is not logged.
- **G2 and G5** are why F8 says the upload was attempted. A connection to 198.51.100[.]210 opened at 08:15:08. How much was sent, whether it was accepted, and what the bundle held are unknown.
- **G3** is why F3 says the scheduled task was "most likely" planted. The request, the single cron run and the timing support it; the write itself is not logged.
- **G4 and G9** are why the settings file is the Medium-confidence source of the stolen passwords in F4.
- **G7** is why burst 2 in F5 is Medium. It matches burst 1 by pattern and timing, with no connection record tying it to PID 4401.
- **G8** limits F9 and N-04: no login by `svc_monitor` was seen, but only SSH logins are visible.
- **G11** limits the whole timeline: nothing before 19 September was examined.
