# Gaps G1 to G13

Source: section 04 of the v5.0 report. These are the things the logs could not show. They are why the findings say "requested" or "attempted" rather than "stolen" or "sent". Recommendation 7 in section 14 of the report addresses G1 to G3 and G13.

| Gap | Not visible | What that means for the findings |
|---|---|---|
| G1 | What the portal, database, build store and admin platform sent back | I know what was requested, not what was handed over |
| G2 | Data volume and web address of connections | Upload completion and size are unproven |
| G3 | Redis writing the scheduled task | That step is inferred from the request and the timing |
| G4 | Command output (for example `env`, which lists stored settings) | Other exposed passwords cannot be ruled out |
| G5 | File reads; no writes to the staging folder `.portal-cache` were logged 06:52 to 08:02:05 (A-21) | The archive's contents are unknown |
| G6 | The portal application's own internal connections | Only the attacker's are visible. Sensors often cap events per long-running process, which may explain it (app internet traffic is visible, A-33) |
| G7 | A connection record for the 07:43:01 database login | Burst 2 is linked by pattern, not a direct trace |
| G8 | Logins other than SSH | "No attacker login" covers SSH only |
| G9 | Contents of `/etc/semicrest/portal.conf` | A "file changed" record at 07:05:16 may be a read or a change (AH-10) |
| G10 | A separate shell process for the remote session | Commands appear directly under PID 4401 (A-38). This is most likely how the sensor records them |
| G11 | Anything before 2026-09-19 00:00 UTC | Earlier probing was not examined |
| G12 | The alert record and its exact timestamp | Detection time is known only to the minute |
| G13 | Script content inside PID 4401 | Actions the Python code took without starting a process (such as direct file reads) leave no record |

## Where each gap bites

- **G1** is why F5, F6 and F7 describe requests, not data taken. Customer contacts and password hashes were requested. Whether they were returned is not logged.
- **G2 and G5** are why F8 says the upload was attempted. A connection to 198.51.100[.]210 opened at 08:15:08. How much was sent, whether it was accepted, and what the archive held are unknown.
- **G3** is why F3 says the request "almost certainly" planted the scheduled task. The request, the single cron run and the timing support it; the write itself is not logged.
- **G4 and G9** are why the settings file is the likely source of the stolen passwords in F4, a moderate-confidence judgment.
- **G7** is why burst 2 in F5 is assessed as very likely the attacker's, with moderate confidence. It matches burst 1 by pattern and timing, with no connection record tying it to PID 4401.
- **G8** limits F9 and N-04: no login by `svc_monitor` was seen, but only SSH logins are visible.
- **G11** limits the whole timeline: nothing before 19 September was examined.
- **G12** is why dwell time (intrusion to detection) is given as about 12 seconds or less. The exploit landed at 06:52:48 and the alert fired in the same minute; the alert's exact timestamp would confirm this, but the record is not in the data.
- **G13** is why actions the Python code took without starting a process, such as direct file reads, cannot be ruled out. The payload itself is only partly visible: the results grid cut off part of the value, and no CSV export was available (Appendix A).
