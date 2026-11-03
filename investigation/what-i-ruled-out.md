# What I ruled out

Source: section 6.7 and Appendix B of the v4.0 report. Three registers sit behind the findings:

- **R-** look-alike activity: things that looked like the attack but were routine.
- **N-** searches that found nothing. A null result is only as wide as the search, so each one states where I looked.
- **AH-** alternative explanations I tested against the evidence.

Each negative is bounded to the records and windows it names.

## Summary (section 6.7)

| Possibility tested | Result | Ref |
|---|---|---|
| A stolen remote login was the way in | Ruled out as the entry for this chain: the scheduled task, not a login, started the attacker's program; SSH logins then are known administrators on the internal network | AH-2, N-06 |
| The portal application itself made the connections to other systems | Ruled out for the observed connections: each was made by the attacker's root program (PID 4401) | AH-1 |
| An earlier break-in at 23:12 on 19 September | Not supported: those rows match a sped-up copy of the attack, with no portal activity | AH-9, R-05 |
| The attacker ran programs on the database, build store or admin platform | None found in the logs examined (account-level access is in F5 to F7); attacker addresses appear only on the portal | N-07, N-13 |
| Attacker database activity after the second burst | Only normal application activity appeared in the database logins and queries examined from 07:46 to 09:30; the other tested look-alikes were routine | N-12, R-02 to R-04 |

## R-: look-alike activity

| ID | Pattern | Looks like | Why it is noise | Ref |
|---|---|---|---|---|
| R-01 | Nessus from 10.5.0.250 | Recon | `Nessus/10.6.2`, 204 logged rows (raw count) over 7 generic paths across 30 hours, never `/api/v1/preview` | A-01 |
| R-02 | `pg_dump` as `portal_svc` during the attack | Theft with the attacker's account | Routine job: 44 runs across 33.5 hours at irregular times, including 07:09:09, 07:22:21, 07:25:17 and 07:47:50 on 09-20, all `backup` via `bash` to `-h localhost`, written to `/backup/nightly/semicrest.dump`; identical before the intrusion; no network path | A-48 |
| R-03 | Postgres spike 07:29:57 to 07:48:47 | Enumeration | 406 logged FATAL rows on sc-db01 from 07:29:57 to 07:48:47 (exact-host A-24, raw count), all connection rejections (`reserved for SUPERUSER`, `too many clients`, A-14); no queries in them | A-24, A-14 |
| R-04 | `ci-builder` pushes and pulls | Registry abuse | All from CI runner 10.5.0.100, EventType `ci_pipeline` | A-08 |
| R-05 | Enumeration statements on sc-db01 and `portal_svc` admin API calls, 2026-09-19 23:12 to 23:14 | An earlier intrusion, or app baseline | Most likely a duplicate or logging artefact (Syslog carries no RunId, so the qf-122 link is by co-occurrence). See below. | A-34 to A-36, A-46, A-47 |

### Why I excluded the 23:12 replay rows (R-05)

These rows look like the whole attack happening the night before. I excluded them for these reasons, all from the report:

- In the same window, the replay bucket holds the recon IPs and 203.0.113[.]87, while the qf-121 bucket holds only partner and CI traffic.
- There is one run of each statement: 5 rows at 23:12 and 5 at 23:13.
- There is no portal process or network activity, and the qf-122 process table holds no attack tree then.
- The exported sc-db01 Syslog for 23:10 to 23:16 holds the entire attack database sequence (`pg_dump` logins, both enumeration bursts including the `password_hash` dump, and the FATAL rejections), compressed into about 1.6 s at 23:12:32 and repeated at 23:13:56. That export has 1,000 rows, the display limit, so it is possibly truncated.

I read this as a time-compressed replay. Its exact Syslog run attribution is unverified.

**Host attribution for sc-db01.** The F5 logins and the R-03 volume rest on exact-host queries (`Computer =~ "sc-db01"`, A-23 and A-24). A-07 and A-14 use the broader `Computer has "db01"` filter and do not display Computer, so they support the message types and the `pg_dump` pattern only, not host attribution.

## N-: searches that found nothing

| ID | Looked for | Where | Conclusion | Ref |
|---|---|---|---|---|
| N-01 | Other external destinations from the shell | DeviceNetworkEvents_CL, PIDs 4400/4401/4430, 06:40 to 09:30 | Two only: C2 and upload address | A-15 |
| N-02 | Activity after persistence | DeviceProcessEvents_CL, PID 4401 or `svc_monitor`, 08:15 to 09:30 | Only the four persistence commands | A-16 |
| N-03 | Cleanup or anti-forensics | DeviceFileEvents_CL deletes/modifies on staging, `svc_monitor`, cron, history | Zero rows; no deletion or modification observed | A-17 |
| N-04 | Backdoor use | DeviceLogonEvents_CL, `svc_monitor`, 08:29 to 09:30 | Zero rows (SSH only, G8) | A-13 |
| N-05 | Registry tampering | ContainerRegistryLog_CL, source 10.5.0.10, 07:00 to 09:30 | One login and three reads at 07:33 only | A-18 |
| N-06 | Stolen-login entry | Shell parent and SSH logons, 06:00 to 06:53 | Shell parent is cron, not sshd; every SSH logon is a named admin from 10.5.0.50 to .59, none from an attacker address | A-04, A-32 |
| N-07 | Attacker addresses on other hosts | All tables, 2026-09-19 to 2026-09-20 09:30 | sc-portal01 only: Syslog 16, DeviceNetworkEvents_CL 8, DeviceProcessEvents_CL 4, PortalAccessLog_CL 156 logged rows, with host normalized from Computer or DeviceName (counts include suspected replay rows, exact Syslog run attribution unverified; host result unaffected) | A-19 |
| N-08 | Repeat cron executions | Syslog CRON on sc-portal01, 06:50 to 09:30 | One run, 06:52:49.907 | A-20 |
| N-09 | Files written into `.portal-cache` before archiving | DeviceFileEvents_CL, 06:52 to 08:02:05 | Zero rows | A-21 |
| N-10 | `authorized_keys` written anywhere | DeviceFileEvents_CL, all devices, 06:52 to 09:30 | Zero rows | A-30 |
| N-11 | AI-claimed `db_admin` credential used | Syslog sc-db01, 09-19 00:00 to 09-20 09:30 | Zero rows | A-27 |
| N-12 | Attacker database activity after burst 2 | Syslog sc-db01 logins and statements, 07:46 to 09:30 | Only parameterised application statements | A-42 |
| N-13 | Attacker activity on sc-db01, sc-registry01, sc-admin01 | Process, device and file events, 06:52 to 09:30 | Only `dpkg`, `apt-get`, `pg_dump` by named admins and backup | A-45 |
| N-14 | A shell or other root process outside PID 4401's tree | DeviceProcessEvents_CL sc-portal01, 06:52 to 09:30 | None; `python3` (parent cron) and its 11 children only, 12 processes in total | A-38 |
| N-15 | A second exploit request (e.g. removing the cron line) | PortalAccessLog_CL, preview endpoint or 203.0.113[.]87, 06:52:49 to 09:30 | Only internal users fetching normal http(s) URLs, all 200 | A-40 |

## AH-: alternative explanations

| ID | Alternative explanation | Test and evidence | Disposition |
|---|---|---|---|
| AH-1 | The application itself made the pivot connections | The pivot connections at 07:16:11, 07:33:01 and 07:45:24 are each owned by PID 4401 (root, parent cron) (A-05, A-39). The app's internal connections are not logged (G6), so this rests on ownership, not on the absence of app traffic (A-25) | Ruled out for the observed pivots |
| AH-2 | Entry was a stolen SSH credential | Shell parent is cron, not sshd (A-04); entry-window SSH logons are named admins from internal addresses only (A-32) | Ruled out within SSH logs |
| AH-3 | A human ran the chain by hand | About 1 to 11 s command spacing within bursts, no repeated or corrected commands; operator directives only at gates (A-29, A-12) | Not supported; operator-gated AI most likely (Medium) |
| AH-4 | The 07:45 admin API calls were the app's routine sweep | The only other `portal_svc` admin API calls (09-19 23:12, 23:13) are the replay copy (most consistent with a duplicate or logging artefact; exact Syslog run attribution unverified, R-05); PID 4401 connects 3.5 s before 07:45 (A-05, A-09) | Ruled out (attacker) |
| AH-5 | Data reached the attacker | Connection and upload command only; no bytes or response (G2) | Open |
| AH-6 | Cron gives the attacker ongoing access | One execution in 157 scheduled minutes; file state not logged (A-20, G3) | Unresolved; no repeat execution observed |
| AH-7 | The environment (`env`, G4) held further credentials that were used | Every downstream login uses one of the two identities the agent names (A-28): `portal_svc` on sc-db01 and the admin API, `ci-builder` on the registry. A-23 (all sc-db01 logins), A-08 (all registry operations) and A-49 (all admin API requests from 10.5.0.10, 06:52 to 09:30, no user filter: only `portal_svc`) show no other identity | Not supported; `env` output itself remains unknown |
| AH-8 | The database results were written into the staging folder (G5) | No file events under `.portal-cache` from 06:52:00 to 08:02:05 (A-21); statement bursts end 07:45:23, 17 min before `tar` | Open; cannot be tested in this telemetry |
| AH-9 | The intrusion began earlier, at 2026-09-19 23:12 | Rows then are most consistent with a duplicate or logging artefact (exact Syslog run attribution unverified); no portal process or network activity 23:05 to 23:20 in any bucket (A-34 to A-36, A-46, A-47) | Not supported (High) |
| AH-10 | The attacker modified `portal.conf` (G9) | Only file event is FileModified by `cat` PID 4410 at 07:05:16.978 (A-44); `cat` does not write its input; no hash or size recorded | Open; read logged as modify most likely (Medium) |
