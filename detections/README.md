# Detection pack C-D1 to C-D5

Source: Appendix C of the v5.0 report. Each rule is written in KQL for Microsoft Sentinel and was backtested against this incident's data.

> **Tested on this incident's data, not a production false-positive rate.** One backtest on one incident shows a rule can catch this attack. It says nothing about how noisy the rule will be in your environment.

## The rules

| Rule | What the printed query matches | Data source | ATT&CK | Threshold |
|---|---|---|---|---|
| [C-D1](C-D1_ssrf_preview_nonhttp_or_loopback.kql) | `/api/v1/preview` requests whose `url=` scheme is present and not http/https, or whose target contains `127.0.0.1`, `localhost` or `169.254.` | PortalAccessLog_CL | T1190 | ≥1 event |
| [C-D2](C-D2_cron_spawned_python_reverse_shell.kql) | `python`/`python3` whose parent is cron and whose command line has `socket` plus a shell or `dup2` reference | DeviceProcessEvents_CL | T1053.003, T1059.006 | ≥1 event |
| [C-D3](C-D3_local_account_create_or_priv_group.kql) | Any `useradd`/`adduser`, or `usermod` with `sudo`, `wheel` or `-aG` | DeviceProcessEvents_CL | T1136.001 | ≥1 event |
| [C-D4](C-D4_postgres_enumeration_statements.kql) | Postgres statements on sc-db01 containing `SELECT *`, `pg_shadow`, `information_schema` or `password_hash`, or an unfiltered read `FROM customers` (any user) | Syslog | T1213.006 | ≥1 event |
| [C-D5](C-D5_ci_account_from_non_ci_source.kql) | `ci-builder` registry operations from any source other than 10.5.0.100 | ContainerRegistryLog_CL | T1078 | ≥1 event |

All five have status **Backtested**.

## Test windows and results

Tested windows, as shown in each backtest capture:

| Rule | Test window (UTC) | Backtest result | Capture |
|---|---|---|---|
| C-D1 | No explicit time filter; scoped by the portal run bucket `qf-121-20260920` | 203.0.113[.]87 only, 5 distinct requests (dcount); zero baseline | CAP-92 |
| C-D2 | 2026-09-19 00:00 to 2026-09-20 09:00 | PID 4401 at 06:52:52 only; zero baseline | CAP-93 |
| C-D3 | 2026-09-19 00:00 to 2026-09-20 09:30 | `svc_monitor` at 08:29:35 and 08:29:45 only; zero baseline | CAP-94 |
| C-D4 | 2026-09-19 00:00 to 2026-09-20 09:30 | 7 of the 8 statements in F5: all 5 of burst 1 and both sensitive-data reads in burst 2 (`customers`, `password_hash`). The only other hits are suspected replay copies (09-19 23:12, 23:13; exact Syslog run attribution unverified, R-05). Zero application statements match | CAP-95 |
| C-D5 | 2026-09-19 00:00 to 2026-09-20 09:30 | 10.5.0.10 only: 4 distinct operations (8 logged rows, duplicate ingestion), 07:33:01.905 to 07:33:05.119; no baseline or replay hits | CAP-96 |

Each rule returned only attacker rows. C-D4 also returned the suspected replay copies of the same statements, the expected and named exception (R-05). Hit counts in the captures are logged rows, which include duplicate ingestion; the result column gives distinct events. The backtests applied the scope, time bounds, deduplication and output transformations shown in each capture.

## Tuning before go-live

| Rule | Main caveat | What to do |
|---|---|---|
| C-D1 | Matches only literal loopback and link-local strings | Decode `UrlOriginal` first; add private ranges, resolved addresses, `0.0.0.0`, `[::1]` and decimal or hex IP forms |
| C-D2 | Misses compiled implants | Pair with any cron child making an outbound connection. The legitimate cron jobs in this data (`logrotate`, `ntpdate`, `/opt/monitoring/checks/*.sh`, seen in sc-admin01 Syslog CRON lines) carry no python interpreter with socket and shell-spawn markers, so the rule cannot match them. The process table records no cron child other than PID 4401 in the window (A-31), so that look-alike exists only in Syslog and could not be replayed through this rule |
| C-D3 | Fires on legitimate provisioning | Add parent-process or same-account create-and-grant correlation. No legitimate account provisioning occurs in the lead-in, so this data held no harmless look-alike to exclude; false-positive behavior on real provisioning is untested |
| C-D4 | The burst-2 `projects ... ORDER BY revision DESC` query is outside its coverage | Exclude `pg_dump` (`backup` account); `application_name` is not a usable filter (A-37); suppress known replay or test windows |
| C-D5 | Depends on a correct CI source list | Maintain the CI runner allowlist |

Recommendation 6 in the report: tune C-D4 and C-D5 on 30 days of data; build C-D6 (archive, encrypt, upload). C-D6 is not in this pack because it has not been built or tested.

## Files

- `C-D*.kql`: the rules copied as printed in Appendix C. The printed rules carry no backtest time bounds or RunId filters, so nothing was removed. Line wrapping follows the PDF.
- [`sentinel/`](sentinel/): the same five queries as Microsoft Sentinel scheduled analytics rule YAML.

### Sentinel YAML notes

- **Schedule.** From the report: every 5 minutes over a 10-minute lookback (`queryFrequency: 5m`, `queryPeriod: 10m`). Threshold ≥1 event (`triggerOperator: gt`, `triggerThreshold: 0`).
- **Tactics and techniques.** From Appendix C. Sub-techniques are listed under `subTechniques`, with the parent under `relevantTechniques`.
- **Entity mappings** use only columns the query returns: IP for C-D1 and C-D5; Host, Account and Process for C-D2 and C-D3; Host for C-D4. Verify them against a generated test alert before relying on them.
- **Severity is High** for all five. The report assigns no per-rule severity; High is the incident severity it lists (cover, section 03). Adjust it to your own triage scheme.
- The `id` values are generated identifiers for these files, not values from the report.
