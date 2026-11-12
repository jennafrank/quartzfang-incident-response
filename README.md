<p align="center">
  <img src="quartzfang-hero.svg" alt="Quartzfang Banner" width="100%">
</p>

# Operation QUARTZFANG: Incident Response

**One web request. Full control of a server. And an attacker's AI that overstated its own wins.**

An incident investigation in a Microsoft Sentinel workspace, by Jenna Frank. Report v5.0, public edition, issued 2026-11-11 and revised after peer review and the grading debrief. TLP:CLEAR, published with permission.

**[Project site](https://jennafrank.github.io/quartzfang-incident-response/)** · [Impact, root cause and response plan](docs/response-and-recommendations.md) · [Full report (PDF)](report/QUARTZFANG_IR_Report_JennaFrank_v5.0_public.pdf) · Full-resolution edition on the [v5.0 release](../../releases/tag/v5.0) page

## In 60 seconds

- **Impact.** On 20 September 2026, an attacker took full control of SemiCrest's customer portal server, used two stolen service passwords to move into three other internal systems, including the customer database, and tried to send an encrypted archive out of the company.
- **How it got in.** Through the portal's link-preview feature, tricking it into sending commands to an internal data store that then ran the attacker's code with full administrator rights.
- **Top recommendation.** Isolate the portal server now. Then change the stolen passwords and remove the account the attacker created. Changing passwords before the server is isolated risks handing the attacker the new ones.
- **Timing.**
  - Dwell time (intrusion to detection): about 12 seconds or less. The exploit landed at 06:52:48 and the alert fired in the same minute.
  - Reconnaissance went undetected for about 22 minutes.
  - Containment has not happened.
  - Attacker activity lasted about 97 minutes, and the end of access is unknown.
- **Lateral movement: yes.** From the portal to the database, build store and admin platform, using stolen service passwords.
- **Exfiltration: attempted.** An encrypted upload to 198.51.100[.]210 opened a connection at 08:15. Whether any data arrived, and what it was, is unproven.
- **What it went after.** It requested customer contacts, project records and users' password hashes. The logs record what was requested, not what was returned.
- **What I found.** 10 findings, each with an estimative judgment and a confidence level. The attacker's AI agent also claimed successes that the server logs contradict.
- **What I built.** 5 detection rules tested on this incident's data, and the 49 hunting queries behind the findings.
- **Decisions needed now.**
  - Isolate the portal server.
  - Block the two attacker addresses.
  - Disable the attacker-created account.
  - Start the breach and notification assessment.
  - Change the stolen service passwords and all database passwords, after isolation.
  - Keep the portal offline until the preview feature is fixed.

## For detection engineers

| Rule | Catches | Data source | ATT&CK | Backtest on this incident | Main tuning caveat |
|---|---|---|---|---|---|
| [C-D1](detections/C-D1_ssrf_preview_nonhttp_or_loopback.kql) | Preview requests with a non-http(s) scheme or a loopback/link-local target | PortalAccessLog_CL | T1190 | 203.0.113[.]87 only, 5 distinct requests; zero baseline | Decode the URL first; add private ranges and decimal/hex IP forms |
| [C-D2](detections/C-D2_cron_spawned_python_reverse_shell.kql) | Cron-parented Python with socket and shell-spawn markers | DeviceProcessEvents_CL | T1053.003, T1059.006 | PID 4401 at 06:52:52 only; zero baseline | Misses compiled implants |
| [C-D3](detections/C-D3_local_account_create_or_priv_group.kql) | Account creation, or `usermod` adding a privileged group | DeviceProcessEvents_CL | T1136.001 | `svc_monitor` at 08:29:35 and 08:29:45 only; zero baseline | Fires on legitimate provisioning; untested on real provisioning |
| [C-D4](detections/C-D4_postgres_enumeration_statements.kql) | Enumeration-style Postgres statements | Syslog | T1213.006 | 7 of 8 attack statements; replay copies only; zero application hits | Exclude `pg_dump`; one burst-2 query is outside coverage |
| [C-D5](detections/C-D5_ci_account_from_non_ci_source.kql) | CI account used from a non-CI source | ContainerRegistryLog_CL | T1078 | 10.5.0.10 only, 4 distinct operations; no baseline hits | Maintain the CI runner allowlist |

These were tested on this incident's data. That is not a production false-positive rate. Test windows, Sentinel rule YAML and full tuning notes are in [detections/](detections/).

## For threat hunters

```mermaid
flowchart LR
    A["Scan of 15 portal pages<br/>F1"] --> B["Preview feature SSRF<br/>F2"]
    B --> C["Request to Redis<br/>F3"]
    C --> D["Cron task, one run<br/>F3"]
    D --> E["Root shell, PID 4401<br/>F3"]
    E --> F["Two stolen service passwords<br/>F4"]
    F --> G["Database searches<br/>F5"]
    F --> H["Build store reads<br/>F6"]
    F --> I["Admin API requests<br/>F7"]
    E --> J["Encrypted bundle<br/>F8"]
    J --> K["Attempted upload<br/>F8"]
    E --> L["Account in sudo group<br/>F9"]
```

What's worth a closer look:

- **The agent-claims audit.** A separate AI agent log matches parts of the attack. Of its claims, two are contradicted by system records and two can't be confirmed. It says secrets were extracted; the request was refused (403). [ai-agent-claims.md](investigation/ai-agent-claims.md)
- **Burst 2 is moderate confidence, not high.** The second database burst matches the first by pattern and timing, but its login has no connection record tying it to the attacker's process (G7). I assess it as very likely the attacker's, with moderate confidence. [findings.md](investigation/findings.md#f5-the-attacker-searched-the-customer-database-twice-unlike-anything-the-application-did-in-the-baseline)
- **The replay rows I excluded.** Rows from the night before look like the whole attack. They hold the full database sequence compressed into about 1.6 seconds, repeated, with no portal process or network activity. I read them as a time-compressed replay and left them out (R-05). [what-i-ruled-out.md](investigation/what-i-ruled-out.md#why-i-excluded-the-2312-replay-rows-r-05)
- **Requested is not returned.** None of the systems logged what they sent back (G1), so every data finding says "requested", and the upload says "attempted". [gaps.md](investigation/gaps.md)

## What I can prove and what I can't

**I can show:** the break-in request, a single root cron run seconds later, every command the attacker's process started, its connections to three internal systems, what it asked each one for, the encrypted archive, the upload command and connection, and the account it created.

**I can't show:** what any system sent back, what the archive held, whether the upload arrived, whether the cron task is still in place, whether the new account was ever used, or when the attacker's access ended. The roughly 97 minutes is the attacker activity I can see, from 06:52:48 to 08:30:00. It is not the end of access. I assess that an AI likely did the work with a person approving each stage, with moderate confidence, but I cannot prove the agent log belongs to this attack.

## How I investigated

1. **Alert.** Started from the reported alert at 06:52 and the case leads.
2. **Portal requests.** Found the scan, the preview-feature probes and the accepted request to Redis (A-01 to A-03).
3. **Process tree.** Traced the attacker's root process (PID 4401) and every command it started (A-04, A-29).
4. **Network connections.** Followed its connections out to the attacker and in to three internal systems (A-05, A-39).
5. **Downstream logs.** Read the database, build store and admin platform logs for each connection (A-06, A-08, A-09, A-23).
6. **Alternatives.** Tested other explanations and swept every table for the attacker's addresses ([what-i-ruled-out.md](investigation/what-i-ruled-out.md)).

Timeline: [timeline.md](investigation/timeline.md). ATT&CK: [attack-mapping.md](mitre/attack-mapping.md). Queries: [hunting-queries/](hunting-queries/). Evidence: [evidence/](evidence/).

## Repository structure

| Path | Contents |
|---|---|
| `report/` | The full IR report, v5.0 public edition PDF (TLP:CLEAR) |
| `investigation/` | [Findings](investigation/findings.md), [timeline](investigation/timeline.md), [gaps](investigation/gaps.md), [what I ruled out](investigation/what-i-ruled-out.md), [AI agent claims audit](investigation/ai-agent-claims.md) |
| `docs/` | GitHub Pages site: [`index.md`](docs/index.md) and [impact, root cause and response](docs/response-and-recommendations.md) (report sections 08 to 14 in Markdown) |
| `detections/` | 5 KQL detections, with Sentinel analytics rule YAML in `detections/sentinel/` |
| `hunting-queries/` | The 49 queries (A-01 to A-49) behind the findings |
| `evidence/` | Query-result captures and [MANIFEST.md](evidence/MANIFEST.md) |
| `mitre/` | [ATT&CK mapping](mitre/attack-mapping.md) |

## Skills demonstrated

KQL · Microsoft Sentinel · Incident response (NIST SP 800-61r3, SANS PICERL) · Detection engineering · MITRE ATT&CK mapping · Evidence handling (SHA-256 per capture, chain of custody) · AI-assisted investigation with human verification

## AI disclosure

I used AI tools. Claude (Anthropic) was my hunt partner and helped draft the report. ChatGPT/Codex (OpenAI) reviewed drafts for overclaiming. I ran every query and made every call in the report, and checked each finding against the logs. Case-brief statements and inferences are labeled as such.

## About me

Jenna Frank, SOC Operations Lead. [linkedin.com/in/jenna-frank-cyber](https://www.linkedin.com/in/jenna-frank-cyber) · Portfolio: [JennaFrank.co](https://www.JennaFrank.co)

## License

Code and queries: [MIT](LICENSE). The report PDF is © Jenna Frank, all rights reserved.
