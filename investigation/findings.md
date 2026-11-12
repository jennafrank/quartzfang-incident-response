# Findings F1 to F10

Source: section 06 of the v5.0 report. Each finding follows the same form. **State it** says what happened. **Show it** gives the proof and the query that produced it (Appendix A). **Interpret it** gives my judgment and its confidence.

The report uses estimative language. Almost certainly, very likely, likely and roughly even chance say how probable a judgment is. High, moderate and low confidence say how strong the evidence behind it is.

Queries are in [`../hunting-queries/`](../hunting-queries/). Gaps (G-) are in [gaps.md](gaps.md). Look-alikes, null searches and alternatives (R-, N-, AH-) are in [what-i-ruled-out.md](what-i-ruled-out.md).

| Finding | Summary | Judgment and confidence |
|---|---|---|
| F1 | The same scan came from three addresses | Coordinated scanning or shared tooling, high confidence |
| F2 | The preview feature accepted a request aimed inside the server | The exploited flaw, high confidence |
| F3 | That request almost certainly planted the scheduled task that gave root control | Best-supported path, high confidence (write not logged) |
| F4 | Two service passwords were stolen and reused within 30 minutes, likely from a settings file | Passwords obtained, high confidence; settings file as source, moderate confidence |
| F5 | Two database search bursts, unlike the application's baseline | Burst 1, high confidence; burst 2 very likely the attacker's, moderate confidence |
| F6 | Build store browsed; vulnerability report requested; no download or upload logged | Attacker, high confidence |
| F7 | Admin platform: service list and network map succeeded; secrets refused | Attacker, high confidence |
| F8 | Files bundled, encrypted and an upload attempted; arrival unknown | Almost certainly attacker traffic; delivery unproven |
| F9 | Local account created in the sudo group; not seen in use | High confidence |
| F10 | A separate agent log suggests AI execution with human approvals | Likely, moderate confidence |

## 6.1 Reconnaissance, break-in and first control

### F1: The same scan came from three addresses.

- **State it.** Three outside addresses ran the identical list of 15 page requests, one after another, from 06:30:00 to 06:31:52.
- **Show it.** PortalAccessLog_CL: same tool name (`python-requests/2.31.0`) and page list from 198.51.100[.]31, [.]45, [.]62 (A-01, A-26).
- **Interpret it.** I assess with high confidence that this was coordinated scanning or shared tooling. I cannot tell how many operators were involved. A Nessus scan from 10.5.0.250, the company's own security scanner, is routine (R-01).

### F2: The portal's preview feature accepted a request aimed inside the server.

- **State it.** 203.0.113[.]87 tested what the feature would fetch at 06:44. A request to read a system file was refused at 06:52:30. Eighteen seconds later, a request in gopher, an old address format, pointing back at the server itself was accepted.
- **Show it.** PortalAccessLog_CL: `file://` 400, then `gopher://127.0.0.1:6379` 200 (A-02).
- **Interpret it.** The feature's address checks stopped `file://` but not a gopher request to Redis on the server's own address. How the checks work was not available. I assess with high confidence that this gap is the flaw the attacker exploited.

### F3: That request almost certainly planted the scheduled task that gave the attacker root control.

- **State it.** The request told Redis to save a scheduled task, set to run the attacker's code every minute, into the folder the server reads for jobs. One run was observed, at 06:52:49.907 (A-20). That run started the attacker's process as root (`python3`, PID 4401) at 06:52:52, and it connected out to 203.0.113[.]87 at 06:52:55.
- **Show it.** Request payload `CONFIG SET dir /var/spool/cron/`, `dbfilename root`, `SAVE`; Syslog CRON; process and network tables (A-03, A-20, A-04, A-05). See [CAP-06](../evidence/CAP-06_A-03_gopher-payload.jpg).
- **Interpret it.** The file write itself is not logged (G3). The request, the run and the timing make this the best-supported path, and I hold that judgment with high confidence. Whether the scheduled task is still there is unknown.

## 6.2 Stolen passwords

### F4: Two service passwords were stolen and reused within 30 minutes, likely from a settings file.

- **State it.** At 07:05 the attacker ran a command to display the portal settings file (`portal.conf`), listed the server's stored settings (`env`) and searched for files. Its process then logged in as `portal_svc` (database) at 07:16 and `ci-builder` (build store) at 07:33.
- **Show it.** Commands under PID 4401; logins; the agent log's credential-harvest step names both accounts (A-04, A-23, A-08, A-28).
- **Interpret it.** I assess with high confidence that the attacker obtained both passwords. The settings file is the likely source, a moderate-confidence judgment because command output is not logged (G4, G9). Those two passwords opened three more systems.

## 6.3 Lateral movement and data collection

### F5: The attacker searched the customer database twice, unlike anything the application did in the baseline.

- **State it.** As `portal_svc`, a first burst (07:16:16 to 07:16:25) asked for all users, projects and customers, the list of tables, and `pg_shadow`, which holds database login details and password-verification values. A second burst (07:45:18 to 07:45:23) asked for projects, customer contacts and user password hashes.
- **Show it.** Syslog sc-db01 queries and logins (A-06, A-23).
- **Interpret it.** The portal normally asks for a few records at a time (A-42). These asked for whole tables in seconds. The connection's application label does not separate them (A-37). Burst 1 traces directly to the attacker's process (high confidence). Burst 2 matches by pattern and timing only, so I assess it as very likely the attacker's, with moderate confidence. What came back is not logged (G1). The customer contacts and hashes requested are why the legal review is needed.

### F6: The attacker browsed the build store and requested a vulnerability report; no software download or upload was logged.

- **State it.** Logged in as `ci-builder` from the portal (10.5.0.10), the attacker requested the repository list, one item's description and a vulnerability report within 3.2 seconds at 07:33. All returned success. The contents were not captured.
- **Show it.** ContainerRegistryLog_CL: `login`, `list_repository`, `pull_manifest`, `inspect_layer` (A-08, A-18).
- **Interpret it.** In the baseline this account works only from the build server (10.5.0.100). The source and actions mark this as the attacker, with high confidence. A vulnerability report lists known weaknesses in the company's software. If it was returned, it tells the attacker what to try next.

### F7: On the admin platform, the service list and network map requests succeeded; the secrets request was refused.

- **State it.** As `portal_svc` from the portal, the attacker got a success status (200) for the service list and network map and was refused secrets (403) at 07:45:27 to 07:45:32. That was 3.5 seconds after its process connected to the platform.
- **Show it.** Syslog sc-admin01 `admin_api` (`/services`, `/topology`, `/secrets`); network table (A-09, A-05).
- **Interpret it.** The connection from the attacker's process ties these requests to the attacker (high confidence). What came back is not logged (G1). A network map, if returned, is a guide for a next attack. The refused secrets request shows access controls held there. The only other such requests are in the suspected replay (R-05).

## 6.4 Staging and attempted exfiltration

### F8: The attacker bundled and encrypted files and tried to upload them; whether they arrived is unknown.

- **State it.** By 08:02:20 the attacker had bundled, compressed and encrypted files into `/tmp/.portal-cache/report.tar.gz.enc`. At 08:15:00 it ran an upload command to 198.51.100[.]210. A connection to that address opened at 08:15:08.
- **Show it.** `tar`, `gzip`, `openssl` and `curl -X POST` in the process table; the file created; the connection (A-04, A-10, A-39). See [CAP-69](../evidence/CAP-69_A-39_upload-connection.jpg).
- **Interpret it.** I can show the upload was attempted. I cannot show how much was sent, whether it was accepted or what the archive held (G2, G5). The connection is recorded under the attacker's main process, not the upload command, so I link them by destination and timing. Over about 30 hours, the portal's normal web traffic went only to four known cloud services (A-33). This is almost certainly attacker traffic. Treat the data as possibly sent.

## 6.5 Persistence

### F9: The attacker created a local account in the sudo group; it was not seen in use.

- **State it.** Commands created `svc_monitor` (08:29:35), added it to the sudo group, normally used to grant administrator rights (08:29:45), and generated a login key with no passphrase (by 08:30:00). The account-event records carry slightly later times.
- **Show it.** Process, account and file events under PID 4401 (A-11, A-22).
- **Interpret it.** The account exists but was not shown in use. A key works only once it is registered for login, and no registration was logged (N-10). No SSH login by the account was logged through 09:30 (N-04, G8). I hold both points with high confidence. Administrator rights are inferred from the group. Changing the stolen passwords leaves this account in place, so it must be removed separately.

## 6.6 Evidence suggesting AI execution with human approvals

### F10: A separate agent log suggests an AI did the work with a person approving each stage; several of its claims are contradicted by the logs.

- **State it.** The agent log (run `qf-155-20261024`, dated 24 October) shows five approval messages at four points where the attack moved to a new stage. On the servers, commands within each burst ran 1 to 11 seconds apart with no retries or corrections.
- **Show it.** LLMAgentLogs_CL `user_input` (agent clock); process tree (A-12, A-29).
- **Interpret it.** I assess that an AI likely did the work with a person approving each stage, with moderate confidence. I cannot prove the log belongs to this attack. Fast, clean execution alone would also fit a script, and the last two approvals came 0.4 seconds apart, close enough for a script to have sent them. Of the AI's claims, two are contradicted and two cannot be confirmed. See [ai-agent-claims.md](ai-agent-claims.md).
