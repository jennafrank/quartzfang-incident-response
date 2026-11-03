# Findings F1 to F10

Source: section 06 of the v4.0 report. Each finding follows the same form. **State it** says what happened. **Show it** gives the proof and the query that produced it (Appendix A). **Interpret it** gives my judgement and its confidence.

Queries are in [`../hunting-queries/`](../hunting-queries/). Gaps (G-) are in [gaps.md](gaps.md). Look-alikes, null searches and alternatives (R-, N-, AH-) are in [what-i-ruled-out.md](what-i-ruled-out.md).

| Finding | Summary | Confidence |
|---|---|---|
| F1 | The same scan came from three addresses | High |
| F2 | The preview feature accepted a request aimed inside the server | High |
| F3 | That request most likely planted the scheduled task that gave root control | High (write not logged) |
| F4 | Two service passwords were taken and reused within 30 minutes | High obtained; Medium on the settings file as source |
| F5 | Two database search bursts, unlike the application's baseline | High burst 1; Medium burst 2 |
| F6 | Build store browsed; vulnerability report requested; no download or upload logged | High |
| F7 | Admin platform: service list and network map succeeded; secrets refused | High |
| F8 | Files bundled, encrypted and an upload attempted; arrival unknown | High that it is attacker traffic; delivery unproven |
| F9 | Local account created in the sudo group; not seen in use | High |
| F10 | A separate agent log suggests AI execution with human approvals | Medium |

## 6.1 Reconnaissance, break-in and first control

### F1: The same scan came from three addresses.

- **State it.** Three outside addresses ran the identical list of 15 page requests, one after another, from 06:30:00 to 06:31:52.
- **Show it.** PortalAccessLog_CL: same tool name (`python-requests/2.31.0`) and page list from 198.51.100[.]31, [.]45, [.]62 (A-01, A-26).
- **Interpret it.** I read the matching requests and timing as coordinated scanning or shared tooling (High). I cannot tell how many operators were involved. A Nessus scan from 10.5.0.250, the company's own security scanner, is routine (R-01).

### F2: The portal's preview feature accepted a request aimed inside the server.

- **State it.** 203.0.113[.]87 tested what the feature would fetch at 06:44. A request to read a system file was refused at 06:52:30. 18 seconds later, a request in gopher, an old address format, pointing back at the server itself was accepted.
- **Show it.** PortalAccessLog_CL: `file://` 400, then `gopher://127.0.0.1:6379` 200 (A-02).
- **Interpret it.** The feature's address checks stopped `file://` but not a gopher request to Redis on the server's own address. How the checks work was not available. I am high on that gap being the exploited flaw (High).

### F3: That request most likely planted the scheduled task that gave the attacker root control.

- **State it.** The request instructed Redis to save a scheduled task, in the folder the server reads for jobs to run, configured to run the attacker's program every minute. Only one execution was observed, at 06:52:49.907 UTC (A-20). The file write and the task's continued presence were not logged. That run started the attacker's program as root (`python3`, PID 4401) at 06:52:52, and the program connected out to 203.0.113[.]87 at 06:52:55.
- **Show it.** Request payload `CONFIG SET dir /var/spool/cron/`, `dbfilename root`, `SAVE`; Syslog CRON; process and network tables (A-03, A-20, A-04, A-05). See [CAP-06](../evidence/CAP-06_A-03_gopher-payload.jpg).
- **Interpret it.** The write is not logged (G3). The request, the run and the timing make this the best-supported path, and I am high on it. It ran once; I cannot say whether the line remains.

## 6.2 Stolen passwords

### F4: Two service passwords were taken and reused within 30 minutes, most likely from a settings file.

- **State it.** At 07:05 the attacker ran a command to display the portal settings file (`portal.conf`), listed the server's stored settings (`env`) and searched for files. Its program then logged in as `portal_svc` (database) at 07:16 and `ci-builder` (build store) at 07:33.
- **Show it.** Commands under PID 4401; logins; the AI log's credential-harvest step names both accounts (A-04, A-23, A-08, A-28).
- **Interpret it.** I am high on the passwords being obtained and medium on the settings file as their source, because command output is not logged (G4; an unexplained "file changed" record is G9). The stolen service passwords let the attacker reach three more systems.

## 6.3 Moving to other systems and collecting data

### F5: The attacker searched the customer database twice, unlike anything the application did in the baseline.

- **State it.** As `portal_svc`, a first burst (07:16:16 to 07:16:25) asked for all users, projects and customers, the list of tables and `pg_shadow`, which holds database login details and stored password-verification values (results not captured). A second burst (07:45:18 to 07:45:23) asked for projects, customer contacts and user password hashes.
- **Show it.** Syslog sc-db01 queries and logins (A-06, A-23).
- **Interpret it.** The portal normally asks for a few records at a time (A-42). These asked for whole tables and `pg_shadow` in seconds (the connection's application label does not separate them, A-37). I am high on burst 1, which traces directly to the attacker's program, and medium on burst 2, which matches by pattern and timing only. What came back is not logged (G1). The customer contacts and hashes requested are why legal review is needed.

### F6: The attacker browsed the build store and requested a vulnerability report; no software download or upload was logged.

- **State it.** Logged in as `ci-builder` from the portal (10.5.0.10), the attacker requested the repository list, one item's description and a vulnerability report within 3.2 seconds at 07:33. All returned success; the contents were not captured.
- **Show it.** ContainerRegistryLog_CL: `login`, `list_repository`, `pull_manifest`, `inspect_layer` (A-08, A-18).
- **Interpret it.** In the baseline this account works only from the build server (10.5.0.100), so the source and actions mark this as the attacker (High). A vulnerability report lists known weaknesses in the company's software. If it was returned, it tells the attacker what to try next.

### F7: On the admin platform the service list and network map requests succeeded; the secrets request was refused.

- **State it.** As `portal_svc` from the portal, it received a success status (200) for the service list and network map and was refused secrets (403) at 07:45:27 to 07:45:32, 3.5 seconds after its program connected to the platform.
- **Show it.** Syslog sc-admin01 `admin_api` (`/services`, `/topology`, `/secrets`); network table (A-09, A-05).
- **Interpret it.** The connection from the attacker's program ties these requests to the attacker (High). What came back is not logged (G1). A network map, if returned, guides a next attack. The refused secrets request (stored passwords and keys) shows access controls held there. The only other such requests are in the suspected replay described in R-05.

## 6.4 Bundling files and the attempted upload

### F8: The attacker bundled and encrypted files and tried to upload them; whether they arrived is unknown.

- **State it.** By 08:02:20 the attacker had bundled, compressed and encrypted files into `/tmp/.portal-cache/report.tar.gz.enc`. At 08:15:00 it ran an upload command to 198.51.100[.]210, and a connection to that address opened at 08:15:08.
- **Show it.** `tar`, `gzip`, `openssl` and `curl -X POST` in the process table; the file created; the connection (A-04, A-10, A-39). See [CAP-69](../evidence/CAP-69_A-39_upload-connection.jpg).
- **Interpret it.** I can show the upload was attempted. I cannot show how much was sent, whether it was accepted or what the bundle held (G2, G5). The connection is recorded under the attacker's main program, not the upload command, so I link them by destination and timing. In about 30 hours, the portal's normal web connections went only to four known cloud services (A-33), so I am high that this is attacker traffic. Treat the data as possibly sent.

## 6.5 Backdoor

### F9: The attacker created a local account in the sudo group; it was not seen in use.

- **State it.** Commands created `svc_monitor` (08:29:35), added it to the sudo group, normally used to grant administrator rights (08:29:45), and generated a login key that needs no passphrase (by 08:30:00). The account-event records carry slightly later times.
- **Show it.** Process, account and file events under PID 4401 (A-11, A-22).
- **Interpret it.** In place, not shown usable or used. A key works only once registered for login, and no registration was logged (N-10). No SSH login by the account was logged through 09:30 (N-04, G8) (High). Administrator rights are inferred from the group. Changing the stolen passwords leaves this account in place, so it must be removed separately.

## 6.6 Evidence suggesting AI execution with human approvals

### F10: A separate agent log suggests an AI did the work with a person approving each stage; several of its claims are not supported by the logs.

- **State it.** The separate agent log (run `qf-155-20261024`, dated 24 October) shows five approval messages at four points where the attack moved to a new stage. On the servers, commands within each burst ran 1 to 11 seconds apart with no retries or corrections.
- **Show it.** LLMAgentLogs_CL `user_input` (agent clock); process tree (A-12, A-29).
- **Interpret it.** I read this as an AI with a person approving each stage (Medium), but cannot prove the log belongs to this attack. Fast, clean execution alone would also fit a script, and the last two approvals came 0.4 seconds apart, close enough for a script to have sent them. Of the AI's claims, two are contradicted and two cannot be confirmed. See [ai-agent-claims.md](ai-agent-claims.md).
