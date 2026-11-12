# UTC timeline

Source: section 05 of the v5.0 report. All times are UTC on 20 September 2026, taken from each record's event time.

Scanning began at 06:30. The break-in took one request at 06:52. Over the next 97 minutes the attacker took passwords, searched the database, bundled files and created an account. Nothing further matching its behaviors appears from 08:30 to 09:30 (N-01 to N-15).

| Time (UTC) | What happened | Evidence |
|---|---|---|
| 06:30:00 to 06:31:52 | Three outside addresses (198.51.100[.]31, [.]45, [.]62) run the same scan of 15 portal pages | PortalAccessLog_CL · F1, A-01 |
| 06:44:05 to 06:52:30 | 203.0.113[.]87 tests what the preview feature will fetch; a request to read a system file is refused (400) | PortalAccessLog_CL · F2, A-02 |
| 06:52:48 | Request aimed at Redis accepted (200); payload built to plant a scheduled task (write inferred, G3) | PortalAccessLog_CL · F3, A-03 |
| 06:52:49.907 | The scheduled task runs as root (the only run observed) | Syslog · F3, A-20 |
| 06:52 (minute) | Sentinel alert fires on the portal server (exact second not available, G12) | Case brief · section 08 |
| 06:52:52.281 | The attacker's process starts as root (`python3`, PID 4401) | DeviceProcessEvents_CL · F3, A-04 |
| 06:52:55.889 | Connects out to 203.0.113[.]87 on port 443: the remote session | DeviceNetworkEvents_CL · F3, A-05 |
| 07:05:15 to 07:05:27 | Commands to display the portal settings file, list stored settings, search for files | DeviceProcessEvents_CL · F4, A-04 |
| 07:16:11 to 07:16:25 | Connects to the database; first burst of searches | DeviceNetworkEvents_CL, Syslog · F5, A-05, A-06 |
| 07:33:01 to 07:33:05 | Logs in to the build store as `ci-builder` (the build system's account) and makes three reads | DeviceNetworkEvents_CL, ContainerRegistryLog_CL · F6, A-08 |
| 07:43:01 to 07:45:23 | Second database login (no connection record) and second burst of searches | Syslog · F5, A-06, A-23 |
| 07:45:24 to 07:45:32 | Admin platform: service list and network map requests succeed (200), secrets refused (403) | DeviceNetworkEvents_CL, Syslog · F7, A-09 |
| 08:02:05 to 08:02:20 | Bundles, compresses and encrypts files into `report.tar.gz.enc` | DeviceProcessEvents_CL, DeviceFileEvents_CL · F8, A-04, A-10 |
| 08:15:00 to 08:15:08 | Tries to upload the archive to 198.51.100[.]210; a connection opens at 08:15:08 | DeviceProcessEvents_CL, DeviceNetworkEvents_CL · F8, A-05 |
| 08:29:35 to 08:30:00 | Creates `svc_monitor` in the sudo group; generates a login key | DeviceProcessEvents_CL, DeviceFileEvents_CL · F9, A-11 |

## Detection, dwell time and containment (section 08)

| Measure | Value |
|---|---|
| Reconnaissance undetected | About 22 minutes. Scanning began at 06:30:00 (F1) and nothing fired on it. Scanning is low-priority on its own, but it was this attack's first signal. |
| Dwell time (intrusion to detection) | About 12 seconds or less: the exploit landed at 06:52:48 and the alert fired in the same minute. The alert's exact timestamp would confirm this, but the record is not in the data (G12). |
| Time to containment | Not contained. Attacker activity runs 06:52:48 to 08:30:00 UTC, about 97 minutes after the alert, and the end of access is unknown. |

## How to read these times

- **One clock.** A May date in the raw exploit line (A-03) and 19 September processing times (A-41) are not used. Their cause is unverified.
- **Duplicates.** Some events were stored several times (A-41 shows six copies of one). Each event is counted once.
- **Suspected replay.** Rows at 23:12 to 23:14 on 19 September look like a sped-up duplicate of the attack sequence, most likely a re-ingestion artifact. They are excluded. Their origin is unverified (R-05).
- **Agent clock.** The agent log is dated 24 October and linked to this attack by content and order only. Its times are marked "agent clock" wherever they appear.
