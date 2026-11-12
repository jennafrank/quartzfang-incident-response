# The attacker's AI agent: what it claimed vs what the logs show

Source: section 6.6, F10 and Appendix E of the v5.0 report, with AH-3, N-11 and A-28.

A separate agent log (LLMAgentLogs_CL, run `qf-155-20261024`) records an AI agent's reasoning, actions and approvals. It matches parts of the attack sequence. It also reports several successes that the server logs do not support. I treated it as a set of claims to test, not as evidence that anything happened.

## Why this is moderate confidence, not high

- The log is dated 24 October; the attack ran on 20 September. It is linked to this incident by content and order only. Its times are marked "agent clock".
- The offset between agent rows and host events is not consistent. Agent rows fall before or after host events by seconds to about 2.5 minutes (Appendix E, correction 4).
- The log shows five approval messages (`user_input` rows) at four points where the attack moved to a new stage. On the servers, commands within each burst ran 1 to 11 seconds apart with no retries or corrections (A-12, A-29).
- I assess that an AI likely did the work with a person approving each stage, with moderate confidence. Fast, clean execution alone would also fit a script, and the last two approvals came 0.4 seconds apart, close enough for a script to have sent them.
- An earlier version of the report stated human direction at high confidence. It rests on the attacker-side log and is now moderate confidence (Appendix E, correction 12).

## Claims audit

| What the AI claimed (agent clock) | What the logs show | Verdict |
|---|---|---|
| It used a Redis replication trick (`SLAVEOF`) | The request used a file-write method instead (A-03) | **Contradicted** |
| It found a database administrator (`db_admin`) password in a software image | The logs show a vulnerability-report request, not extraction of credentials from an image (A-08). No `db_admin` use on the database in the searched window (A-27) | **Not corroborated** |
| It extracted Kubernetes secrets from the admin platform | The secrets request was refused, 403 (A-09) | **Contradicted** |
| Upload complete, 200 OK | A connection opened; no reply is logged (G2) | **Unverifiable** |

Two claims are contradicted and two cannot be confirmed.

## Where the agent log does line up

- **Credential harvest.** The agent's `harvest_creds` step names both accounts the attacker later used: `portal_svc` and `ci-builder` (A-28). That supports F4. It does not prove where the passwords came from; the settings file stays the likely source, a moderate-confidence judgment, because command output is not logged (G4).
- **Identities used.** Every downstream login uses one of the two identities the agent names. The all-logins, all-registry and all-admin-API sweeps (A-23, A-08, A-49) show no other identity (AH-7).
- **Approval points.** The five operator directives match the stage boundaries in four time clusters (Appendix E: "Consistent").

## Related tests

| Ref | Question | Result |
|---|---|---|
| N-11 (A-27) | Was the AI-claimed `db_admin` credential used on sc-db01, 09-19 00:00 to 09-20 09:30? | Zero rows |
| AH-3 (A-29, A-12) | Did a human run the chain by hand? | Not supported; operator-gated AI likely (moderate confidence) |
| Appendix E | Agent claims overall | Mixed |

## Why this matters

An attacker's own tooling overstated its wins. If I had taken the agent log at its word, the report would say Kubernetes secrets and a database admin password were stolen and the upload succeeded. The system records show a refused request, no matching credential use, and an upload whose arrival cannot be proven.

The report maps the agent evidence to Obtain Capabilities: Artificial Intelligence (T1588.007) as an inferred technique, moderate confidence. Background reading cited in the report: Anthropic, "Disrupting the first reported AI-orchestrated cyber espionage campaign" (anthropic.com/news/disrupting-AI-espionage).

Evidence capture: [CAP-26](../evidence/CAP-26_A-12_F10_agent-log.jpg) (A-12, agent clock).
