# Capture plan

The first release has no verified Muse indicators. Collect the following separate sessions on the same test device and network where possible. Record the app name/version, OS, access method, test device IP, timestamp with timezone, and a short action timeline. Confirm the exact application identity/link so similarly named apps are not confused.

| Session | Activity | Purpose |
| --- | --- | --- |
| Idle baseline | Device idle, app closed, 2–3 minutes | Find background traffic |
| Standalone launch | Open the app without sending a prompt | Distinguish startup from interaction |
| Standalone interaction | Send a harmless synthetic prompt, wait for response | Find candidate interaction indicators |
| Facebook baseline | Normal Facebook browsing without AI interaction | Exclude shared endpoints |
| Facebook interaction | Use the relevant AI feature, if available | Check for distinct endpoints or visible request metadata |
| Repeat and control | Repeat interaction plus ordinary Instagram/other Meta activity | Check consistency and false matches |

Begin collection before launching the app so DNS and TLS setup are included. Capture both directions, full packets when feasible, and note any VPN, proxy, encrypted DNS, or packet loss. Keep each test separate and identify precisely when each action happened. Do not disable security controls just to get a match.

PCAP/PCAPNG is preferred. Zeek `conn`, `dns`, `ssl`, `http` and `quic` logs, when available, are useful alongside it. An encrypted capture still supports DNS/SNI work when those names are visible; it does not reveal HTTPS request paths or prove what the user asked. A trace containing only server IP addresses may not support reliable attribution.

Use test accounts and harmless synthetic content. Keep originals in an approved private location and transfer securely. Captures and HAR exports can contain access credentials and private content. The repository ignores common capture/export extensions, but that is not a privacy filter: do not commit real captures or their raw logs.

For each proposed rule, compare the interaction trace with baseline and repeat traces, document alternatives, and add a sanitized synthetic regression. Only add a production indicator when evidence supports its claimed scope. Record negative controls and remaining limitations in `INDICATORS.md`. A name observed during a session is only a candidate until differentiated from shared/background activity.
