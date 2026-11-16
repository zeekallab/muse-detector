# Indicator ledger

**No verified production indicators as of 2026-11-16.**

The default ruleset is empty. Names in examples and tests are synthetic. There is no validated coverage for either standalone-app or Facebook usage.

Before adding an indicator, record:

- Stable rule ID and nonsensitive domain/path/header condition.
- Evidence kind: DNS query, TLS SNI, or visible HTTP request.
- Application identity/version, OS, date, access method and test actions.
- Private capture reference and matching Zeek connection UID, without embedding captures, tokens or private logs here.
- What repeated sessions establish and what they do not.
- Negative controls, including ordinary Facebook and other Meta traffic.
- Whether the indicator distinguishes an access method or must retain `Unknown`.
- Status (`Experimental` or `Capture_Validated`), review date and known gaps.

Validating an endpoint does not by itself validate every request to that endpoint, installation detection, autonomous execution, or malicious behavior.
