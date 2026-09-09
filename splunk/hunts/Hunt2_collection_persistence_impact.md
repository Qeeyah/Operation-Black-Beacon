# Hunt 2 - Persistence and Operational Impact

## Hypothesis

The compromised identity performed collection, persistence-like activity, outbound transfer, and backup interference.

## Scope

- Index: `black_beacon`
- Sourcetype: `bb:scenario`
- Primary identity: `dev.victor`

## SPL

```spl
index=black_beacon sourcetype=bb:scenario user="dev.victor"
| where event_action IN ("privileged_command","account_created","archive_created","outbound_connection","backup_stopped")
| table _time event_action host resource dest_ip severity
| sort _time
