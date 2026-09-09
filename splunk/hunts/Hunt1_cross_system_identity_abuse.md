# Hunt 1 - Cross System Identity Abuse

## Hypothesis

A single compromised developer identity was used across authentication, application, repository, and CI/CD activity.

## Scope

- Index: `black_beacon`
- Sourcetype: `bb:scenario`
- Primary identity: `dev.victor`

## Telemetry

- Identity
- Cloud/application
- Repository
- CI/CD

## SPL

```spl
index=black_beacon sourcetype=bb:scenario user="dev.victor"
| where event_category IN ("identity","cloud_application","repository_ci")
| table _time event_category event_action src_ip host application resource result severity
| sort _time
