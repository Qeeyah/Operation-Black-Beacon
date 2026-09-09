# Operation Black Beacon Case Report

**Case ID:** BB-DEMO-01
**Risk Score:** 155
**Risk Level:** Critical
**Events Analysed:** 73

## Matched Conditions
- Eight or more failed logins for one user/source (+20)
- Successful login after repeated failures (+30)
- New application token or consent activity (+20)
- Repository or CI/CD modification (+20)
- Archive creation (+20)
- Outbound connection after archive creation (+25)
- New account, privileged action or backup stop (+20)

## Recommended Analyst Actions
- Review authentication and identity telemetry.
- Validate application token and consent activity.
- Review repository and CI/CD changes.
- Preserve relevant logs and case evidence.
- Consider credential reset and session revocation.
- Review and revoke unauthorised application tokens.
- Validate newly created accounts and privileged changes.
- Confirm backup integrity and recovery readiness.
- Investigate outbound connection activity.

## Important Events

| Time | Action | User | Host | Resource |
|---|---|---|---|---|
| 2026-09-01T09:07:09+01:00 | login | dev.auwal | nova-ci01 | developer-account |
| 2026-09-01T09:13:35+01:00 | login | admin.lara | nova-app01 | user-session |
| 2026-09-01T09:14:16+01:00 | login | dev.auwal | nova-app01 | user-session |
| 2026-09-01T09:18:26+01:00 | login | admin.lara | nova-app01 | user-session |
| 2026-09-01T09:23:06+01:00 | workflow_modified | ci.runner | nova-dev01 | approved-maintenance.yml |
| 2026-09-01T09:23:36+01:00 | outbound_connection | analyst.qeeyah | nova-backup01 | updates.example:443 |
| 2026-09-01T09:24:54+01:00 | login | analyst.qeeyah | nova-app01 | user-session |
| 2026-09-01T09:25:01+01:00 | login | dev.auwal | nova-app01 | developer-account |
| 2026-09-01T09:27:17+01:00 | login | dev.auwal | nova-app01 | user-session |
| 2026-09-01T09:27:18+01:00 | outbound_connection | analyst.qeeyah | nova-backup01 | updates.example:443 |
| 2026-09-01T09:30:00+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:30:35+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:31:10+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:31:45+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:32:20+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:32:21+01:00 | login | dev.auwal | nova-app01 | user-session |
| 2026-09-01T09:32:55+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:33:30+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:33:57+01:00 | login | analyst.qeeyah | nova-app01 | user-session |
| 2026-09-01T09:34:05+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:34:40+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:35:15+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:35:50+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:36:02+01:00 | login | dev.auwal | nova-app01 | user-session |
| 2026-09-01T09:36:25+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:37:12+01:00 | login | analyst.qeeyah | nova-app01 | user-session |
| 2026-09-01T09:37:13+01:00 | login | admin.lara | nova-app01 | user-session |
| 2026-09-01T09:38:00+01:00 | login | dev.victor | nova-app01 | developer-account |
| 2026-09-01T09:41:00+01:00 | token_issued | dev.victor | nova-app01 | developer-api-token |
| 2026-09-01T09:41:03+01:00 | outbound_connection | ci.runner | nova-ci01 | updates.example:443 |
| 2026-09-01T09:42:28+01:00 | login | dev.auwal | nova-app01 | developer-account |
| 2026-09-01T09:43:00+01:00 | consent_granted | dev.victor | nova-app01 | repo.read workflow.write |
| 2026-09-01T09:46:25+01:00 | outbound_connection | dev.auwal | nova-app01 | updates.example:443 |
| 2026-09-01T09:50:00+01:00 | workflow_modified | dev.victor | nova-ci01 | .ci/deploy-learning-api.yml |
| 2026-09-01T09:50:45+01:00 | login | admin.lara | nova-app01 | user-session |
| 2026-09-01T09:56:09+01:00 | login | analyst.qeeyah | nova-app01 | user-session |
| 2026-09-01T09:56:49+01:00 | login | admin.lara | nova-app01 | user-session |
| 2026-09-01T09:59:00+01:00 | privileged_command | dev.victor | nova-app01 | /etc/sudoers |
| 2026-09-01T09:59:59+01:00 | outbound_connection | analyst.qeeyah | nova-backup01 | updates.example:443 |
| 2026-09-01T10:01:00+01:00 | account_created | dev.victor | nova-app01 | svc-beacon |
| 2026-09-01T10:02:46+01:00 | workflow_modified | ci.runner | nova-app01 | approved-maintenance.yml |
| 2026-09-01T10:05:00+01:00 | archive_created | dev.victor | nova-app01 | learner_export.tar.gz |
| 2026-09-01T10:05:09+01:00 | login | admin.lara | nova-app01 | user-session |
| 2026-09-01T10:07:14+01:00 | login | analyst.qeeyah | nova-app01 | user-session |
| 2026-09-01T10:08:00+01:00 | outbound_connection | dev.victor | nova-app01 | 203.0.113.50:443 |
| 2026-09-01T10:08:13+01:00 | login | admin.lara | nova-app01 | user-session |
| 2026-09-01T10:11:00+01:00 | backup_stopped | dev.victor | nova-backup01 | daily-learning-backup |
| 2026-09-01T10:14:05+01:00 | login | dev.auwal | nova-app01 | user-session |
| 2026-09-01T10:15:52+01:00 | login | dev.auwal | nova-app01 | user-session |
| 2026-09-01T10:15:59+01:00 | outbound_connection | ci.runner | nova-ci01 | updates.example:443 |