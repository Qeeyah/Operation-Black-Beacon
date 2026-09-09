# MITRE ATT&CK Mapping

Map observed behaviours from the simulated intrusion to MITRE ATT&CK techniques.

---

## ATT&CK Coverage

| Technique | Name                           | Observed Evidence                                               | Defensive Coverage |
| --------- | ------------------------------ | --------------------------------------------------------------- | ------------------ |
| T1110.001 | Password Guessing              | Repeated authentication failures against the developer identity | D1, Hunt 1         |
| T1078     | Valid Accounts                 | Successful authentication after repeated failures               | D1, Hunt 1         |
| T1528     | Steal Application Access Token | Application token and consent activity                          | D2, Hunt 1         |
| T1136.001 | Local Account                  | Creation of `svc-beacon`                                        | D5, Hunt 2         |
| T1560.001 | Archive via Utility            | Creation of `learner_export.tar.gz`                             | D4, Hunt 2         |
| T1490     | Inhibit System Recovery        | Backup interruption                                             | D5, Hunt 2         |

---

## Observed Behaviour View

```text
Password Guessing
       |
Valid Account Access
       |
Application Token Activi
       |
Local Account Creation
       |
Archive Creation
       |
Backup Interference
```

The mapping represents behaviours observed in the controlled synthetic incident.

