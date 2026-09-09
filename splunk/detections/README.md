# Splunk Detection Pack

This directory contains five Splunk SPL detections developed for **Operation Black Beacon**, a defensive-security mini-SOC project built around a simulated multi-stage intrusion.

This detection pack focuses on **behavioural correlation** rather than identifying individual suspicious events.

Ground-truth labels contained in the synthetic dataset are used only for validation and are **not used by the detection logic**.

---

## Detection Summary

| ID | Detection                              | Objective                                                                          |
| -- | -------------------------------------- | ---------------------------------------------------------------------------------- |
| D1 | Password Attack - Valid Access         | Detect repeated authentication failures followed by successful access              |
| D2 | Identity - CI/CD Compromise            | Correlate token/consent activity with subsequent CI/CD modification                |
| D3 | Web Reconnaissance                     | Detect repeated requests to sensitive web paths                                    |
| D4 | Collection - Outbound Transfer         | Detect archive creation followed by outbound communication                         |
| D5 | Persistence / Operational Interference | Detect combinations of privileged activity, account creation and backup disruption |

---

## D1 - Password Attack → Valid Access

**File:** `D1_password_attack_to_valid_access.spl`

### Objective

Detected eight or more failed authentication attempts followed by a successful login for the same user and source IP within 15 minutes.

### Example attack sequence

```text
Repeated login failures
        |
Successful login
        |
Possible valid account compromise
```

### MITRE ATT&CK

* **T1110.001 — Password Guessing**
* **T1078 — Valid Accounts**

### False positive considerations

Possible benign causes include:

* mistyped passwords
* recently changed passwords
* automated applications using outdated credentials

### Limitation

Distributed password attacks, source-IP rotation or successful access from a different source may evade this correlation.

---

## D2 - Identity - CI/CD Compromise

**File:** `D2_identity_to_cicd_compromise.spl`

### Objective

Detected application token followed by CI/CD workflow modification by the same identity within 30 minutes.

### Example sequence

```text
Token issued
     |
Consent granted
     |
Repository activity
     |
CI/CD workflow modified
```

### MITRE ATT&CK

* **T1528 - Application Access Token**

### False-positive considerations

Legitimate developers may authorise applications and subsequently modify CI/CD workflows during approved development activity.

### Tuning

The detection requires temporal correlation by identity rather than alerting solely on token issuance or repository access.

### Limitation

Activity performed using different service accounts or outside the correlation window may not be detected.

---

## D3 - Web Reconnaissance

**File:** `D3_web_reconnaissance.spl`

### Objective

Detect repeated requests to potentially sensitive web paths.

Monitored paths include:

```text
/admin
/.env
/login
/api/export
```

The detection uses `bb:web`and `bb:scenario` to provide visibility across synthetic scenario activity and independently collected Nginx telemetry.

### False positive considerations

Administrators, application developers and vulnerability-management tools may legitimately request some of these paths.

### Tuning

Multiple suspicious paths are required rather than alerting on a single request.

### Limitation

Low-and-slow reconnaissance or probing of paths not included in the rule may evade detection.

---

## D4 - Collection - Outbound Transfer

**File:** `D4_collection_to_outbound_transfer.spl`

### Objective

Detected archive creation followed by outbound network activity for the same user or host within 15 minutes.

### Example sequence

```text
learner_export.tar.gz
        |
Outbound connection
        |
203.0.113.50:443
```

This activity is treated as **possible exfiltration**, not confirmed exfiltration, because an outbound connection alone does not prove that data was transferred.

### MITRE ATT&CK

* **T1560.001 - Archive via Utility**

### False positive considerations

Legitimate processes may create archives before:

* backups
* software deployment
* file transfers
* approved data exports

### Limitation

Direct transfer without archive creation, delayed transfer or transfer from another host may evade the correlation.

---

## D5 - Persistence / Operational Interference

**File:** `D5_persistence_operational_interference.spl`

### Objective

Detect combinations of suspicious administrative behaviour including:

* privileged command execution
* local account creation
* backup interruption

### Example sequence

```text
Privileged command
        |
Local account created
        |
Backup stopped
```

### MITRE ATT&CK

* **T1136.001 - Local Account**
* **T1490 - Inhibit System Recovery**

### False positive considerations

Administrators may legitimately:

* execute privileged commands
* create service accounts
* stop backup jobs during maintenance

### Tuning

The detection requires multiple distinct administrative actions from the same identity to increase confidence.

### Limitation

A threat actor performing only one action or distributing activity across several identities may evade the rule.

---

## Detection Engineering Approach

Each detection was developed using the following process:

```text
Define behaviour
      |
Write SPL
      |
Positive test
      |
Benign / negative test
      |
False positive analysis
      |
Tune threshold / correlation
      |
Document limitations
```

This project deliberately include benign distractor events to ensure detections were tested against realistic alternatives rather than only malicious data.

---

## Design Decision

The dataset includes a field called:

```text
simulation_class
```

with values such as:

```text
normal
suspicious
distractor
```

This field acts as **ground truth for validation only**.

None of the production detection searches use `simulation_class` to decide whether activity is suspicious.

Detection decisions are based on observable telemetry including:

* time
* user
* source IP
* host
* event action
* result
* resource
* application

This prevents the detections from being aware of which events were generated as malicious.

---

## Environment

The detections were tested against:

```text
index=black_beacon
```

using telemetry from:

```text
bb:auth
bb:linux
bb:web
bb:scenario
```

All suspicious indicators use fictional identities and documentation-only IP ranges.

---

## Disclaimer

These detections were developed by me in a controlled security lab.

**Note:** Thresholds and correlation windows should be tuned according to normal behaviour, authentication volume, asset criticality and operational requirements before deployment in a production SOC.
