# Threat Hunting

This directory contains the hypothesis driven threat hunts developed for **Operation Black Beacon**.

The goal of the hunts is to move beyond individual alerts and determine whether multiple events form a meaningful attack sequence.

---

## Hunt 1 - Cross System Identity Abuse

**Hypothesis**
A single compromised developer identity was used across authentication, application, repository, and CI/CD activity.

### Key Sequence

```text
Repeated failed authentication
        |
Successful access
        |
Application token issuance
        |
Application consent
        |
Repository access
        |
CI/CD workflow modification
```

### Conclusion

This hypothesis was supported with **high confidence**.

The same fictional developer identity was observed across multiple stages of the simulated intrusion.

### Primary Detection Gap

The correlation depends on consistent identity information across telemetry sources.

Activity performed using separate service accounts, stolen tokens, or incomplete logging could reduce visibility.

---

## Hunt 2 - Persistence and Operational Impact

**Hypothesis:**
The compromised identity performed collection, persistence-like activity, outbound transfer, and backup interference.

### Key Sequence

```text
Privileged command
        |
Local account creation
        |
Archive creation
        |
Outbound connection
        |
Backup interruption
```

### Findings

* Privilege activity: Observed
* Persistence-like activity: Observed
* Collection: Observed
* Backup interference: Observed
* Possible exfiltration: Observed, but not confirmed

### Confidence

**High** confidence in the observed host and identity activity.

**Moderate** confidence in actual exfiltration because an outbound connection does not prove that data was transferred.

### Primary Detection Gap

The available network telemetry does not include:

* packet payloads
* file transfer confirmation
* transferred byte counts

---

## Threat Hunting Method

Each hunt follows this process:

```text
Hypothesis
    |
Define scope
    |
Identify telemetry
    |
Run SPL
    |
Review supporting events
    |
Consider benign alternatives
    |
Assess confidence
    |
Document detection gaps
    |
Conclusion
```

This structure helps to ensure that findings are evidence based rather than based only on individual alerts.

---

## Files

* `Hunt1_cross_system_identity_abuse.md`
* `Hunt2_collection_persistence_impact.md`

---

## Environment

The hunts were performed against:

```text
index=black_beacon
```

using synthetic and locally collected telemetry from the Operation Black Beacon mini-SOC.

All suspicious indicators are fictional and documentation-only IP address ranges were used.

---

## Disclaimer

These threat hunts were developed by me for a controlled defensive-security environment.

The findings demonstrate investigative methodology and should not be interpreted as attribution to any real threat actor or infrastructure.
