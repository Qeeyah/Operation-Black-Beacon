# Operation Black Beacon Architecture

The project uses a lightweight Splunk-based mini-SOC architecture running inside a controlled Ubuntu lab.

```mermaid
flowchart TD

    A[OpenSSH Authentication Logs<br/>bb:auth]
    B[Linux System Logs<br/>bb:linux]
    C[Nginx Access Logs<br/>bb:web]
    D[Python Event Generator<br/>black_beacon_generator.py]

    D --> E[black_beacon.json<br/>bb:scenario]

    A --> F[Splunk Enterprise]
    B --> F
    C --> F
    E --> F

    F --> G[index=black_beacon]

    G --> H[Six-Panel SOC Dashboard]
    G --> I[D1-D5 SPL Detections]
    G --> J[Threat Hunts]
    G --> K[Incident Timeline]

    I --> L[Splunk CSV Export]
    J --> L
    K --> L

    L --> M[Python Case Builder<br/>black_beacon_case_builder.py]

    M --> N[case_summary.json]
    M --> O[case_report.md]
    M --> P[audit.log]

    Q[MITRE ATT&CK Mapping] --> J
    Q --> I
```

## Data Flow

```text
Linux / SSH / Nginx telemetry
            +
Synthetic incident telemetry
            |
      Splunk Enterprise
            |
      index=black_beacon
            |
Dashboard + Detections + Hunts
            |
       Splunk CSV Export
            |
      Python Case Builder
            |
case_summary.json
case_report.md
audit.log
```
