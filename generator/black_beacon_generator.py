#!/usr/bin/env python3

import argparse
import json
import random
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path


BST = timezone(timedelta(hours=1))

BASE_TIME = datetime(
    2026, 9, 1, 9, 0, 0,
    tzinfo=BST
)

ATTACKER_IP = "198.51.100.77"
INTERNAL_APP_IP = "192.0.2.20"
INTERNAL_CI_IP = "192.0.2.30"
EXFIL_IP = "203.0.113.50"

COMPROMISED_USER = "dev.victor"

HOSTS = [
    "nova-app01",
    "nova-dev01",
    "nova-ci01",
    "nova-backup01",
]

NORMAL_USERS = [
    "analyst.qeeyah",
    "dev.auwal",
    "admin.lara",
    "backup.service",
    "ci.runner",
]

NORMAL_SOURCE_IPS = [
    "198.51.100.10",
    "198.51.100.11",
    "198.51.100.12",
    "198.51.100.20",
    "198.51.100.21",
]

DESTINATION_IPS = [
    "192.0.2.20",
    "192.0.2.21",
    "192.0.2.30",
    "192.0.2.40",
]

NORMAL_WEB_PATHS = [
    "/",
    "/home",
    "/courses",
    "/profile",
    "/api/catalog",
    "/api/status",
]

SUSPICIOUS_WEB_PATHS = [
    "/admin",
    "/.env",
    "/login",
    "/api/export",
]


def make_event(
    timestamp,
    event_category,
    event_action,
    user,
    src_ip,
    dest_ip,
    host,
    application,
    resource,
    result,
    severity,
    message,
    simulation_class
):
    return {
        "time": timestamp.isoformat(),
        "event_category": event_category,
        "event_action": event_action,
        "user": user,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "host": host,
        "application": application,
        "resource": resource,
        "result": result,
        "severity": severity,
        "message": message,
        "simulation_class": simulation_class,
    }


def random_timestamp(rng, start_minute=0, end_minute=120):
    seconds = rng.randint(
        start_minute * 60,
        end_minute * 60
    )
    return BASE_TIME + timedelta(seconds=seconds)


def generate_normal_events(rng):
    events = []

    # 30 identity events
    for _ in range(30):
        user = rng.choice(NORMAL_USERS[:-2])
        result = rng.choices(
            ["success", "failure"],
            weights=[90, 10],
            k=1
        )[0]

        events.append(
            make_event(
                random_timestamp(rng),
                "identity",
                "login",
                user,
                rng.choice(NORMAL_SOURCE_IPS),
                INTERNAL_APP_IP,
                "nova-app01",
                "NovaLearn Portal",
                "user-session",
                result,
                "low",
                f"Routine authentication event for {user}",
                "normal",
            )
        )

    # 40 normal web events
    for _ in range(40):
        path = rng.choice(NORMAL_WEB_PATHS)

        events.append(
            make_event(
                random_timestamp(rng),
                "web",
                "http_request",
                rng.choice(NORMAL_USERS[:-2]),
                rng.choice(NORMAL_SOURCE_IPS),
                INTERNAL_APP_IP,
                "nova-app01",
                "nginx",
                path,
                "success",
                "low",
                f"Routine HTTP GET request to {path} returned status 200",
                "normal",
            )
        )

    # 20 Linux events
    linux_actions = [
        "process_start",
        "package_check",
        "session_open",
        "file_read",
    ]

    for _ in range(20):
        action = rng.choice(linux_actions)

        events.append(
            make_event(
                random_timestamp(rng),
                "linux",
                action,
                rng.choice(NORMAL_USERS),
                rng.choice(NORMAL_SOURCE_IPS),
                rng.choice(DESTINATION_IPS),
                rng.choice(HOSTS),
                "linux",
                "/var/log/system",
                "success",
                "low",
                f"Routine Linux activity: {action}",
                "normal",
            )
        )

    # 20 cloud/application events
    cloud_actions = [
        "session_refresh",
        "application_access",
        "api_read",
        "token_validate",
    ]

    for _ in range(20):
        action = rng.choice(cloud_actions)

        events.append(
            make_event(
                random_timestamp(rng),
                "cloud_application",
                action,
                rng.choice(NORMAL_USERS[:-2]),
                rng.choice(NORMAL_SOURCE_IPS),
                INTERNAL_APP_IP,
                "nova-app01",
                "NovaLearn Cloud",
                "student-api",
                "success",
                "low",
                f"Routine cloud/application operation: {action}",
                "normal",
            )
        )

    # 20 repository / CI-CD events
    repository_actions = [
        "repository_read",
        "pull_request_view",
        "pipeline_read",
        "approved_commit",
    ]

    for _ in range(20):
        action = rng.choice(repository_actions)

        events.append(
            make_event(
                random_timestamp(rng),
                "repository_ci",
                action,
                rng.choice(["dev.tari", "ci.runner"]),
                rng.choice(NORMAL_SOURCE_IPS),
                INTERNAL_CI_IP,
                "nova-ci01",
                "NovaForge",
                "nova-learner-api",
                "success",
                "low",
                f"Approved development activity: {action}",
                "normal",
            )
        )

    # 10 network events
    for _ in range(10):
        events.append(
            make_event(
                random_timestamp(rng),
                "network",
                "outbound_connection",
                rng.choice(NORMAL_USERS),
                rng.choice(DESTINATION_IPS),
                "203.0.113.10",
                rng.choice(HOSTS),
                "network",
                "updates.example:443",
                "success",
                "low",
                "Approved outbound HTTPS connection to updates.example",
                "normal",
            )
        )

    # 10 normal backup events
    backup_actions = [
        "backup_started",
        "backup_completed",
    ]

    for _ in range(10):
        action = rng.choice(backup_actions)

        events.append(
            make_event(
                random_timestamp(rng),
                "backup",
                action,
                "backup.service",
                "192.0.2.40",
                "192.0.2.41",
                "nova-backup01",
                "NovaBackup",
                "daily-learning-backup",
                "success",
                "low",
                f"Scheduled backup activity: {action}",
                "normal",
            )
        )

    return events


def generate_suspicious_events():
    events = []

    # 1. Password attack: 12 failures
    attack_start = BASE_TIME + timedelta(minutes=30)

    for i in range(12):
        events.append(
            make_event(
                attack_start + timedelta(seconds=i * 35),
                "identity",
                "login",
                COMPROMISED_USER,
                ATTACKER_IP,
                INTERNAL_APP_IP,
                "nova-app01",
                "NovaLearn Portal",
                "developer-account",
                "failure",
                "medium",
                "Synthetic failed developer login for capstone testing",
                "suspicious",
            )
        )

    # 2. Successful access after failures
    success_time = attack_start + timedelta(minutes=8)

    events.append(
        make_event(
            success_time,
            "identity",
            "login",
            COMPROMISED_USER,
            ATTACKER_IP,
            INTERNAL_APP_IP,
            "nova-app01",
            "NovaLearn Portal",
            "developer-account",
            "success",
            "high",
            "Successful login following repeated authentication failures",
            "suspicious",
        )
    )

    # 3. Token and consent abuse
    events.append(
        make_event(
            success_time + timedelta(minutes=3),
            "cloud_application",
            "token_issued",
            COMPROMISED_USER,
            ATTACKER_IP,
            INTERNAL_APP_IP,
            "nova-app01",
            "BeaconSync",
            "developer-api-token",
            "success",
            "high",
            "New application token issued to BeaconSync",
            "suspicious",
        )
    )

    events.append(
        make_event(
            success_time + timedelta(minutes=5),
            "cloud_application",
            "consent_granted",
            COMPROMISED_USER,
            ATTACKER_IP,
            INTERNAL_APP_IP,
            "nova-app01",
            "BeaconSync",
            "repo.read workflow.write",
            "success",
            "high",
            "Developer granted new permissions to BeaconSync",
            "suspicious",
        )
    )

    # 4. Repository access
    events.append(
        make_event(
            success_time + timedelta(minutes=9),
            "repository_ci",
            "repository_access",
            COMPROMISED_USER,
            ATTACKER_IP,
            INTERNAL_CI_IP,
            "nova-ci01",
            "NovaForge",
            "nova-learner-api",
            "success",
            "medium",
            "Unexpected repository access from new source address",
            "suspicious",
        )
    )

    # CI/CD modification
    events.append(
        make_event(
            success_time + timedelta(minutes=12),
            "repository_ci",
            "workflow_modified",
            COMPROMISED_USER,
            ATTACKER_IP,
            INTERNAL_CI_IP,
            "nova-ci01",
            "NovaForge CI",
            ".ci/deploy-learning-api.yml",
            "success",
            "critical",
            "Synthetic modification of CI/CD workflow",
            "suspicious",
        )
    )

    # 5. Web reconnaissance: 8 requests
    web_start = success_time + timedelta(minutes=15)

    paths = [
        "/admin",
        "/.env",
        "/login",
        "/api/export",
        "/admin",
        "/.env",
        "/api/export",
        "/login",
    ]

    for i, path in enumerate(paths):
        events.append(
            make_event(
                web_start + timedelta(seconds=i * 25),
                "web",
                "http_request",
                COMPROMISED_USER,
                ATTACKER_IP,
                INTERNAL_APP_IP,
                "nova-app01",
                "nginx",
                path,
                "failure",
                "medium",
                f"Repeated suspicious request to {path} returned status 404",
                "suspicious",
            )
        )

    # 6. Privileged action
    events.append(
        make_event(
            success_time + timedelta(minutes=21),
            "linux",
            "privileged_command",
            COMPROMISED_USER,
            ATTACKER_IP,
            INTERNAL_APP_IP,
            "nova-app01",
            "sudo",
            "/etc/sudoers",
            "success",
            "high",
            "Synthetic privileged command executed by developer account",
            "suspicious",
        )
    )

    # Persistence-like account creation
    events.append(
        make_event(
            success_time + timedelta(minutes=23),
            "linux",
            "account_created",
            COMPROMISED_USER,
            ATTACKER_IP,
            INTERNAL_APP_IP,
            "nova-app01",
            "useradd",
            "svc-beacon",
            "success",
            "critical",
            "Synthetic local service account creation event",
            "suspicious",
        )
    )

    # 7. Archive creation
    events.append(
        make_event(
            success_time + timedelta(minutes=27),
            "linux",
            "archive_created",
            COMPROMISED_USER,
            ATTACKER_IP,
            INTERNAL_APP_IP,
            "nova-app01",
            "tar",
            "learner_export.tar.gz",
            "success",
            "high",
            "Synthetic learner export archive created",
            "suspicious",
        )
    )

    # 8. Outbound connection after archive
    events.append(
        make_event(
            success_time + timedelta(minutes=30),
            "network",
            "outbound_connection",
            COMPROMISED_USER,
            INTERNAL_APP_IP,
            EXFIL_IP,
            "nova-app01",
            "network",
            "203.0.113.50:443",
            "success",
            "critical",
            "Synthetic outbound connection after archive creation",
            "suspicious",
        )
    )

    # 9. Backup interference
    events.append(
        make_event(
            success_time + timedelta(minutes=33),
            "backup",
            "backup_stopped",
            COMPROMISED_USER,
            ATTACKER_IP,
            "192.0.2.40",
            "nova-backup01",
            "NovaBackup",
            "daily-learning-backup",
            "success",
            "critical",
            "Synthetic backup job stop event",
            "suspicious",
        )
    )

    return events


def generate_distractor_events(rng):
    events = []

    distractors = [
        (
            "identity",
            "login",
            "dev.auwal",
            "failure",
            "Mistyped password during routine developer login"
        ),
        (
            "web",
            "http_request",
            "admin.lara",
            "success",
            "Authorised administrator accessed /admin"
        ),
        (
            "repository_ci",
            "workflow_modified",
            "ci.runner",
            "success",
            "Approved CI/CD maintenance change"
        ),
        (
            "backup",
            "backup_completed",
            "backup.service",
            "success",
            "Scheduled benign backup completed successfully"
        ),
        (
            "cloud_application",
            "token_issued",
            "analyst.qeeyah",
            "success",
            "Approved short-lived application token issued"
        ),
    ]

    for i in range(20):
        category, action, user, result, message = distractors[
            i % len(distractors)
        ]

        if category == "web":
            application = "nginx"
            resource = "/admin"
        elif category == "repository_ci":
            application = "NovaForge CI"
            resource = "approved-maintenance.yml"
        elif category == "backup":
            application = "NovaBackup"
            resource = "daily-learning-backup"
        elif category == "cloud_application":
            application = "NovaLearn Cloud"
            resource = "approved-reporting-token"
        else:
            application = "NovaLearn Portal"
            resource = "developer-account"

        events.append(
            make_event(
                random_timestamp(rng, 5, 115),
                category,
                action,
                user,
                rng.choice(NORMAL_SOURCE_IPS),
                rng.choice(DESTINATION_IPS),
                rng.choice(HOSTS),
                application,
                resource,
                result,
                "low",
                message,
                "distractor",
            )
        )

    return events


def main():
    parser = argparse.ArgumentParser(
        description="Generate reproducible Operation Black Beacon telemetry."
    )

    parser.add_argument(
        "--output",
        required=True,
        help="Output JSON Lines file"
    )

    parser.add_argument(
        "--seed",
        required=True,
        type=int,
        help="Random seed for reproducibility"
    )

    args = parser.parse_args()

    rng = random.Random(args.seed)

    events = []
    events.extend(generate_normal_events(rng))
    events.extend(generate_suspicious_events())
    events.extend(generate_distractor_events(rng))

    events.sort(key=lambda x: x["time"])

    for i, event in enumerate(events, start=1):
        event["event_id"] = f"BB-EVT-{i:04d}"

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")

    class_counts = Counter(
        event["simulation_class"]
        for event in events
    )

    category_counts = Counter(
        event["event_category"]
        for event in events
    )

    print(f"Generated {len(events)} events")
    print(f"Output: {output_path}")
    print(f"Seed: {args.seed}")

    print("\nSimulation classes:")
    for name, count in sorted(class_counts.items()):
        print(f"  {name}: {count}")

    print("\nCategories:")
    for name, count in sorted(category_counts.items()):
        print(f"  {name}: {count}")

    print(f"\nFirst event: {events[0]['time']}")
    print(f"Last event:  {events[-1]['time']}")


if __name__ == "__main__":
    main()
