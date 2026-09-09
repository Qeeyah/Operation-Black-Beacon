#!/usr/bin/env python3

import argparse
import csv
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


REQUIRED_COLUMNS = {
    "_time",
    "event_action",
    "user",
    "src_ip",
    "dest_ip",
    "host",
    "resource",
    "result",
    "severity",
}


def parse_time(value):
    value = value.strip()

    if value.endswith(" BST"):
        value = value[:-4] + "+01:00"
    elif value.endswith(" UTC"):
        value = value[:-4] + "+00:00"

    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    try:
        return datetime.fromisoformat(value)
    except ValueError:
        pass

    formats = [
        "%Y-%m-%d %H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue

    raise ValueError(f"Unrecognised timestamp: {value}")


def level_from_score(score):
    if score >= 90:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 30:
        return "Medium"
    return "Low"


def read_events(path):
    if not path.exists():
        raise ValueError(f"Input file does not exist: {path}")

    if path.stat().st_size == 0:
        raise ValueError("Input CSV is empty")

    with path.open(newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)

        if not reader.fieldnames:
            raise ValueError("CSV has no header")

        missing = REQUIRED_COLUMNS - set(reader.fieldnames)

        if missing:
            raise ValueError(
                "Missing required columns: "
                + ", ".join(sorted(missing))
            )

        events = []

        for row_number, row in enumerate(reader, start=2):
            try:
                timestamp = parse_time(row["_time"])
            except ValueError as exc:
                raise ValueError(
                    f"Row {row_number}: {exc}"
                )

            event = {
                key: (value.strip() if value else "")
                for key, value in row.items()
            }

            event["_dt"] = timestamp

            # Indicator normalisation
            event["user"] = event["user"].lower()
            event["host"] = event["host"].lower()
            event["src_ip"] = event["src_ip"].strip()
            event["dest_ip"] = event["dest_ip"].strip()

            events.append(event)

    if not events:
        raise ValueError("CSV contains no event rows")

    events.sort(key=lambda e: e["_dt"])

    return events


def score_events(events):
    score = 0
    matched = []

    # Authentication activity grouped by user/source
    auth = defaultdict(list)

    for event in events:
        if event["event_action"] == "login":
            auth[(event["user"], event["src_ip"])].append(event)

    password_attack_found = False
    success_after_failure_found = False

    for (user, src_ip), group in auth.items():
        failures = [
            e for e in group
            if e["result"].lower() == "failure"
        ]

        successes = [
            e for e in group
            if e["result"].lower() == "success"
        ]

        if len(failures) >= 8:
            password_attack_found = True

        if failures and successes:
            last_failure = max(e["_dt"] for e in failures)

            if any(e["_dt"] > last_failure for e in successes):
                success_after_failure_found = True

    if password_attack_found:
        score += 20
        matched.append(
            "Eight or more failed logins for one user/source (+20)"
        )

    if success_after_failure_found:
        score += 30
        matched.append(
            "Successful login after repeated failures (+30)"
        )

    # Application token or consent
    if any(
        e["event_action"] in {"token_issued", "consent_granted"}
        for e in events
    ):
        score += 20
        matched.append(
            "New application token or consent activity (+20)"
        )

    # Repository / CI-CD modification
    if any(
        e["event_action"] in {
            "workflow_modified",
            "repository_modified",
            "ci_cd_modified",
        }
        for e in events
    ):
        score += 20
        matched.append(
            "Repository or CI/CD modification (+20)"
        )

    # Archive creation
    archives = [
        e for e in events
        if e["event_action"] == "archive_created"
    ]

    if archives:
        score += 20
        matched.append("Archive creation (+20)")

    # Outbound connection after archive
    outbound_after_archive = False

    for archive in archives:
        for event in events:
            if event["event_action"] != "outbound_connection":
                continue

            same_context = (
                event["user"] == archive["user"]
                or event["host"] == archive["host"]
            )

            if same_context and event["_dt"] > archive["_dt"]:
                outbound_after_archive = True
                break

        if outbound_after_archive:
            break

    if outbound_after_archive:
        score += 25
        matched.append(
            "Outbound connection after archive creation (+25)"
        )

    # Persistence / privilege / backup interference
    impact_actions = {
        "account_created",
        "privileged_command",
        "backup_stopped",
    }

    if any(
        e["event_action"] in impact_actions
        for e in events
    ):
        score += 20
        matched.append(
            "New account, privileged action or backup stop (+20)"
        )

    return score, matched


def build_groups(events):
    groups = defaultdict(int)

    for event in events:
        key = (
            event["user"] or "unknown",
            event["host"] or "unknown",
            event["src_ip"] or "unknown",
        )
        groups[key] += 1

    return [
        {
            "user": user,
            "host": host,
            "src_ip": src_ip,
            "event_count": count,
        }
        for (user, host, src_ip), count
        in sorted(groups.items())
    ]


def important_events(events):
    notable_actions = {
        "login",
        "token_issued",
        "consent_granted",
        "repository_access",
        "workflow_modified",
        "privileged_command",
        "account_created",
        "archive_created",
        "outbound_connection",
        "backup_stopped",
    }

    output = []

    for event in events:
        if event["event_action"] not in notable_actions:
            continue

        output.append({
            "time": event["_dt"].isoformat(),
            "event_action": event["event_action"],
            "user": event["user"],
            "src_ip": event["src_ip"],
            "dest_ip": event["dest_ip"],
            "host": event["host"],
            "resource": event["resource"],
            "result": event["result"],
            "severity": event["severity"],
        })

    return output[:50]


def analyst_actions(level):
    actions = [
        "Review authentication and identity telemetry.",
        "Validate application token and consent activity.",
        "Review repository and CI/CD changes.",
        "Preserve relevant logs and case evidence.",
    ]

    if level in {"High", "Critical"}:
        actions.extend([
            "Consider credential reset and session revocation.",
            "Review and revoke unauthorised application tokens.",
            "Validate newly created accounts and privileged changes.",
            "Confirm backup integrity and recovery readiness.",
            "Investigate outbound connection activity.",
        ])

    return actions


def write_outputs(case_id, input_path, events, output_dir):
    score, matched = score_events(events)
    level = level_from_score(score)

    groups = build_groups(events)
    important = important_events(events)
    actions = analyst_actions(level)

    output_dir.mkdir(parents=True, exist_ok=True)

    summary = {
        "case_id": case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "input_file": str(input_path),
        "event_count": len(events),
        "risk_score": score,
        "risk_level": level,
        "matched_conditions": matched,
        "activity_groups": groups,
        "important_events": important,
        "recommended_analyst_actions": actions,
    }

    summary_path = output_dir / "case_summary.json"

    summary_path.write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    report_path = output_dir / "case_report.md"

    lines = [
        f"# Operation Black Beacon Case Report",
        "",
        f"**Case ID:** {case_id}",
        f"**Risk Score:** {score}",
        f"**Risk Level:** {level}",
        f"**Events Analysed:** {len(events)}",
        "",
        "## Matched Conditions",
    ]

    if matched:
        lines.extend(f"- {item}" for item in matched)
    else:
        lines.append("- No high-risk conditions matched.")

    lines.extend([
        "",
        "## Recommended Analyst Actions",
    ])

    lines.extend(f"- {item}" for item in actions)

    lines.extend([
        "",
        "## Important Events",
        "",
        "| Time | Action | User | Host | Resource |",
        "|---|---|---|---|---|",
    ])

    for event in important:
        lines.append(
            f"| {event['time']} | "
            f"{event['event_action']} | "
            f"{event['user']} | "
            f"{event['host']} | "
            f"{event['resource']} |"
        )

    report_path.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    audit_path = output_dir / "audit.log"

    audit_lines = [
        f"{datetime.now(timezone.utc).isoformat()} case_id={case_id}",
        f"input={input_path}",
        f"events={len(events)}",
        f"score={score}",
        f"level={level}",
    ]

    for condition in matched:
        audit_lines.append(f"matched={condition}")

    audit_path.write_text(
        "\n".join(audit_lines) + "\n",
        encoding="utf-8",
    )

    return score, level, summary_path, report_path, audit_path


def main():
    parser = argparse.ArgumentParser(
        description="Operation Black Beacon case builder"
    )

    parser.add_argument(
        "input_csv",
        help="CSV exported from Splunk"
    )

    parser.add_argument(
        "case_id",
        help="Incident case ID"
    )

    parser.add_argument(
        "--output-dir",
        default="case_output",
        help="Directory for generated case files"
    )

    args = parser.parse_args()

    input_path = Path(args.input_csv)
    output_dir = Path(args.output_dir)

    try:
        events = read_events(input_path)

        score, level, summary, report, audit = write_outputs(
            args.case_id,
            input_path,
            events,
            output_dir,
        )

    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    print(f"Case ID: {args.case_id}")
    print(f"Events analysed: {len(events)}")
    print(f"Risk score: {score}")
    print(f"Risk level: {level}")
    print(f"Created: {summary}")
    print(f"Created: {report}")
    print(f"Created: {audit}")


if __name__ == "__main__":
    main()
