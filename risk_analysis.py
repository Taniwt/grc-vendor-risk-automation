"""Vendor risk analysis.

Reads the third-party risk register, scores each vendor against the risk
matrix and remediation SLA policy defined in risk_policy.json, maps every
finding to SOC 2 / ISO 27001 / NIST CSF controls, and writes a summary of
the vendors that require GRC follow-up.

Rows that cannot be evaluated are recorded in a data-quality report rather
than aborting the run.
"""

import csv
import json
import sys
from datetime import date, datetime, timedelta
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

INPUT_FILE = BASE_DIR / "vendor_risk_register.csv"
POLICY_FILE = BASE_DIR / "risk_policy.json"
MAPPINGS_FILE = BASE_DIR / "control_mappings.csv"
OUTPUT_FILE = BASE_DIR / "risk_summary_report.csv"
ISSUES_FILE = BASE_DIR / "data_quality_issues.csv"

# Columns the analysis cannot run without.
REQUIRED_COLUMNS = [
    "Vendor Name",
    "Data Classification",
    "SOC 2",
    "MFA",
    "Encryption",
    "Finding",
    "Finding Category",
    "Likelihood",
    "Impact",
    "Risk Level",
    "Remediation Owner",
    "Identified Date",
    "Due Date",
    "Status",
]

REPORT_COLUMNS = [
    "Vendor Name",
    "Data Classification",
    "Register Risk Level",
    "Computed Risk Level",
    "Risk Score",
    "Adjusted Risk Level",
    "Finding",
    "Finding Category",
    "SOC 2 (TSC)",
    "ISO 27001:2022 Annex A",
    "NIST CSF 2.0",
    "Status",
    "Identified Date",
    "Due Date",
    "SLA Due Date",
    "Days Past Due",
    "Aging Bucket",
    "Remediation Owner",
    "Review Reason",
]

ISSUE_COLUMNS = ["Row", "Vendor Name", "Severity", "Issue"]


class RowError(Exception):
    """A row cannot be evaluated and must be reported as a data-quality issue."""


class ConfigError(Exception):
    """The register, policy, or control mappings could not be loaded."""


def normalize(value):
    """Lower-case and trim a register value so comparisons are case-insensitive."""
    return (value or "").strip().lower()


def parse_date(value, field_name):
    """Parse an ISO date, naming the offending field if it is malformed."""
    text = (value or "").strip()

    if not text:
        raise RowError(f"{field_name} is empty")

    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        raise RowError(f"{field_name} is not a valid YYYY-MM-DD date: {text!r}")


def load_policy(path):
    """Load the risk matrix, escalation, and SLA policy."""
    try:
        with path.open(encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise ConfigError(f"Policy file not found: {path}")
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Policy file is not valid JSON ({path}): {exc}")


def load_control_mappings(path):
    """Load the finding-category to control-framework mapping table."""
    try:
        with path.open(newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))
    except FileNotFoundError:
        raise ConfigError(f"Control mappings file not found: {path}")

    mappings = {}

    for row in rows:
        category = normalize(row.get("Finding Category"))

        if category:
            mappings[category] = {
                "SOC 2 (TSC)": (row.get("SOC 2 (TSC)") or "").strip(),
                "ISO 27001:2022 Annex A": (row.get("ISO 27001:2022 Annex A") or "").strip(),
                "NIST CSF 2.0": (row.get("NIST CSF 2.0") or "").strip(),
            }

    return mappings


def load_register(path):
    """Load the vendor risk register and confirm the expected columns exist."""
    try:
        with path.open(newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            fieldnames = reader.fieldnames or []
            rows = list(reader)
    except FileNotFoundError:
        raise ConfigError(f"Vendor risk register not found: {path}")

    missing = [column for column in REQUIRED_COLUMNS if column not in fieldnames]

    if missing:
        raise ConfigError(
            "Register is missing required column(s): " + ", ".join(missing)
        )

    return rows


def score_risk(likelihood, impact, policy):
    """Compute the inherent risk score and level from the likelihood/impact matrix."""
    matrix = policy["risk_matrix"]

    likelihood_weight = matrix["likelihood_weights"].get(normalize(likelihood))
    impact_weight = matrix["impact_weights"].get(normalize(impact))

    if likelihood_weight is None:
        raise RowError(f"Unrecognised Likelihood value: {likelihood!r}")

    if impact_weight is None:
        raise RowError(f"Unrecognised Impact value: {impact!r}")

    score = likelihood_weight * impact_weight

    for threshold in matrix["score_thresholds"]:
        if score <= threshold["max_score"]:
            return score, threshold["level"]

    # Score exceeds every band; fall back to the most severe defined level.
    return score, matrix["score_thresholds"][-1]["level"]


def escalate_for_classification(level, classification, policy):
    """Raise the risk level where the vendor handles more sensitive data."""
    order = policy["risk_level_order"]
    steps = policy["data_classification_escalation"].get(normalize(classification))

    if steps is None:
        raise RowError(f"Unrecognised Data Classification: {classification!r}")

    index = min(order.index(level) + steps, len(order) - 1)

    return order[index]


def canonical_level(value, policy):
    """Match a register-supplied risk level to a policy level, ignoring case."""
    for level in policy["risk_level_order"]:
        if normalize(value) == normalize(level):
            return level

    raise RowError(f"Unrecognised Risk Level: {value!r}")


def sla_days_for(level, policy):
    """Return the remediation SLA, in days, for an adjusted risk level."""
    days = policy["remediation_sla_days"].get(normalize(level))

    if days is None:
        raise RowError(f"No remediation SLA defined for risk level: {level!r}")

    return days


def aging_bucket(days_past_due, policy):
    """Bucket an overdue item by how long it has been outstanding."""
    if days_past_due <= 0:
        return "Not yet due"

    for bucket in policy["aging_buckets"]:
        limit = bucket["max_days_past_due"]

        if limit is None or days_past_due <= limit:
            return bucket["label"]

    return policy["aging_buckets"][-1]["label"]


def find_control_gaps(row, policy):
    """Identify security-control attestations that are absent or unevidenced.

    A value of "No" is a missing control; a blank or "Unknown" value is
    missing evidence. Both are gaps, but they are different findings.
    """
    gaps = []

    for column, category in policy["assessed_controls"].items():
        if column.startswith("_"):
            continue

        value = normalize(row.get(column))

        if value in policy["control_attested_values"]:
            continue

        description = policy["control_gap_values"].get(value)

        if description is None:
            raise RowError(f"Unrecognised value in {column} column: {row.get(column)!r}")

        gaps.append({"column": column, "category": category, "description": description})

    return gaps


def lookup_controls(category, mappings, policy):
    """Return the framework references for a finding category."""
    key = normalize(category)

    if key in [normalize(v) for v in policy["no_finding_categories"]]:
        return {column: "" for column in
                ("SOC 2 (TSC)", "ISO 27001:2022 Annex A", "NIST CSF 2.0")}

    if key not in mappings:
        raise RowError(f"Finding Category has no control mapping: {category!r}")

    # Copy: the caller merges gap references into this dict, and the mapping
    # table is shared by every row that uses the same category.
    return dict(mappings[key])


def evaluate_row(row, policy, mappings, as_of):
    """Evaluate one register row. Returns (report_row_or_None, warnings)."""
    warnings = []

    vendor = (row.get("Vendor Name") or "").strip()

    if not vendor:
        raise RowError("Vendor Name is empty")

    classification = (row.get("Data Classification") or "").strip()
    status = (row.get("Status") or "").strip()
    finding = (row.get("Finding") or "").strip()
    category = (row.get("Finding Category") or "").strip()

    identified_date = parse_date(row.get("Identified Date"), "Identified Date")
    due_date = parse_date(row.get("Due Date"), "Due Date")

    if due_date < identified_date:
        warnings.append("Due Date precedes Identified Date")

    # 1. Score the vendor from the likelihood/impact matrix rather than
    #    trusting the Risk Level recorded in the register.
    score, computed_level = score_risk(row.get("Likelihood"), row.get("Impact"), policy)
    register_level = canonical_level(row.get("Risk Level"), policy)
    adjusted_level = escalate_for_classification(computed_level, classification, policy)

    is_closed = normalize(status) in policy["closed_statuses"]
    has_finding = normalize(finding) not in [
        normalize(v) for v in policy["no_finding_values"]
    ]

    # 2. Remediation SLA is derived from the adjusted level and the date the
    #    finding was identified; the register's own due date is validated
    #    against it.
    sla_days = sla_days_for(adjusted_level, policy)
    sla_due_date = identified_date + timedelta(days=sla_days)

    days_past_due = (as_of - due_date).days if not is_closed else 0
    days_past_due = max(days_past_due, 0)
    days_until_due = (due_date - as_of).days

    control_gaps = find_control_gaps(row, policy)
    controls = lookup_controls(category, mappings, policy)

    # A finding category is expected whenever there is a finding to categorise.
    if has_finding and normalize(category) in [
        normalize(v) for v in policy["no_finding_categories"]
    ]:
        warnings.append("Open finding has no Finding Category assigned")

    # Merge in the control references implied by any attestation gaps, so the
    # report cites a framework control for gaps the register did not describe.
    for gap in control_gaps:
        gap_controls = lookup_controls(gap["category"], mappings, policy)

        for column, reference in gap_controls.items():
            existing = [part.strip() for part in controls[column].split(";") if part.strip()]

            for part in (p.strip() for p in reference.split(";")):
                if part and part not in existing:
                    existing.append(part)

            controls[column] = "; ".join(existing)

    # 3. Decide whether this vendor needs GRC follow-up, and record why.
    reasons = []

    if adjusted_level in {"High", "Critical"}:
        reason = f"{adjusted_level} risk"

        if adjusted_level != computed_level:
            reason += f" (escalated from {computed_level} — {classification} data)"

        reasons.append(reason)

    if not is_closed and has_finding:
        reasons.append(f"Open finding ({status})")

    if days_past_due > 0:
        reasons.append(f"Overdue remediation ({days_past_due} days)")
    elif not is_closed and 0 <= days_until_due <= policy["early_warning_days"]:
        reasons.append(f"Due within {policy['early_warning_days']} days")

    for gap in control_gaps:
        reasons.append(f"{gap['description']}: {gap['column']}")

    if register_level != computed_level:
        reasons.append(
            f"Risk rating mismatch (register={register_level}, computed={computed_level})"
        )

    if not is_closed and due_date > sla_due_date:
        overshoot = (due_date - sla_due_date).days
        reasons.append(
            f"SLA breach: due date exceeds {adjusted_level} SLA "
            f"of {sla_days} days by {overshoot} days"
        )

    if not reasons:
        return None, warnings

    report_row = {
        "Vendor Name": vendor,
        "Data Classification": classification,
        "Register Risk Level": register_level,
        "Computed Risk Level": computed_level,
        "Risk Score": score,
        "Adjusted Risk Level": adjusted_level,
        "Finding": finding,
        "Finding Category": category,
        "SOC 2 (TSC)": controls["SOC 2 (TSC)"],
        "ISO 27001:2022 Annex A": controls["ISO 27001:2022 Annex A"],
        "NIST CSF 2.0": controls["NIST CSF 2.0"],
        "Status": status,
        "Identified Date": identified_date.isoformat(),
        "Due Date": due_date.isoformat(),
        "SLA Due Date": sla_due_date.isoformat(),
        "Days Past Due": days_past_due,
        "Aging Bucket": aging_bucket(days_past_due, policy),
        "Remediation Owner": (row.get("Remediation Owner") or "").strip(),
        "Review Reason": "; ".join(reasons),
    }

    return report_row, warnings


def sort_key(report_row, policy):
    """Order the report by severity, then by how long remediation has slipped."""
    order = policy["risk_level_order"]

    return (
        -order.index(report_row["Adjusted Risk Level"]),
        -report_row["Days Past Due"],
        report_row["Vendor Name"],
    )


def write_csv(path, fieldnames, rows):
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def run(as_of=None):
    """Run the analysis. Returns a process exit code."""
    as_of = as_of or date.today()

    try:
        policy = load_policy(POLICY_FILE)
        mappings = load_control_mappings(MAPPINGS_FILE)
        rows = load_register(INPUT_FILE)
    except ConfigError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    findings = []
    issues = []
    seen_vendors = {}

    # Row 1 is the header, so register rows start at line 2.
    for line_number, row in enumerate(rows, start=2):
        vendor = (row.get("Vendor Name") or "").strip()

        # Duplicate vendor names make remediation ownership ambiguous.
        if vendor:
            if vendor in seen_vendors:
                issues.append({
                    "Row": line_number,
                    "Vendor Name": vendor,
                    "Severity": "Warning",
                    "Issue": f"Duplicate vendor name (first seen on row {seen_vendors[vendor]})",
                })
            else:
                seen_vendors[vendor] = line_number

        try:
            report_row, warnings = evaluate_row(row, policy, mappings, as_of)
        except RowError as exc:
            issues.append({
                "Row": line_number,
                "Vendor Name": vendor or "(unknown)",
                "Severity": "Error",
                "Issue": f"Row skipped — {exc}",
            })
            continue

        for warning in warnings:
            issues.append({
                "Row": line_number,
                "Vendor Name": vendor,
                "Severity": "Warning",
                "Issue": warning,
            })

        if report_row:
            findings.append(report_row)

    findings.sort(key=lambda item: sort_key(item, policy))

    write_csv(OUTPUT_FILE, REPORT_COLUMNS, findings)
    write_csv(ISSUES_FILE, ISSUE_COLUMNS, issues)

    skipped = sum(1 for issue in issues if issue["Severity"] == "Error")
    evaluated = len(rows) - skipped

    by_level = {}
    for item in findings:
        by_level[item["Adjusted Risk Level"]] = by_level.get(item["Adjusted Risk Level"], 0) + 1

    overdue = sum(1 for item in findings if item["Days Past Due"] > 0)
    mismatches = sum(1 for item in findings
                     if item["Register Risk Level"] != item["Computed Risk Level"])
    sla_breaches = sum(1 for item in findings if "SLA breach" in item["Review Reason"])

    level_summary = ", ".join(
        f"{level}: {by_level[level]}"
        for level in reversed(policy["risk_level_order"])
        if level in by_level
    ) or "none"

    print(f"As of:               {as_of.isoformat()}")
    print(f"Policy version:      {policy['policy_version']}")
    print(f"Vendors evaluated:   {evaluated} of {len(rows)}")
    print(f"Flagged for review:  {len(findings)} ({level_summary})")
    print(f"Overdue remediation: {overdue}")
    print(f"SLA policy breaches: {sla_breaches}")
    print(f"Risk rating mismatches: {mismatches}")
    print(f"Data-quality issues: {len(issues)} ({skipped} row(s) skipped)")
    print(f"Report written to:   {OUTPUT_FILE.name}")
    print(f"Issues written to:   {ISSUES_FILE.name}")

    return 0


def main():
    return run()


if __name__ == "__main__":
    sys.exit(main())
