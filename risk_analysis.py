import csv
from datetime import date, datetime
from pathlib import Path


INPUT_FILE = Path("vendor_risk_register.csv")
OUTPUT_FILE = Path("risk_summary_report.csv")

TODAY = date.today()


def parse_date(value):
    return datetime.strptime(value, "%Y-%m-%d").date()


def main():
    with INPUT_FILE.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    findings = []

    for row in rows:
        due_date = parse_date(row["Due Date"])

        # Determine whether the remediation item is still unresolved.
        is_open = row["Status"].lower() != "closed"

        # Determine whether an unresolved remediation deadline has passed.
        is_overdue = is_open and due_date < TODAY

        # Identify vendors already assessed as High or Critical risk.
        high_risk = row["Risk Level"] in {"High", "Critical"}

        # Check for missing or unknown security-control information.
        missing_fields = []

        for field in ["SOC 2", "MFA", "Encryption"]:
            if row[field].strip().lower() in {"", "unknown"}:
                missing_fields.append(field)

        # Record why this vendor requires additional GRC review.
        reasons = []

        if high_risk:
            reasons.append("High/Critical risk")

        if is_overdue:
            reasons.append("Overdue remediation")

        if missing_fields:
            reasons.append(
                "Missing/unknown: " + ", ".join(missing_fields)
            )

        # Add vendors requiring attention to the findings list.
        if reasons:
            findings.append({
                "Vendor Name": row["Vendor Name"],
                "Risk Level": row["Risk Level"],
                "Finding": row["Finding"],
                "Status": row["Status"],
                "Due Date": row["Due Date"],
                "Remediation Owner": row["Remediation Owner"],
                "Review Reason": "; ".join(reasons),
            })

    # Define the columns for the generated GRC summary report.
    fieldnames = [
        "Vendor Name",
        "Risk Level",
        "Finding",
        "Status",
        "Due Date",
        "Remediation Owner",
        "Review Reason",
    ]

    # Create the risk summary report.
    with OUTPUT_FILE.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(findings)

    # Display a summary when the analysis finishes.
    print(f"Reviewed {len(rows)} vendors.")
    print(f"Flagged {len(findings)} vendors for follow-up.")
    print(f"Report written to: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
