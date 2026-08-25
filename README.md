# GRC Vendor Risk Automation

A Python automation that evaluates a third-party (vendor) cybersecurity risk register, scores each
vendor against a documented risk policy, identifies security control gaps, maps every finding to
recognised control frameworks, and produces audit-ready remediation reporting.

The project replaces a manual, spreadsheet-driven vendor review with a repeatable, policy-driven
process where the scoring rules, SLAs, and control mappings live in version-controlled
configuration rather than in someone's head.

**Note on data:** the vendor register in this repository is fictional sample data created for
demonstration purposes. It contains no real vendor, customer, or company information.

---

## What This Project Demonstrates

| Area | How it appears in this project |
|---|---|
| Governance, Risk & Compliance | Risk policy, SLAs, and control mappings maintained as reviewable configuration |
| Third-party / vendor risk assessment | 15-vendor risk register evaluated end to end |
| Python security automation | Single-command run, standard library only, no external dependencies |
| Automated risk scoring | Likelihood × impact matrix producing a numeric score and risk level |
| Likelihood and impact analysis | 3×3 matrix with documented weights and score bands |
| Data classification | Restricted data escalates the resulting risk level |
| High/Critical risk identification | Escalated High and Critical vendors surfaced for follow-up |
| Security control-gap identification | Missing controls distinguished from missing evidence |
| Framework / control mapping | Findings crosswalked to SOC 2, ISO 27001:2022, and NIST CSF 2.0 |
| NIST and CIS security concepts | NIST CSF 2.0 references emitted; assessed control domains align with common CIS safeguard areas |
| Remediation and SLA tracking | Policy SLA due dates calculated and compared against recorded due dates |
| Overdue remediation detection | Days past due plus 0-30 / 31-60 / 61-90 / 90+ aging buckets |
| Security findings reporting | Per-vendor report with a written justification for every flagged item |
| Data-quality validation | Invalid rows quarantined to a separate exceptions report instead of failing the run |
| Audit-ready reporting | Every flagged row records the register value, the computed value, and the reason for the finding |

---

## How It Works

### 1. Independent risk scoring

Rather than trusting the `Risk Level` already recorded in the register, the engine recalculates it
from the likelihood/impact matrix defined in `risk_policy.json`:

```
score = likelihood weight (1-3) x impact weight (1-3)

  score <= 2  ->  Low
  score <= 4  ->  Medium
  score <= 6  ->  High
  score <= 9  ->  Critical
```

Where the recalculated level disagrees with the register, the row is flagged as a **risk rating
mismatch** — a governance control against stale or optimistic self-reported ratings.

### 2. Data classification escalation

The matrix result is then adjusted for the sensitivity of the data the vendor handles. Under the
current policy, vendors processing **Restricted** data are escalated one level, so a High-risk
vendor handling Restricted data becomes Critical. The report shows the pre- and post-escalation
levels side by side so the adjustment is auditable.

### 3. Security control-gap identification

Three attestation columns — SOC 2, MFA, and Encryption — are assessed, and the engine deliberately
separates two different problems:

- **Control not in place** (`No`) — the safeguard is absent
- **Evidence not provided** (`Unknown` or blank) — the safeguard may exist but is unevidenced

`Yes` and `N/A` are treated as satisfied. Any unrecognised value is rejected as a data-quality
issue rather than silently assumed compliant.

### 4. Framework and control mapping

Every finding category is crosswalked through `control_mappings.csv` to:

- **SOC 2** Trust Services Criteria
- **ISO 27001:2022** Annex A controls
- **NIST CSF 2.0** subcategories

Control references implied by an attestation gap are merged into the row, so a vendor with a
documented finding *and* a missing SOC 2 report is cited against both sets of controls. The
assessed control domains — multi-factor authentication, encryption, access review, backup and
recovery testing, and independent assurance — correspond to widely used CIS Controls safeguard
areas, though the crosswalk emitted by the tool covers SOC 2, ISO 27001, and NIST CSF 2.0.

### 5. Remediation SLA and aging

Remediation SLAs are derived from the **escalated** risk level and measured from the date the
finding was identified:

| Adjusted risk level | Remediation SLA |
|---|---|
| Critical | 15 days |
| High | 30 days |
| Medium | 60 days |
| Low | 90 days |

The engine calculates the policy SLA due date, flags **SLA breaches** where the register's own due
date exceeds it, counts days past due for open items, assigns an aging bucket, and raises an early
warning for items falling due within 14 days. Closed items are excluded from overdue counts.

### 6. Data-quality validation

A malformed row does not stop the run. Unparseable dates, unrecognised likelihood/impact/
classification values, unmapped finding categories, and missing vendor names are quarantined to
`data_quality_issues.csv` with the row number, severity, and cause, and the remaining vendors are
still assessed. Warnings — duplicate vendor names, a due date preceding the identified date, an
open finding with no category — are recorded without discarding the row.

Genuine configuration failures (a missing register, malformed policy JSON, or a register missing
required columns) fail loudly with a non-zero exit code.

---

## Repository Contents

| File | Purpose |
|---|---|
| `risk_analysis.py` | The risk engine: scoring, escalation, control-gap detection, mapping, SLA tracking, validation |
| `risk_policy.json` | Risk matrix, escalation tiers, remediation SLAs, aging buckets, attestation rules |
| `control_mappings.csv` | Finding category → SOC 2 / ISO 27001:2022 / NIST CSF 2.0 crosswalk |
| `vendor_risk_register.csv` | Input register (fictional sample data) |
| `risk_summary_report.csv` | Generated report of vendors requiring GRC follow-up |
| `data_quality_issues.csv` | Generated register exceptions report |

Both generated files are committed intentionally: they are the audit artifacts of the run, and an
empty exceptions report is itself meaningful evidence that the register passed validation.

---

## Output

`risk_summary_report.csv` records, for each vendor requiring follow-up: the register-recorded and
independently computed risk levels, the numeric score, the escalated level, the finding and its
category, SOC 2 / ISO 27001 / NIST CSF references, status, identified and due dates, the policy SLA
due date, days past due, aging bucket, remediation owner, and a plain-language **Review Reason**
explaining every trigger — for example:

```
Critical risk (escalated from High — Restricted data); Open finding (Open);
Overdue remediation (10 days); SLA breach: due date exceeds Critical SLA of 15 days by 25 days
```

That reason string is what makes the output defensible in an audit or vendor conversation: no
finding appears without a stated, traceable justification.

Against the sample register, the run evaluates 15 vendors and flags 10 for follow-up, including
overdue remediation, SLA policy breaches, and control gaps. Day-count fields are calculated
relative to the run date, so figures shift as items age.

---

## Running It

Requires Python 3.8+. No third-party packages.

```bash
python3 risk_analysis.py
```

The script prints a run summary and writes `risk_summary_report.csv` and
`data_quality_issues.csv`.

---

## AI-Assisted Development

**Claude Code (Anthropic) was used as an AI-assisted development tool throughout this project.**
This is disclosed openly because transparency about AI usage is itself a governance practice.

### What Claude Code assisted with

- Code development and iterative refinement of the risk engine
- Debugging and troubleshooting
- Testing, including edge-case and error-path test scenarios
- Repetitive automation tasks such as scaffolding, data shaping, and formatting
- Data-quality checks and validation logic
- Documentation, including this README
- Reviewing logic and identifying potential defects

As one concrete example, verification testing surfaced a latent defect in which framework control
references were shared across register rows rather than copied per row, which could have attributed
a control gap to a compliant vendor. The defect was identified during AI-assisted review, confirmed
with a reproducible test case, and corrected before the work was finalised.

### Human review and validation

AI-generated output was reviewed and validated rather than accepted at face value. Every scoring
rule, SLA threshold, control mapping, and report field in this repository was checked against the
intended policy before being committed.

Human cybersecurity judgment remains necessary and non-delegable for:

- **Risk decisions** — accepting, escalating, or transferring vendor risk
- **Security-control interpretation** — deciding whether a control is genuinely effective, not merely attested
- **Remediation decisions** — prioritisation, deadlines, and exception approvals
- **Validation of results** — confirming that automated output reflects reality before it informs a business decision

An automated score is an input to a risk decision, not the decision itself. This tool is designed
to surface and evidence issues consistently; a qualified practitioner still owns the judgment.

### Responsible AI and security considerations

Using AI tooling in a security context introduces its own risks, which were considered here:

- **Protecting sensitive information** — only fictional sample data is used. Real vendor names, contract terms, assessment evidence, or customer data should not be pasted into AI tools without an approved data-handling path.
- **Least-privilege access** — AI tooling should be scoped to the minimum repository, file, and system access needed for the task, and should not hold standing credentials to production or GRC systems of record.
- **Validating AI-generated output** — generated code and analysis can be confidently wrong. Output must be tested and reviewed before it influences a risk rating or remediation decision.
- **Using approved AI tools** — AI assistants should be sanctioned by the organisation and covered by its acceptable-use, data-classification, and third-party risk policies. An AI vendor is itself a third party subject to assessment.
- **Prompt-injection awareness** — untrusted content such as vendor questionnaire responses, emails, or web pages can carry instructions intended to manipulate an AI agent. Externally sourced content should be treated as data, never as trusted instructions.
- **Agent permission and access risk** — autonomous agents that can execute commands, modify files, or reach networks expand the blast radius of a mistake or a compromise. Permissions should be explicit, actions auditable, and irreversible operations gated by human approval.

---

## Technologies and Skills

**Python** · **Git** · **GitHub** · **Claude Code** · **AI-assisted development** · **GRC** ·
**Third-party risk management** · **NIST concepts (CSF 2.0)** · **CIS Controls** ·
**Risk assessment** · **Security controls** · **Remediation tracking** ·
**CSV/data processing** · **Cybersecurity documentation**

Also applied: SOC 2 Trust Services Criteria, ISO 27001:2022 Annex A, risk matrix design, data
classification, SLA and aging analysis, and defensive input validation.

---

## Scope and Limitations

- The register is fictional sample data, not a production vendor inventory.
- Risk scoring reflects the policy defined in `risk_policy.json`; a real programme would tune the matrix, escalation tiers, and SLAs to its own risk appetite.
- The tool identifies and evidences issues. It does not accept risk, approve exceptions, or replace a vendor security review.
