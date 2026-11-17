# POAM Generator

A CLI tool for generating FedRAMP/FISMA **Plan of Action & Milestones (POAM)** documents from structured JSON findings.

🔗 **[Live Demo](https://poam-generator-cappnr854zntygjkdtqxzbs.streamlit.app)** | **[GitHub](https://github.com/JulietRodriguez/poam-generator)**

## Features

- **Color-coded terminal table** — findings sorted by severity (Critical → Low) with rich formatting
- **Multiple output formats** — CSV, Excel (`.xlsx`), and OSCAL 1.1.2 POA&M in JSON and XML (both validated against NIST's official schemas in CI)
- **Built-in validation** — checks required fields and valid values before generating output
- **Demo mode** — 5 realistic sample findings spanning AC-2, IA-5, SI-3, SC-28, and CM-6 controls
- **Summary report** — per-severity and per-status counts printed after every run
- **NIST 800-53 / FedRAMP aligned** — fields match standard POAM column requirements

## Screenshots

### CLI Demo

<img src="CLIdemo.png" alt="CLI Demo" width="900"/>

### Web Dashboard

![Dashboard](dashboard_screenshot.png)

## Installation

```bash
git clone https://github.com/JulietRodriguez/poam-generator.git
cd poam-generator
pip install -e .
```

## Usage

### Run the built-in demo

```bash
poam demo
```

Displays 5 sample findings and saves `poam_output.csv` in the current directory.

### Generate a POAM from your findings

```bash
# CSV (default)
poam generate -i findings.json -o poam.csv

# Excel
poam generate -i findings.json -o poam.xlsx --format excel

# OSCAL JSON
poam generate -i findings.json -o poam.json --format oscal

# OSCAL XML
poam generate -i findings.json -o poam.xml --format oscal-xml
```

### Validate a findings file

```bash
poam validate -i findings.json
```

### Findings JSON format

```json
[
  {
    "weakness_name": "Privileged Account Review Not Performed",
    "weakness_description": "...",
    "security_control": "AC-2",
    "severity": "Critical",
    "source": "Audit",
    "detection_date": "2026-01-15",
    "scheduled_completion": "2026-04-30",
    "office_org": "Office of Information Technology",
    "point_of_contact": "Jane Smith, ISSO",
    "resources_required": "IAM team (40 hrs)",
    "remediation_plan": "...",
    "milestones": ["2026-02-01: Disable stale accounts"],
    "status": "In Progress",
    "comments": "..."
  }
]
```

Valid severities: `Critical`, `High`, `Medium`, `Low`  
Valid statuses: `Open`, `In Progress`, `Closed`, `Risk Accepted`  
Valid sources: `Audit`, `Vulnerability Scan`, `Penetration Test`, `AWS Security Hub`

## Remediation Tracking

Load findings into the local SQLite tracker and monitor remediation progress:

```bash
# Import findings into the tracker
poam track -i findings.json

# Show overdue, due-this-week, and all open findings
poam status
```

Each time `poam track` runs, it compares the file with the database and records every status change (old status, new status, timestamp) in a `status_history` table, so you keep an audit trail across runs. Status can also be changed by hand in the dashboard's Remediation Tracker, which records a note with the change.

Note: `poam track` assigns item IDs by position in the file (`V-001`, `V-002`, ...). Keep findings in the same order between runs, or a reordered file will be matched to the wrong history.

## Web Dashboard

Launch a browser-based dashboard to upload findings, view color-coded POAM tables, and download outputs:

```bash
poam dashboard
```

Opens at `http://localhost:8501` and loads straight to a live view of findings from AWS Security Hub with no setup required. Features:

- **AWS Security Hub** — opens automatically with findings loaded, no clicks needed. Connect real AWS credentials to sync live findings
- **Upload Findings** — drag-and-drop a JSON findings file for offline use
- **Remediation Tracker** — timeline of findings by due date (🔴 overdue, 🟡 due this week, 🟢 on track), inline status update form, full status change history
- **Metrics panel** — total findings, critical count, open count, in-progress count
- **Severity bar chart** — visual breakdown of findings by risk level

## AWS Security Hub Integration

Pull live findings directly from AWS Security Hub and automatically map them to a POAM-ready JSON file.

### Test with mock data (no AWS credentials needed)

```bash
poam sync --source aws-security-hub --region us-east-1 --mock
```

### Sync real findings from your AWS account

```bash
poam sync --source aws-security-hub --region us-east-1 --output findings.json
```

Then generate your POAM from the synced findings:

```bash
poam generate -i findings.json -o poam.xlsx --format excel
```

AWS credentials must be configured via `aws configure` or environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`).

The sync command pulls findings filtered to `RecordState=ACTIVE` and `WorkflowStatus=NEW or NOTIFIED` and maps title, description, control ID, severity, account/resource, first-observed date, remediation text, and status. Scheduled completion, point of contact, resources, and milestones aren't in Security Hub, so they're left blank for the ISSO to fill in; `poam validate` and `poam generate` will flag them until they are.

## Requirements

- Python 3.10+
- `click >= 8.1`
- `rich >= 13.0`
- `openpyxl >= 3.1`
- `boto3 >= 1.26` (for AWS Security Hub integration)

## Testing and CI

```bash
pip install -e ".[dev]"
pytest --cov            # 71 tests: models, validation, CSV/Excel, OSCAL JSON/XML, tracker, Security Hub mapping, CLI
ruff check .
```

The Security Hub tests use a fake `boto3` client, so no AWS account is needed. GitHub Actions runs lint and the tests on Python 3.10 to 3.12 and validates the OSCAL JSON and XML output against NIST's OSCAL 1.1.2 POA&M JSON Schema and XSD. See [.github/workflows/README.md](.github/workflows/README.md).

## Contributing

Pull requests welcome. For major changes open an issue first to discuss what you'd like to change.

## License

MIT. See [LICENSE](LICENSE).
