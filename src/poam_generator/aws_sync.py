"""AWS Security Hub -> POAM finding mapper."""

from __future__ import annotations

from datetime import date, datetime

MOCK_FINDINGS = [
    {
        "weakness_name": "S3 Bucket Publicly Accessible",
        "weakness_description": "An S3 bucket has public read access enabled, potentially exposing sensitive federal data to unauthorized parties.",
        "security_control": "SC-28",
        "severity": "Critical",
        "source": "AWS Security Hub",
        "detection_date": "2026-05-01",
        "scheduled_completion": "2026-07-01",
        "office_org": "123456789012 / arn:aws:s3:::federal-data-bucket",
        "point_of_contact": "Cloud Security Team",
        "resources_required": "Cloud Engineer (4 hrs)",
        "remediation_plan": "Remove public access block override. Enable S3 Block Public Access at account level.",
        "milestones": [
            "2026-05-15: Remove public ACLs",
            "2026-06-01: Enable account-level block",
            "2026-07-01: Verify with Config rule",
        ],
        "status": "Open",
        "comments": "Detected by Security Hub FSBP control S3.2",
    },
    {
        "weakness_name": "MFA Not Enabled for IAM Root User",
        "weakness_description": "The AWS root account does not have multi-factor authentication enabled, violating IA-5 requirements for privileged account protection.",
        "security_control": "IA-5",
        "severity": "Critical",
        "source": "AWS Security Hub",
        "detection_date": "2026-04-10",
        "scheduled_completion": "2026-05-10",
        "office_org": "123456789012 / arn:aws:iam:::root",
        "point_of_contact": "IAM Administrator",
        "resources_required": "System Administrator (1 hr)",
        "remediation_plan": "Enable virtual or hardware MFA device on the root account immediately.",
        "milestones": [
            "2026-04-15: Procure hardware MFA token",
            "2026-05-10: Enable and verify MFA on root",
        ],
        "status": "In Progress",
        "comments": "Hardware token ordered. Awaiting delivery.",
    },
    {
        "weakness_name": "CloudTrail Not Enabled in All Regions",
        "weakness_description": "AWS CloudTrail is not configured to log API activity in all regions, creating gaps in the audit trail required by AU-2.",
        "security_control": "AU-2",
        "severity": "High",
        "source": "AWS Security Hub",
        "detection_date": "2026-03-22",
        "scheduled_completion": "2026-06-22",
        "office_org": "123456789012 / AWS::CloudTrail::Trail",
        "point_of_contact": "Cloud Operations",
        "resources_required": "Cloud Engineer (8 hrs); S3 storage costs (~$50/mo)",
        "remediation_plan": "Create a multi-region CloudTrail trail with log file validation and S3 server-side encryption.",
        "milestones": [
            "2026-04-15: Create multi-region trail",
            "2026-05-01: Enable log file validation",
            "2026-06-22: Verify coverage in all regions",
        ],
        "status": "In Progress",
        "comments": "Trail created in us-east-1. Expanding to remaining regions.",
    },
    {
        "weakness_name": "Security Groups Allow Unrestricted SSH Access",
        "weakness_description": "EC2 security groups permit inbound SSH (port 22) from 0.0.0.0/0, exposing instances to brute-force and unauthorized access attempts.",
        "security_control": "AC-17",
        "severity": "High",
        "source": "AWS Security Hub",
        "detection_date": "2026-05-05",
        "scheduled_completion": "2026-06-05",
        "office_org": "123456789012 / arn:aws:ec2:us-east-1:123456789012:security-group/sg-0abc123",
        "point_of_contact": "Network Security Team",
        "resources_required": "Network Engineer (4 hrs)",
        "remediation_plan": "Restrict SSH inbound rules to approved bastion host IPs only. Enforce via AWS Config rule.",
        "milestones": [
            "2026-05-10: Update security group rules",
            "2026-06-05: Deploy Config rule for ongoing enforcement",
        ],
        "status": "Open",
        "comments": "Three security groups identified. Change window scheduled.",
    },
    {
        "weakness_name": "RDS Instance Not Encrypted at Rest",
        "weakness_description": "An RDS database instance storing application data is not encrypted at rest, violating SC-28 requirements for protection of data at rest.",
        "security_control": "SC-28",
        "severity": "Medium",
        "source": "AWS Security Hub",
        "detection_date": "2026-02-14",
        "scheduled_completion": "2026-08-14",
        "office_org": "123456789012 / arn:aws:rds:us-east-1:123456789012:db:prod-app-db",
        "point_of_contact": "Database Administrator",
        "resources_required": "DBA (16 hrs); maintenance window downtime",
        "remediation_plan": "Snapshot unencrypted RDS instance, restore to new encrypted instance, update connection strings, decommission old instance.",
        "milestones": [
            "2026-04-01: Create encrypted snapshot copy",
            "2026-06-01: Restore to encrypted instance in staging",
            "2026-08-14: Migrate production and decommission unencrypted instance",
        ],
        "status": "In Progress",
        "comments": "Staging migration complete. Production cutover planned for Q3 maintenance window.",
    },
]


def _map_severity(label: str) -> str:
    return {"CRITICAL": "Critical", "HIGH": "High", "MEDIUM": "Medium", "LOW": "Low"}.get(
        label.upper(), "Medium"
    )


def _map_status(record_state: str, workflow_status: str) -> str:
    if record_state == "ARCHIVED" or workflow_status == "RESOLVED":
        return "Closed"
    if workflow_status == "NOTIFIED":
        return "In Progress"
    return "Open"


def _fmt_date(iso: str) -> str:
    try:
        return datetime.fromisoformat(iso.replace("Z", "+00:00")).strftime("%Y-%m-%d")
    except Exception:
        return date.today().isoformat()


def fetch_security_hub_findings(region: str) -> list[dict]:
    """Pull active findings from AWS Security Hub and map to POAM Finding dicts."""
    try:
        import boto3
    except ImportError:
        raise RuntimeError("boto3 is required: pip install boto3")

    client = boto3.client("securityhub", region_name=region)
    paginator = client.get_paginator("get_findings")

    pages = paginator.paginate(
        Filters={
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
            "WorkflowStatus": [
                {"Value": "NEW", "Comparison": "EQUALS"},
                {"Value": "NOTIFIED", "Comparison": "EQUALS"},
            ],
        }
    )

    findings = []
    for page in pages:
        for f in page["Findings"]:
            resources = f.get("Resources", [{}])
            resource_arn = resources[0].get("Id", "Unknown resource") if resources else "Unknown resource"
            account_id = f.get("AwsAccountId", "Unknown account")

            compliance = f.get("Compliance", {})
            control_id = (
                compliance.get("SecurityControlId")
                or (compliance.get("RelatedRequirements") or ["UNKNOWN"])[0]
                or "UNKNOWN"
            )

            findings.append({
                "weakness_name": f.get("Title", "Untitled Finding")[:120],
                "weakness_description": f.get("Description", "No description provided."),
                "security_control": control_id,
                "severity": _map_severity(f.get("Severity", {}).get("Label", "MEDIUM")),
                "source": f.get("ProductName", "AWS Security Hub"),
                "detection_date": _fmt_date(f.get("FirstObservedAt", "")),
                "scheduled_completion": "",
                "office_org": f"{account_id} / {resource_arn}",
                "point_of_contact": "",
                "resources_required": "",
                "remediation_plan": (
                    f.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
                ),
                "milestones": [],
                "status": _map_status(
                    f.get("RecordState", "ACTIVE"),
                    f.get("Workflow", {}).get("Status", "NEW"),
                ),
                "comments": f"Finding ID: {f.get('Id', '')}",
            })

    return findings
