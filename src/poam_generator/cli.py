"""POAM Generator CLI — poam demo | generate | validate | sync."""

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import box

from .demo_data import DEMO_FINDINGS
from .generate import write_csv, write_excel
from .oscal import write_oscal_json, write_oscal_xml
from .models import Finding, SEVERITY_ORDER
from .validate import validate_findings
from .aws_sync import fetch_security_hub_findings, MOCK_FINDINGS
from .tracker import (
    init_db, save_findings, update_status, get_all_findings,
    get_overdue_findings, get_due_this_week, get_status_history, days_remaining,
)

console = Console()

SEVERITY_STYLES = {
    "Critical": "bold red",
    "High": "bold yellow",
    "Medium": "yellow",
    "Low": "bold green",
}

STATUS_STYLES = {
    "Open": "red",
    "In Progress": "yellow",
    "Closed": "green",
    "Risk Accepted": "cyan",
}


def _build_table(findings: list[Finding]) -> Table:
    table = Table(
        title="[bold blue]Plan of Action & Milestones (POAM)[/bold blue]",
        box=box.ROUNDED,
        show_lines=True,
        header_style="bold white on blue",
        expand=True,
    )
    table.add_column("#", style="dim", width=3, no_wrap=True)
    table.add_column("Weakness Name", min_width=22)
    table.add_column("Control", width=9, no_wrap=True)
    table.add_column("Severity", width=10, no_wrap=True)
    table.add_column("Source", width=18, no_wrap=True)
    table.add_column("Status", width=14, no_wrap=True)
    table.add_column("Detection", width=12, no_wrap=True)
    table.add_column("Due Date", width=12, no_wrap=True)
    table.add_column("Office/Org", min_width=18)
    table.add_column("POC", min_width=16)

    sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    for i, f in enumerate(sorted_findings, start=1):
        sev_style = SEVERITY_STYLES.get(f.severity, "")
        status_style = STATUS_STYLES.get(f.status, "")
        table.add_row(
            str(i),
            f.weakness_name,
            f"[bold]{f.security_control}[/bold]",
            f"[{sev_style}]{f.severity}[/{sev_style}]",
            f.source,
            f"[{status_style}]{f.status}[/{status_style}]",
            f.detection_date,
            f.scheduled_completion,
            f.office_org,
            f.point_of_contact,
        )

    return table


@click.group()
@click.version_option("0.5.0", prog_name="poam")
def cli():
    """POAM Generator — create FedRAMP/FISMA Plan of Action & Milestones documents."""


@cli.command()
def demo():
    """Load 5 built-in demo findings and display a color-coded table, then save to poam_output.csv."""
    findings = [Finding.from_dict(d) for d in DEMO_FINDINGS]

    table = _build_table(findings)
    console.print()
    console.print(table)
    console.print()

    output_path = Path("poam_output.csv")
    write_csv(findings, output_path)
    console.print(
        f"[bold green]Saved {len(findings)} findings to[/bold green] [cyan]{output_path}[/cyan]"
    )

    _print_summary(findings)


@cli.command()
@click.option("-i", "--input", "input_file", required=True, type=click.Path(exists=True), help="JSON findings file")
@click.option("-o", "--output", "output_file", required=True, help="Output file path")
@click.option(
    "--format", "fmt",
    type=click.Choice(["csv", "excel", "oscal", "oscal-xml"], case_sensitive=False),
    default="csv", show_default=True,
    help="Output format: csv, excel, oscal (JSON), or oscal-xml",
)
def generate(input_file: str, output_file: str, fmt: str):
    """Read a JSON findings file and write a formatted POAM to CSV, Excel, or OSCAL."""
    try:
        with open(input_file, encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error:[/bold red] Invalid JSON in '{input_file}': {e}")
        sys.exit(1)

    if isinstance(raw, dict):
        raw = [raw]

    errors = validate_findings(raw)
    if errors:
        console.print("[bold red]Validation errors found — fix before generating:[/bold red]")
        for err in errors:
            console.print(f"  [red]•[/red] {err}")
        sys.exit(1)

    findings = [Finding.from_dict(d) for d in raw]

    output_path = Path(output_file)
    fmt_lower = fmt.lower()
    if fmt_lower == "excel":
        write_excel(findings, output_path)
        label = "Excel"
    elif fmt_lower == "oscal":
        write_oscal_json(findings, output_path)
        label = "OSCAL JSON"
    elif fmt_lower == "oscal-xml":
        write_oscal_xml(findings, output_path)
        label = "OSCAL XML"
    else:
        write_csv(findings, output_path)
        label = "CSV"

    table = _build_table(findings)
    console.print()
    console.print(table)
    console.print()
    console.print(
        f"[bold green]Wrote {len(findings)} findings to {label}:[/bold green] [cyan]{output_path}[/cyan]"
    )
    _print_summary(findings)


@cli.command()
@click.option("-i", "--input", "input_file", required=True, type=click.Path(exists=True), help="JSON findings file to validate")
def validate(input_file: str):
    """Check a JSON findings file for missing fields and invalid values."""
    try:
        with open(input_file, encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error:[/bold red] Invalid JSON in '{input_file}': {e}")
        sys.exit(1)

    if isinstance(raw, dict):
        raw = [raw]

    errors = validate_findings(raw)

    if errors:
        console.print(f"[bold red]Found {len(errors)} validation error(s) in '{input_file}':[/bold red]\n")
        for err in errors:
            console.print(f"  [red]x[/red]  {err}")
        console.print()
        sys.exit(1)
    else:
        console.print(
            f"[bold green]OK All {len(raw)} finding(s) in '{input_file}' are valid.[/bold green]"
        )


@cli.command()
@click.option(
    "--source", required=True,
    type=click.Choice(["aws-security-hub"], case_sensitive=False),
    help="Data source to sync from",
)
@click.option("--region", default="us-east-1", show_default=True, help="AWS region")
@click.option("-o", "--output", "output_file", default="findings.json", show_default=True, help="Output JSON file")
@click.option("--mock", is_flag=True, help="Use built-in mock findings (no AWS credentials needed)")
def sync(source: str, region: str, output_file: str, mock: bool):
    """Pull findings from AWS Security Hub and save to a JSON file."""
    if mock:
        console.print("[bold yellow]-- MOCK MODE -- Using built-in AWS Security Hub demo findings[/bold yellow]\n")
        raw_findings = MOCK_FINDINGS
    else:
        console.print(f"[cyan]Connecting to AWS Security Hub in [bold]{region}[/bold]...[/cyan]")
        try:
            raw_findings = fetch_security_hub_findings(region)
        except RuntimeError as e:
            console.print(f"[bold red]Error:[/bold red] {e}")
            sys.exit(1)
        except Exception as e:
            console.print(f"[bold red]AWS Error:[/bold red] {e}")
            console.print("[dim]Ensure AWS credentials are configured: aws configure[/dim]")
            sys.exit(1)

    findings = [Finding.from_dict(d) for d in raw_findings]

    output_path = Path(output_file)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(raw_findings, f, indent=2)

    table = _build_table(findings)
    console.print()
    console.print(table)
    console.print()
    console.print(f"[bold green]Synced {len(findings)} findings ->[/bold green] [cyan]{output_path}[/cyan]")
    console.print(
        f"[dim]Run [bold]poam generate -i {output_path} -o poam.xlsx --format excel[/bold] to produce your POAM[/dim]"
    )
    _print_summary(findings)


@cli.command()
@click.option("-i", "--input", "input_file", required=True, type=click.Path(exists=True), help="JSON findings file")
@click.option("--db", "db_path", default="poam_tracker.db", show_default=True, help="SQLite database path")
def track(input_file: str, db_path: str):
    """Save findings to the tracker database and show what changed since last run."""
    from pathlib import Path as _Path

    try:
        with open(input_file, encoding="utf-8") as f:
            raw = json.load(f)
    except json.JSONDecodeError as e:
        console.print(f"[bold red]Error:[/bold red] Invalid JSON: {e}")
        sys.exit(1)

    if isinstance(raw, dict) and "findings" in raw:
        raw = raw["findings"]

    # Build items list with generated IDs
    items = []
    for i, d in enumerate(raw, start=1):
        items.append({
            "item_id": f"V-{i:03d}",
            "weakness_name": d.get("weakness_name", ""),
            "security_control": d.get("security_control", ""),
            "severity": d.get("severity", ""),
            "status": d.get("status", ""),
            "detection_date": d.get("detection_date", ""),
            "scheduled_completion": d.get("scheduled_completion", ""),
            "office_org": d.get("office_org", ""),
            "point_of_contact": d.get("point_of_contact", ""),
        })

    db = _Path(db_path)
    changes = save_findings(items, db_path=db)

    console.print(f"\n[bold cyan]POAM Tracker[/bold cyan] — database: [dim]{db}[/dim]")
    console.print(f"[green]✓[/green] Processed [bold]{len(items)}[/bold] findings\n")

    if not changes:
        console.print("[dim]No changes since last run.[/dim]")
    else:
        from rich.table import Table as _Table
        t = _Table(title="Changes Since Last Run", box=box.SIMPLE_HEAVY, show_header=True,
                   header_style="bold white on dark_blue")
        t.add_column("Item ID", width=8)
        t.add_column("Type", width=14)
        t.add_column("Detail")
        for c in changes:
            if c["type"] == "new":
                t.add_row(c["item_id"], "[green]New finding[/green]", c["value"])
            else:
                t.add_row(
                    c["item_id"], "[yellow]Status changed[/yellow]",
                    f"{c['old']} → [bold]{c['new']}[/bold]"
                )
        console.print(t)

    console.print()


@cli.command("status")
@click.option("--db", "db_path", default="poam_tracker.db", show_default=True, help="SQLite database path")
def status_cmd(db_path: str):
    """Show a terminal dashboard: overdue items, due this week, and all open findings."""
    from pathlib import Path as _Path
    from rich.table import Table as _Table
    from rich.panel import Panel as _Panel

    db = _Path(db_path)
    if not db.exists():
        console.print("[yellow]No tracker database found. Run [bold]poam track[/bold] first.[/yellow]")
        sys.exit(1)

    overdue = get_overdue_findings(db_path=db)
    due_week = get_due_this_week(db_path=db)
    all_findings = get_all_findings(db_path=db)
    open_findings = [f for f in all_findings if f["status"] not in ("Closed", "Risk Accepted")]

    console.print()

    # Metrics row
    total = len(all_findings)
    n_overdue = len(overdue)
    n_week = len(due_week)
    n_open = len(open_findings)
    console.print(
        f"  [bold]Total:[/bold] {total}   "
        f"[bold red]Overdue:[/bold red] {n_overdue}   "
        f"[bold yellow]Due This Week:[/bold yellow] {n_week}   "
        f"[bold cyan]Open:[/bold cyan] {n_open}\n"
    )

    if overdue:
        t = _Table(title="[bold red]⚠ Overdue Findings[/bold red]", box=box.ROUNDED,
                   show_lines=True, header_style="bold white on red")
        t.add_column("ID", width=7)
        t.add_column("Weakness", min_width=28)
        t.add_column("Severity", width=10)
        t.add_column("Due Date", width=12)
        t.add_column("Days Overdue", width=13, justify="right")
        t.add_column("Status", width=13)
        for f in overdue:
            days = abs(days_remaining(f["scheduled_completion"]))
            sev_s = SEVERITY_STYLES.get(f["severity"], "")
            t.add_row(
                f["item_id"], f["weakness_name"],
                f"[{sev_s}]{f['severity']}[/{sev_s}]",
                f["scheduled_completion"],
                f"[bold red]{days}[/bold red]",
                f"[red]{f['status']}[/red]",
            )
        console.print(t)
        console.print()

    if due_week:
        t = _Table(title="[bold yellow]Due This Week[/bold yellow]", box=box.ROUNDED,
                   show_lines=True, header_style="bold white on dark_orange")
        t.add_column("ID", width=7)
        t.add_column("Weakness", min_width=28)
        t.add_column("Severity", width=10)
        t.add_column("Due Date", width=12)
        t.add_column("Days Left", width=10, justify="right")
        t.add_column("Status", width=13)
        for f in due_week:
            days = days_remaining(f["scheduled_completion"])
            sev_s = SEVERITY_STYLES.get(f["severity"], "")
            t.add_row(
                f["item_id"], f["weakness_name"],
                f"[{sev_s}]{f['severity']}[/{sev_s}]",
                f["scheduled_completion"],
                f"[yellow]{days}[/yellow]",
                f["status"],
            )
        console.print(t)
        console.print()

    if open_findings:
        t = _Table(title="[bold cyan]All Open Findings[/bold cyan]", box=box.ROUNDED,
                   show_lines=True, header_style="bold white on dark_blue", expand=True)
        t.add_column("ID", width=7)
        t.add_column("Weakness", min_width=24)
        t.add_column("Control", width=9)
        t.add_column("Severity", width=10)
        t.add_column("Status", width=13)
        t.add_column("Due Date", width=12)
        t.add_column("Days Left", width=10, justify="right")
        for f in open_findings:
            days = days_remaining(f["scheduled_completion"])
            sev_s = SEVERITY_STYLES.get(f["severity"], "")
            sta_s = STATUS_STYLES.get(f["status"], "")
            days_str = (
                f"[bold red]{days}[/bold red]" if days < 0
                else f"[yellow]{days}[/yellow]" if days <= 7
                else str(days)
            )
            t.add_row(
                f["item_id"], f["weakness_name"], f["security_control"],
                f"[{sev_s}]{f['severity']}[/{sev_s}]",
                f"[{sta_s}]{f['status']}[/{sta_s}]",
                f["scheduled_completion"], days_str,
            )
        console.print(t)
        console.print()


@cli.command()
@click.option("--port", default=8501, show_default=True, help="Port to run dashboard on")
def dashboard(port: int):
    """Launch the Streamlit web dashboard."""
    import subprocess
    import sys
    from pathlib import Path

    dashboard_path = Path(__file__).parent / "dashboard.py"
    console.print(f"[bold green]Launching POAM dashboard on http://localhost:{port}[/bold green]")
    console.print("[dim]Press Ctrl+C to stop[/dim]\n")
    subprocess.run([
        sys.executable, "-m", "streamlit", "run", str(dashboard_path),
        "--server.port", str(port),
        "--server.headless", "false",
    ])


def _print_summary(findings: list[Finding]) -> None:
    from collections import Counter

    sev_counts = Counter(f.severity for f in findings)
    status_counts = Counter(f.status for f in findings)

    console.print("[bold]Summary:[/bold]")
    for sev in ["Critical", "High", "Medium", "Low"]:
        count = sev_counts.get(sev, 0)
        if count:
            style = SEVERITY_STYLES.get(sev, "")
            console.print(f"  [{style}]{sev}[/{style}]: {count}")

    console.print()
    for status in ["Open", "In Progress", "Closed", "Risk Accepted"]:
        count = status_counts.get(status, 0)
        if count:
            style = STATUS_STYLES.get(status, "")
            console.print(f"  [{style}]{status}[/{style}]: {count}")
    console.print()
