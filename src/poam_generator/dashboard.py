"""Streamlit web dashboard for POAM Generator."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pandas as pd
import streamlit as st

try:
    from .aws_sync import fetch_security_hub_findings, MOCK_FINDINGS
    from .generate import write_csv, write_excel
    from .models import Finding
    from .validate import validate_findings
    from .tracker import (
        init_db, save_findings, update_status, get_all_findings,
        get_overdue_findings, get_due_this_week, get_status_history, days_remaining,
    )
except ImportError:
    from poam_generator.aws_sync import fetch_security_hub_findings, MOCK_FINDINGS
    from poam_generator.generate import write_csv, write_excel
    from poam_generator.models import Finding
    from poam_generator.validate import validate_findings
    from poam_generator.tracker import (
        init_db, save_findings, update_status, get_all_findings,
        get_overdue_findings, get_due_this_week, get_status_history, days_remaining,
    )

SEVERITY_COLORS = {
    "Critical": "#FF4B4B",
    "High": "#FF8C00",
    "Medium": "#FFD700",
    "Low": "#00C851",
}

STATUS_COLORS = {
    "Open": "#FF4B4B",
    "In Progress": "#FF8C00",
    "Closed": "#00C851",
    "Risk Accepted": "#00BFFF",
}

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def _findings_to_df(findings: list[Finding]) -> pd.DataFrame:
    rows = []
    for f in findings:
        rows.append({
            "Weakness Name": f.weakness_name,
            "Control": f.security_control,
            "Severity": f.severity,
            "Status": f.status,
            "Source": f.source,
            "Detection Date": f.detection_date,
            "Due Date": f.scheduled_completion,
            "Office/Org": f.office_org,
            "Point of Contact": f.point_of_contact,
            "Remediation Plan": f.remediation_plan,
            "Comments": f.comments,
        })
    df = pd.DataFrame(rows)
    sev_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    df["_rank"] = df["Severity"].map(sev_rank).fillna(99)
    df = df.sort_values("_rank").drop(columns=["_rank"]).reset_index(drop=True)
    df.index += 1
    return df


def _style_df(df: pd.DataFrame) -> pd.io.formats.style.Styler:
    def color_severity(val):
        color = SEVERITY_COLORS.get(val, "")
        return f"color: {color}; font-weight: bold;" if color else ""

    def color_status(val):
        color = STATUS_COLORS.get(val, "")
        return f"color: {color}; font-weight: bold;" if color else ""

    return (
        df.style
        .map(color_severity, subset=["Severity"])
        .map(color_status, subset=["Status"])
    )


def _to_csv_bytes(findings: list[Finding]) -> bytes:
    buf = io.StringIO()
    import csv
    writer = csv.DictWriter(buf, fieldnames=list(Finding.__dataclass_fields__.keys()))
    writer.writeheader()
    for f in findings:
        writer.writerow(f.__dict__)
    return buf.getvalue().encode()


def _to_excel_bytes(findings: list[Finding]) -> bytes:
    buf = io.BytesIO()
    write_excel(findings, buf)
    return buf.getvalue()


def _show_metrics(findings: list[Finding]) -> None:
    total = len(findings)
    critical = sum(1 for f in findings if f.severity == "Critical")
    open_count = sum(1 for f in findings if f.status == "Open")
    in_progress = sum(1 for f in findings if f.status == "In Progress")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Findings", total)
    c2.metric("Critical", critical, delta=None)
    c3.metric("Open", open_count)
    c4.metric("In Progress", in_progress)


def _show_chart(findings: list[Finding]) -> None:
    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        if f.severity in sev_counts:
            sev_counts[f.severity] += 1

    chart_df = pd.DataFrame(
        {"Count": list(sev_counts.values())},
        index=list(sev_counts.keys()),
    )
    st.bar_chart(chart_df, color="#FF4B4B")


def _show_poam_table(findings: list[Finding]) -> None:
    df = _findings_to_df(findings)
    styled = _style_df(df)
    st.dataframe(styled, use_container_width=True, height=400)


def _show_downloads(findings: list[Finding]) -> None:
    st.markdown("### Download")
    c1, c2, c3 = st.columns(3)
    c1.download_button(
        label="Download CSV",
        data=_to_csv_bytes(findings),
        file_name="poam_output.csv",
        mime="text/csv",
    )
    c2.download_button(
        label="Download Excel",
        data=_to_excel_bytes(findings),
        file_name="poam_output.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )
    raw = [f.__dict__ for f in findings]
    c3.download_button(
        label="Download JSON",
        data=json.dumps(raw, indent=2).encode(),
        file_name="findings.json",
        mime="application/json",
    )


def _render_findings(findings: list[Finding]) -> None:
    _show_metrics(findings)
    st.markdown("---")
    st.markdown("### Findings by Severity")
    _show_chart(findings)
    st.markdown("---")
    st.markdown("### POAM Table")
    _show_poam_table(findings)
    st.markdown("---")
    _show_downloads(findings)


def _show_tracker_tab() -> None:
    st.header("Remediation Tracker")

    db_path = Path("poam_tracker.db")
    init_db(db_path)
    all_findings = get_all_findings(db_path)

    if not all_findings:
        st.info("No findings in the tracker yet. Run `poam track -i findings.json` from the terminal to load findings.")
        return

    overdue = get_overdue_findings(db_path)
    due_week = get_due_this_week(db_path)
    open_findings = [f for f in all_findings if f["status"] not in ("Closed", "Risk Accepted")]

    # Metrics
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Tracked", len(all_findings))
    c2.metric("Overdue", len(overdue), delta=f"-{len(overdue)}" if overdue else None,
              delta_color="inverse")
    c3.metric("Due This Week", len(due_week))
    c4.metric("Open", len(open_findings))

    st.markdown("---")

    # Timeline view — findings by due date
    st.markdown("### Timeline — Findings by Due Date")
    timeline_rows = []
    for f in sorted(all_findings, key=lambda x: x["scheduled_completion"]):
        days = days_remaining(f["scheduled_completion"])
        if f["status"] in ("Closed", "Risk Accepted"):
            flag = "✅"
        elif days < 0:
            flag = "🔴"
        elif days <= 7:
            flag = "🟡"
        else:
            flag = "🟢"
        timeline_rows.append({
            "": flag,
            "ID": f["item_id"],
            "Weakness": f["weakness_name"],
            "Control": f["security_control"],
            "Severity": f["severity"],
            "Due Date": f["scheduled_completion"],
            "Days": days,
            "Status": f["status"],
        })

    df = pd.DataFrame(timeline_rows)

    def color_row(row):
        days = row["Days"]
        status = row["Status"]
        if status in ("Closed", "Risk Accepted"):
            return ["color: #888"] * len(row)
        if days < 0:
            return ["color: #FF4B4B; font-weight: bold"] * len(row)
        if days <= 7:
            return ["color: #FFD700; font-weight: bold"] * len(row)
        return [""] * len(row)

    st.dataframe(df.style.apply(color_row, axis=1), use_container_width=True, height=350)

    st.markdown("---")

    # Status update form
    st.markdown("### Update Finding Status")
    if all_findings:
        item_options = {f["item_id"]: f for f in all_findings}
        selected_id = st.selectbox(
            "Select Finding",
            options=list(item_options.keys()),
            format_func=lambda x: f"{x} — {item_options[x]['weakness_name'][:60]}",
        )
        selected = item_options[selected_id]

        col1, col2 = st.columns([2, 1])
        with col1:
            new_status = col1.selectbox(
                "New Status",
                ["Open", "In Progress", "Closed", "Risk Accepted"],
                index=["Open", "In Progress", "Closed", "Risk Accepted"].index(selected["status"]),
            )
        notes = st.text_input("Notes (optional)", placeholder="e.g. Patch applied, awaiting verification")

        if st.button("Update Status", type="primary"):
            if new_status == selected["status"]:
                st.warning("Status is already set to that value.")
            else:
                update_status(selected_id, new_status, notes, db_path=db_path)
                st.success(f"Updated {selected_id}: {selected['status']} → {new_status}")
                st.rerun()

    st.markdown("---")

    # Status history
    st.markdown("### Status Change History")
    history_id = st.selectbox(
        "View history for",
        options=[f["item_id"] for f in all_findings],
        format_func=lambda x: f"{x} — {item_options[x]['weakness_name'][:60]}",
        key="history_select",
    )
    history = get_status_history(history_id, db_path=db_path)
    if history:
        hist_df = pd.DataFrame(history)
        hist_df.columns = ["From", "To", "Changed At", "Notes"]
        st.dataframe(hist_df, use_container_width=True)
    else:
        st.info("No status changes recorded yet for this finding.")


def main() -> None:
    st.set_page_config(
        page_title="POAM Generator",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ POAM Generator")
    st.caption("FedRAMP / FISMA Plan of Action & Milestones — automated from your security findings")

    tab = st.sidebar.radio(
        "Data Source",
        ["Upload Findings", "AWS Security Hub", "Remediation Tracker"],
        index=0,
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown(
        "**poam-generator** v0.6.0  \n"
        "[GitHub](https://github.com/JulietRodriguez/poam-generator)"
    )

    if tab == "Upload Findings":
        st.header("Upload Findings JSON")
        uploaded = st.file_uploader(
            "Choose a findings JSON file", type=["json"], label_visibility="collapsed"
        )

        if uploaded is not None:
            try:
                raw = json.loads(uploaded.read())
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON: {e}")
                return

            if isinstance(raw, dict) and "findings" in raw:
                raw = raw["findings"]

            errors = validate_findings(raw)
            if errors:
                st.error("Validation errors found:")
                for err in errors:
                    st.write(f"- {err}")
                return

            findings = [Finding.from_dict(d) for d in raw]
            st.success(f"Loaded {len(findings)} findings from `{uploaded.name}`")
            _render_findings(findings)
        else:
            st.info("Upload a JSON findings file to get started, or switch to the AWS Security Hub tab to pull live findings.")

    elif tab == "Remediation Tracker":
        _show_tracker_tab()

    else:  # AWS Security Hub
        st.header("AWS Security Hub")

        col1, col2 = st.columns([2, 1])
        region = col1.text_input("AWS Region", value="us-east-1")
        use_mock = col2.checkbox("Use Mock Data", value=True, help="Test without real AWS credentials")

        if st.button("Sync from Security Hub", type="primary"):
            with st.spinner("Pulling findings from AWS Security Hub..."):
                try:
                    if use_mock:
                        raw_findings = MOCK_FINDINGS
                        st.info("Using built-in mock findings — uncheck 'Use Mock Data' to connect to real AWS.")
                    else:
                        raw_findings = fetch_security_hub_findings(region)

                    findings = [Finding.from_dict(d) for d in raw_findings]
                    st.session_state["sh_findings"] = findings
                    st.success(f"Synced {len(findings)} findings from Security Hub ({region})")
                except RuntimeError as e:
                    st.error(str(e))
                    st.stop()
                except Exception as e:
                    st.error(f"AWS Error: {e}")
                    st.caption("Ensure AWS credentials are configured: `aws configure`")
                    st.stop()

        if "sh_findings" in st.session_state:
            _render_findings(st.session_state["sh_findings"])


if __name__ == "__main__":
    main()
