import csv

from openpyxl import load_workbook

from poam_generator.generate import CSV_HEADERS, write_csv, write_excel


def test_write_csv(sample_findings, tmp_path):
    out = tmp_path / "poam.csv"
    write_csv(sample_findings, out)
    with out.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    assert list(rows[0].keys()) == CSV_HEADERS
    assert len(rows) == len(sample_findings)
    assert rows[0]["Weakness Name"] == sample_findings[0].weakness_name


def test_write_excel(sample_findings, tmp_path):
    out = tmp_path / "poam.xlsx"
    write_excel(sample_findings, out)
    ws = load_workbook(out)["POAM"]
    assert [c.value for c in ws[1]] == CSV_HEADERS
    assert ws.max_row == len(sample_findings) + 1
    assert ws.freeze_panes == "A2"
    sev_col = CSV_HEADERS.index("Severity") + 1
    fills = {ws.cell(row=r, column=sev_col).fill.start_color.rgb for r in range(2, ws.max_row + 1)}
    assert fills  # severity cells are color-coded
