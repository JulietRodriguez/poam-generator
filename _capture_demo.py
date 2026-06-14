"""Capture poam demo output as screenshot.png via visible Edge + PowerShell."""

import re
import subprocess
import sys
import threading
import time
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich import box

sys.path.insert(0, str(Path(__file__).parent / "src"))
from poam_generator.demo_data import DEMO_FINDINGS
from poam_generator.models import Finding, SEVERITY_ORDER
from collections import Counter

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

# ── 1. Render and export SVG ─────────────────────────────────────────────────

console = Console(record=True, width=130)
findings = [Finding.from_dict(d) for d in DEMO_FINDINGS]
sorted_findings = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

table = Table(
    title="[bold blue]Plan of Action & Milestones (POAM)[/bold blue]",
    box=box.ROUNDED,
    show_lines=True,
    header_style="bold white on blue",
    width=128,
)
for col, kw in [
    ("#",            dict(style="dim", width=3, no_wrap=True)),
    ("Weakness Name",dict(min_width=28)),
    ("Control",      dict(width=9,  no_wrap=True)),
    ("Severity",     dict(width=10, no_wrap=True)),
    ("Source",       dict(width=20, no_wrap=True)),
    ("Status",       dict(width=14, no_wrap=True)),
    ("Detection",    dict(width=12, no_wrap=True)),
    ("Due Date",     dict(width=12, no_wrap=True)),
    ("Office/Org",   dict(min_width=20)),
    ("POC",          dict(min_width=18)),
]:
    table.add_column(col, **kw)

for i, f in enumerate(sorted_findings, start=1):
    sev, sta = SEVERITY_STYLES.get(f.severity,""), STATUS_STYLES.get(f.status,"")
    table.add_row(
        str(i), f.weakness_name,
        f"[bold]{f.security_control}[/bold]",
        f"[{sev}]{f.severity}[/{sev}]",
        f.source,
        f"[{sta}]{f.status}[/{sta}]",
        f.detection_date, f.scheduled_completion,
        f.office_org, f.point_of_contact,
    )

sev_counts    = Counter(f.severity for f in findings)
status_counts = Counter(f.status   for f in findings)

console.print()
console.print(table)
console.print()
console.print("[bold green]Saved 5 findings to[/bold green] [cyan]poam_output.csv[/cyan]")
console.print()
console.print("[bold]Summary:[/bold]")
for sev in ["Critical","High","Medium","Low"]:
    c = sev_counts.get(sev,0)
    if c: console.print(f"  [{SEVERITY_STYLES[sev]}]{sev}[/{SEVERITY_STYLES[sev]}]: {c}")
console.print()
for status in ["Open","In Progress","Closed","Risk Accepted"]:
    c = status_counts.get(status,0)
    if c: console.print(f"  [{STATUS_STYLES[status]}]{status}[/{STATUS_STYLES[status]}]: {c}")
console.print()

out_dir  = Path(__file__).parent
svg_path = out_dir / "_demo_output.svg"
console.save_svg(str(svg_path), title="poam demo — POAM Generator v0.2.0")
sys.stdout.flush()

# ── 2. Patch SVG: system font, explicit dimensions ───────────────────────────

svg = svg_path.read_text(encoding="utf-8")
svg = re.sub(r'@font-face\s*\{[^}]*\}', '', svg, flags=re.DOTALL)
svg = svg.replace('font-family: Fira Code, monospace',
                  'font-family: Consolas, "Courier New", monospace')
# Add explicit pixel dimensions so the browser doesn't collapse to 0×0
svg = svg.replace(
    '<svg class="rich-terminal" viewBox="0 0 1604 928.4"',
    '<svg class="rich-terminal" viewBox="0 0 1604 928.4" width="1604" height="929"',
)
svg_path.write_text(svg, encoding="utf-8")

html = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>* {{margin:0;padding:0;}} body {{background:#000;overflow:hidden;}}</style>
</head><body>{svg}</body></html>"""
html_path = out_dir / "_demo_output.html"
html_path.write_text(html, encoding="utf-8")

# ── 3. Serve over localhost (avoids file:// font restrictions) ───────────────

class _Q(SimpleHTTPRequestHandler):
    def log_message(self, *a): pass
    def __init__(self, *a, **kw): super().__init__(*a, directory=str(out_dir), **kw)

srv = HTTPServer(("127.0.0.1", 0), _Q)
port = srv.server_address[1]
threading.Thread(target=srv.serve_forever, daemon=True).start()
url = f"http://127.0.0.1:{port}/_demo_output.html"
print(f"HTTP server: {url}", flush=True)

# ── 4. Open Edge in app-mode (visible, no tabs/address bar) ─────────────────

edge = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
png_path = (out_dir / "screenshot.png").resolve()

edge_proc = subprocess.Popen([
    edge,
    "--kiosk",           # fullscreen, no address bar / tabs / title bar
    "--no-first-run",
    "--no-default-browser-check",
    "--disable-extensions",
    url,
])
print("Edge kiosk opened, waiting 6s for page to render...", flush=True)
time.sleep(6)

# ── 5. Screenshot via PowerShell: bring Edge to top, capture full screen ─────

ps_png = str(png_path).replace("\\", "\\\\")
ps_script = f"""
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Win32 {{
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
}}
"@

# Give Edge the foreground (SW_MAXIMIZE = 3)
$edge = Get-Process msedge -ErrorAction SilentlyContinue |
        Where-Object {{ $_.MainWindowHandle -ne 0 }} |
        Sort-Object StartTime | Select-Object -Last 1
if ($edge) {{
    [Win32]::ShowWindow($edge.MainWindowHandle, 3)
    [Win32]::SetForegroundWindow($edge.MainWindowHandle)
}}
Start-Sleep -Milliseconds 1500

# Full primary-screen capture (kiosk fills the screen)
$png    = '{ps_png}'
$screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$bmp    = New-Object System.Drawing.Bitmap($screen.Width, $screen.Height)
$g      = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen(0, 0, 0, 0, $bmp.Size, [System.Drawing.CopyPixelOperation]::SourceCopy)
$g.Dispose()
$bmp.Save($png, [System.Drawing.Imaging.ImageFormat]::Png)
$bmp.Dispose()
Write-Host "Saved $png"
"""

result = subprocess.run(
    ["powershell", "-NonInteractive", "-Command", ps_script],
    capture_output=True, text=True, timeout=30,
)
print("PS stdout:", result.stdout.strip(), flush=True)
if result.stderr.strip():
    print("PS stderr:", result.stderr.strip()[:300], flush=True)

edge_proc.terminate()
srv.shutdown()

if png_path.exists() and png_path.stat().st_size > 50_000:
    print(f"SUCCESS: screenshot.png ({png_path.stat().st_size:,} bytes)", flush=True)
else:
    size = png_path.stat().st_size if png_path.exists() else 0
    print(f"FAILED — file is {size} bytes", flush=True)
    sys.exit(1)
