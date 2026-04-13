"""
argos.reporter
~~~~~~~~~~~~~~
Rich terminal output, color-coded tables, and multi-format exporting (JSON, CSV, HTML).
"""

from __future__ import annotations

import csv
import json
import io
from datetime import datetime
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.text import Text

from .database import ChangeRecord

console = Console()


def get_severity_color(severity: Optional[str]) -> str:
    """Return the color associated with a severity level."""
    if not severity:
        return "white"
    
    mapping = {
        "CRITICAL": "bold red",
        "SUSPICIOUS": "yellow",
        "ROUTINE": "dim white"
    }
    return mapping.get(severity.upper(), "white")


def print_header(directory: str, baseline_name: str, files_scanned: int):
    """Print the Argos branded header."""
    header_text = Text.assemble(
        ("👁  ", "cyan"),
        ("ARGOS", "bold cyan"),
        ("  •  the hundred-eyed guardian  •  ", "cyan"),
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "dim")
    )
    
    info_text = Text.assemble(
        ("Directory: ", "bold"), (directory, "blue"), ("   "),
        ("Baseline: ", "bold"), (baseline_name, "magenta"), ("   "),
        ("Files scanned: ", "bold"), (str(files_scanned), "green")
    )
    
    console.print(Panel(info_text, title=header_text, border_style="cyan"))


def report_terminal(changes: List[ChangeRecord]):
    """Produce a color-coded Rich table for detected changes."""
    if not changes:
        console.print("[bold green]✔ Argos sees no changes. The perimeter is secure.[/bold green]")
        return

    table = Table(box=None, header_style="bold underline")
    table.add_column("SEVERITY", width=12)
    table.add_column("FILE", style="blue")
    table.add_column("CHANGE", width=10)
    table.add_column("DETAILS")

    for c in changes:
        sev = c.severity or "ROUTINE"
        sev_color = get_severity_color(sev)
        
        # Build change details
        details = []
        if c.change_type == "MODIFIED":
            if c.old_hash and c.new_hash:
                details.append(f"[dim]{c.old_hash[:8]}.. → {c.new_hash[:8]}..[/dim]")
        
        # Add reasons if any
        for reason in c.severity_reasons:
            details.append(f"→ [italic]{reason}[/italic]")
            
        # Add AI explanation if present
        if c.ai_explanation:
            details.append(f"[cyan]👁 Argos:[/cyan] {c.ai_explanation}")
            
        # Handle meta changes
        if c.change_type == "META ONLY":
            if c.old_permissions != c.new_permissions:
                details.append(f"Perms: {c.old_permissions} → {c.new_permissions}")
            if c.old_owner != c.new_owner:
                details.append(f"Owner: {c.old_owner} → {c.new_owner}")

        table.add_row(
            Text(sev, style=sev_color),
            c.path,
            c.change_type,
            "\n".join(details)
        )

    console.print(table)
    
    # Summary footer
    critical = sum(1 for c in changes if c.severity == "CRITICAL")
    suspicious = sum(1 for c in changes if c.severity == "SUSPICIOUS")
    routine = sum(1 for c in changes if c.severity == "ROUTINE" or not c.severity)
    
    console.print(f"\n[cyan]👁[/cyan]  Argos sees all: [bold red]{critical} critical[/bold red] · "
                  f"[yellow]{suspicious} suspicious[/yellow] · [dim]{routine} routine[/dim]")


def report_json(changes: List[ChangeRecord], output_path: Optional[str] = None):
    """Export changes as a JSON structure."""
    data = [
        {
            "path": c.path,
            "type": c.change_type,
            "severity": c.severity or "ROUTINE",
            "reasons": c.severity_reasons,
            "old_hash": c.old_hash,
            "new_hash": c.new_hash,
            "ai_explanation": c.ai_explanation
        }
        for c in changes
    ]
    json_str = json.dumps(data, indent=2)
    if output_path:
        with open(output_path, "w") as f:
            f.write(json_str)
    else:
        print(json_str)


def report_csv(changes: List[ChangeRecord], output_path: Optional[str] = None):
    """Export changes as a CSV file."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["path", "type", "severity", "old_hash", "new_hash"])
    for c in changes:
        writer.writerow([c.path, c.change_type, c.severity or "ROUTINE", c.old_hash or "", c.new_hash or ""])
    
    if output_path:
        with open(output_path, "w") as f:
            f.write(output.getvalue())
    else:
        print(output.getvalue())


def report_html(changes: List[ChangeRecord], output_path: str):
    """Export changes as a basic HTML report."""
    # Simplified HTML generation
    rows = []
    for c in changes:
        rows.append(f"""
            <tr>
                <td>{c.severity or 'ROUTINE'}</td>
                <td>{c.path}</td>
                <td>{c.change_type}</td>
                <td>{'<br>'.join(c.severity_reasons)}</td>
            </tr>
        """)
    
    html = f"""
    <html>
    <head>
        <title>Argos Audit Report</title>
        <style>
            body {{ font-family: sans-serif; background: #121212; color: #eee; padding: 20px; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th, td {{ padding: 10px; border: 1px solid #333; text-align: left; }}
            th {{ background: #1a1a1a; }}
            .CRITICAL {{ color: #ff5555; font-weight: bold; }}
            .SUSPICIOUS {{ color: #ffb86c; }}
        </style>
    </head>
    <body>
        <h1>👁 Argos Audit Report</h1>
        <table>
            <tr><th>Severity</th><th>File</th><th>Change</th><th>Reasons</th></tr>
            {''.join(rows)}
        </table>
    </body>
    </html>
    """
    with open(output_path, "w") as f:
        f.write(html)
