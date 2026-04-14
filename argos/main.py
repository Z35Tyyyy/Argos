"""
argos.main
~~~~~~~~~~
CLI entry point for Argos — the hundred-eyed guardian.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text


from .config import ArgosConfig, load_config_file
from .database import DatabaseManager, ChangeRecord, ScanRecord
from .scanner import scan_directory
from . import reporter, classifier, ai_explain
import schedule
import time

console = Console()


def print_banner():
    """Print the Argos branded header."""
    logo = r"""
 _______  ______    _______  _______  _______    __   __  ____         _______ 
|   _   ||    _ |  |       ||       ||       |  |  | |  ||    |       |  _    |
|  |_|  ||   | ||  |    ___||   _   ||  _____|  |  |_|  | |   |       | | |   |
|       ||   |_||_ |   | __ |  | |  || |_____   |       | |   |       | | |   |
|       ||    __  ||   ||  ||  |_|  ||_____  |  |       | |   |  ___  | |_|   |
|   _   ||   |  | ||   |_| ||       | _____| |   |     |  |   | |   | |       |
|__| |__||___|  |_||_______||_______||_______|    |___|   |___| |___| |_______|
    """
    
    banner_text = Text(logo, style="bold cyan")
    banner_text.append("\n   Argos — the hundred-eyed guardian • Production-Quality FIM", style="dim")
    
    console.print(Panel(
        banner_text,
        border_style="cyan",
        subtitle="[bold blue]Documentation:[/bold blue] [link=https://github.com/youruser/argos/blob/main/README.md]README.md[/link]",
        subtitle_align="right"
    ))


@click.group()
@click.version_option(package_name="argos-fim")
def cli():
    """Argos: File Integrity Monitoring with AI and Behavioral Fingerprinting."""
    pass


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--algo", type=click.Choice(["sha256", "sha512"]), default="sha256", help="Hashing algorithm.")
@click.option("--name", default="default", help="Snapshot name.")
@click.option("--db", type=click.Path(), help="Path to SQLite database.")
def init(directory, algo, name, db):
    """Recursively scan a directory and establish a baseline."""
    print_banner()
    directory = str(Path(directory).resolve())
    
    with DatabaseManager(db) as db_mgr:
        console.print(f"[*] Initializing baseline '[bold]{name}[/bold]' for {directory}...")
        
        # Load local config and ignore rules implicitly via scanner
        records = list(scan_directory(directory, algorithm=algo))
        
        db_mgr.create_baseline(name, directory, algo, records)
        db_mgr.append_ledger("init", directory, len(records), {"baseline_name": name})
        
        console.print(f"[bold green]✔[/bold green] Baseline created with {len(records)} files.")


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--baseline", default="default", help="Snapshot name to check against.")
@click.option("--db", type=click.Path(), help="Path to SQLite database.")
@click.option("--output", type=click.Choice(["terminal", "json", "csv", "html"]), default="terminal")
@click.option("--explain", is_flag=True, help="Enable AI explanation (requires GROQ_API_KEY).")
def check(directory, baseline, db, output, explain):
    """Diff current directory state against a stored baseline."""
    print_banner()
    directory = str(Path(directory).resolve())
    
    with DatabaseManager(db) as db_mgr:
        baseline_info = db_mgr.get_baseline(baseline, directory)
        if not baseline_info:
            console.print(f"[bold red]Error:[/bold red] Baseline '{baseline}' not found for this directory.")
            sys.exit(1)
            
        b_id, algo, created_at = baseline_info
        console.print(f"[*] Checking against baseline '{baseline}' (created {created_at})...")
        
        # Get baseline records
        old_records = {r.path: r for r in db_mgr.get_baseline_records(b_id)}
        
        # Get current state
        new_records = {r.path: r for r in scan_directory(directory, algorithm=algo)}
        
        changes: List[ChangeRecord] = []
        
        # Detect Modified, Deleted, Meta-only
        for path, old_r in old_records.items():
            if path not in new_records:
                changes.append(ChangeRecord(path, "DELETED", old_hash=old_r.hash_value))
            else:
                new_r = new_records[path]
                # Compare hashes
                if old_r.hash_value != new_r.hash_value:
                    changes.append(ChangeRecord(
                        path, "MODIFIED",
                        old_hash=old_r.hash_value, new_hash=new_r.hash_value,
                        old_size=old_r.size, new_size=new_r.size,
                        old_mtime=old_r.mtime, new_mtime=new_r.mtime,
                        time_delta_seconds=new_r.mtime - old_r.mtime
                    ))
                # Compare metadata (permissions/owner)
                elif old_r.permissions != new_r.permissions or old_r.owner != new_r.owner:
                    changes.append(ChangeRecord(
                        path, "META ONLY",
                        old_permissions=old_r.permissions, new_permissions=new_r.permissions,
                        old_owner=old_r.owner, new_owner=new_r.owner
                    ))
                    
        # Detect Added
        for path, new_r in new_records.items():
            if path not in old_records:
                changes.append(ChangeRecord(path, "ADDED", new_hash=new_r.hash_value))

        # Classify every change
        for i, c in enumerate(changes):
            old_r = old_records.get(c.path)
            new_r = new_records.get(c.path)
            
            # Perform semantic analysis using stored fingerprint data
            if old_r and new_r and c.path.endswith(".py"):
                sem_diff = {}
                old_imps = set(json.loads(old_r.import_list or "[]"))
                new_imps = set(json.loads(new_r.import_list or "[]"))
                
                added_imps = sorted(list(new_imps - old_imps))
                removed_imps = sorted(list(old_imps - new_imps))
                
                if added_imps: sem_diff["added_imports"] = added_imps
                if removed_imps: sem_diff["removed_imports"] = removed_imps
                
                if old_r.function_count is not None and new_r.function_count is not None:
                    if new_r.function_count > old_r.function_count:
                        sem_diff["functions"] = f"+{new_r.function_count - old_r.function_count} functions"
                    elif new_r.function_count < old_r.function_count:
                        sem_diff["functions"] = f"-{old_r.function_count - new_r.function_count} functions"
                
                c.semantic_diff = sem_diff

            changes[i] = classifier.classify_change(c, old_r, new_r)

        # AI Explanation
        if explain:
            changes = ai_explain.explain_changes(changes)

        # Use the rich reporter
        reporter.print_header(directory, baseline, len(new_records))
        
        if output == "terminal":
            reporter.report_terminal(changes)
        elif output == "json":
            reporter.report_json(changes)
        elif output == "csv":
            reporter.report_csv(changes)
        # HTML requires a target file in the full implementation, 
        # but for now we'll just handle terminal as default.
                
        # Update ledger
        db_mgr.append_ledger("check", directory, len(new_records), {"changes_count": len(changes)})


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--baseline", default="default", help="Snapshot name to update.")
@click.option("--db", type=click.Path(), help="Path to SQLite database.")
def update(directory, baseline, db):
    """Update an existing baseline to the current directory state."""
    print_banner()
    directory = str(Path(directory).resolve())
    
    with DatabaseManager(db) as db_mgr:
        baseline_info = db_mgr.get_baseline(baseline, directory)
        if not baseline_info:
            console.print(f"[bold red]Error:[/bold red] Baseline '{baseline}' not found.")
            sys.exit(1)
            
        b_id, algo, _ = baseline_info
        console.print(f"[*] Updating baseline '{baseline}'...")
        
        records = list(scan_directory(directory, algorithm=algo))
        db_mgr.create_baseline(baseline, directory, algo, records)
        db_mgr.append_ledger("update", directory, len(records), {"baseline_name": baseline})
        
        console.print(f"[bold green]✔[/bold green] Baseline updated with {len(records)} files.")


@cli.command(name="verify-chain")
@click.option("--db", type=click.Path(), help="Path to SQLite database.")
def verify_chain(db):
    """Validate the tamper-evident ledger integrity."""
    print_banner()
    with DatabaseManager(db) as db_mgr:
        errors = db_mgr.verify_ledger_chain()
        if not errors:
            console.print("[bold green]✔ Audit ledger chain is valid and untampered.[/bold green]")
        else:
            console.print("[bold red]⚠ LEDGER CORRUPTION DETECTED![/bold red]")
            for err in errors:
                console.print(f"  - Record #{err['record_id']} ({err['timestamp']}): {err['field']} mismatch")
                console.print(f"    Expected: {err['expected']}")
                console.print(f"    Actual:   {err['actual']}")
            sys.exit(2)


@cli.command()
@click.option("--db", type=click.Path(), help="Path to SQLite database.")
@click.option("--since", help="Filter by timestamp (ISO format).")
@click.option("--format", "fmt", type=click.Choice(["terminal", "json", "html"]), default="terminal")
def report(db, since, fmt):
    """View the tamper-evident audit ledger."""
    print_banner()
    with DatabaseManager(db) as db_mgr:
        entries = db_mgr.get_ledger_entries(since=since)
        
        if not entries:
            console.print("[dim]No ledger entries found.[/dim]")
            return

        if fmt == "terminal":
            table = Table(title="Audit Ledger", border_style="cyan")
            table.add_column("ID", justify="right")
            table.add_column("TIMESTAMP")
            table.add_column("ACTION", style="bold")
            table.add_column("DIRECTORY")
            table.add_column("FILES", justify="right")
            table.add_column("HASH", style="dim")

            for e in entries:
                table.add_row(
                    str(e.id),
                    e.timestamp,
                    e.action,
                    e.directory,
                    str(e.files_scanned),
                    e.record_hash[:16] + "..."
                )
            console.print(table)
        elif fmt == "json":
            data = [
                {
                    "id": e.id,
                    "timestamp": e.timestamp,
                    "action": e.action,
                    "directory": e.directory,
                    "files_scanned": e.files_scanned,
                    "summary": json.loads(e.changes_summary_json),
                    "hash": e.record_hash
                }
                for e in entries
            ]
            console.print_json(data=data)
        # HTML report for ledger could be added similarly to reporter.report_html


@cli.command()
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--baseline", default="default", help="Baseline name.")
@click.option("--interval", type=int, default=60, help="Scan interval in seconds.")
@click.option("--db", type=click.Path(), help="Path to SQLite database.")
@click.option("--explain", is_flag=True, help="Enable AI explanation.")
def watch(directory, baseline, interval, db, explain):
    """Continuously monitor a directory for changes."""
    print_banner()
    console.print(f"[*] Argos is watching {directory} every {interval}s...")
    
    def job():
        # Invoke check logic (internalised)
        ctx = click.get_current_context()
        ctx.invoke(check, directory=directory, baseline=baseline, db=db, output="terminal", explain=explain)

    schedule.every(interval).seconds.do(job)
    
    # Run once immediately
    job()
    
    try:
        while True:
            schedule.run_pending()
            time.sleep(1)
    except KeyboardInterrupt:
        console.print("\n[bold yellow]! Argos is closing its eyes.[/bold yellow]")


if __name__ == "__main__":
    cli()
