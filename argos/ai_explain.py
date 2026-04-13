"""
argos.ai_explain
~~~~~~~~~~~~~~~~
AI-powered anomaly explanation using the Groq API (Llama-3.3-70b-versatile).
Provides plain-English summaries and security context for detected changes.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional

from groq import Groq
from rich.console import Console
from rich.live import Live
from rich.text import Text

from .database import ChangeRecord

console = Console()

SYSTEM_PROMPT = """
You are a security analyst reviewing file change events on a Linux system.
You are part of Argos — a file integrity monitoring tool named after the
hundred-eyed giant of Greek mythology that never sleeps.
Given the structured context of a file change, provide:
1. A one-sentence plain-English summary of what changed.
2. A one-sentence explanation of why this might be suspicious or benign.
3. A recommended action (monitor / investigate / remediate).
Keep the total response under 80 words. Be specific and technical.
""".strip()


def get_groq_client() -> Tuple[Optional[Groq], Optional[str]]:
    """Return (Groq client, error_message)."""
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        return None, "GROQ_API_KEY not found in environment."
    try:
        return Groq(api_key=api_key), None
    except Exception as e:
        return None, f"Failed to initialize Groq client: {e}"


def explain_changes(changes: List[ChangeRecord]) -> List[ChangeRecord]:
    """
    Batch process SUSPICIOUS and CRITICAL changes and get AI explanations.
    """
    client, err = get_groq_client()
    if not client:
        console.print(f" [dim italic][argos] {err} — skipping AI explanations.[/dim italic]")
        return changes

    # Only explain SUSPICIOUS or CRITICAL changes
    to_explain = [c for c in changes if c.severity in ["SUSPICIOUS", "CRITICAL"]]
    if not to_explain:
        return changes

    console.print(f"[*] Asking Argos's AI eye to look at {len(to_explain)} anomalies...")

    # Batching to avoid rate limits (Groq free tier is ~30/min, so we'll do 1 by 1 or small groups)
    for i, change in enumerate(to_explain):
        context = {
            "file_path": change.path,
            "change_type": change.change_type,
            "severity": change.severity,
            "severity_reasons": change.severity_reasons,
            "semantic_diff": change.semantic_diff,
            "entropy_before": change.entropy_before,
            "entropy_after": change.entropy_after,
            "permissions_before": change.old_permissions,
            "permissions_after": change.new_permissions,
            "file_type": change.file_type
        }

        try:
            completion = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": json.dumps(context, indent=2)}
                ],
                temperature=0.2,
                max_tokens=200,
                stream=True
            )

            explanation = ""
            # Stream the explanation to the console for a premium feel
            console.print(f"\n[cyan]👁 Analysis for {change.path}:[/cyan]")
            with Live(Text(""), refresh_per_second=10, console=console) as live:
                for chunk in completion:
                    content = chunk.choices[0].delta.content or ""
                    explanation += content
                    live.update(Text(explanation, style="italic dim"))
            
            change.ai_explanation = explanation.strip()

            # Small delay between requests for safety in free tier
            if i < len(to_explain) - 1:
                time.sleep(1)

        except Exception as e:
            console.print(f"[dim red]AI request failed for {change.path}: {e}[/dim red]")
            change.ai_explanation = "Error retrieving AI explanation."

    return changes
