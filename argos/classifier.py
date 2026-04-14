"""
argos.classifier
~~~~~~~~~~~~~~~~
Intent classification for file changes. Assigns severity labels
(CRITICAL, SUSPICIOUS, ROUTINE) based on behavioral fingerprinting.
"""

from __future__ import annotations

import json
import os
from typing import List, Optional

from .database import ChangeRecord, ScanRecord


def classify_change(
    change: ChangeRecord,
    old_record: Optional[ScanRecord] = None,
    new_record: Optional[ScanRecord] = None
) -> ChangeRecord:
    """
    Evaluate heuristics and assign a severity level to a ChangeRecord.
    """
    reasons: List[str] = []
    severity = "ROUTINE"
    path_lower = change.path.lower()

    # 1. Critical Heuristics
    # ----------------------
    if change.change_type == "MODIFIED":
        # Binary/executable modified
        if new_record and new_record.is_executable:
            reasons.append("Executable file modified")
            severity = "CRITICAL"
            
        # Sensitive paths
        # Normalize to forward slashes for cross-platform matching
        path_norm = change.path.lower().replace("\\", "/")
        sensitive_dirs = ["/etc/", "/bin/", "/usr/bin/", "/sbin/", "/windows/system32/", "/syswow64/"]
        if any(p in path_norm for p in sensitive_dirs):
            reasons.append("Modification in system configuration/binary directory")
            severity = "CRITICAL"

        # Entropy delta
        if old_record and new_record:
            old_e = old_record.entropy or 0.0
            new_e = new_record.entropy or 0.0
            delta_e = abs(new_e - old_e)
            change.entropy_delta = delta_e
            change.entropy_before = old_e
            change.entropy_after = new_e
            
            if delta_e > 2.0:
                reasons.append(f"Significant entropy shift (+{delta_e})")
                severity = "CRITICAL"
            elif 1.0 < delta_e <= 2.0:
                reasons.append(f"Moderate entropy shift (+{delta_e})")
                if severity != "CRITICAL":
                    severity = "SUSPICIOUS"

        # Dynamic execution calls added (Python)
        if old_record and new_record and change.path.endswith(".py"):
            old_execs = set(json.loads(old_record.exec_call_list or "[]"))
            new_execs = set(json.loads(new_record.exec_call_list or "[]"))
            added_execs = new_execs - old_execs
            if added_execs:
                change.new_exec_calls = list(added_execs)
                reasons.append(f"Risky calls added: {', '.join(added_execs)}")
                severity = "CRITICAL"

    # Permissions changed to executable (mainly for Unix)
    if os.name != "nt" and (change.change_type == "META ONLY" or change.change_type == "MODIFIED"):
        if change.old_permissions and change.new_permissions:
            try:
                # Check if execute bit was added
                old_p = int(change.old_permissions, 8)
                new_p = int(change.new_permissions, 8)
                exec_bits = 0o111
                if (not (old_p & exec_bits)) and (new_p & exec_bits):
                    reasons.append("File became executable (new X bit)")
                    severity = "CRITICAL"
            except (ValueError, TypeError):
                pass

    # 2. Suspicious Heuristics
    # ------------------------
    if severity != "CRITICAL":
        # Sensitive keywords in filename
        secrets = ["auth", "login", "password", "secret", "token", "key", "cert", "config", ".env"]
        if any(s in path_lower for s in secrets):
            reasons.append("Modification to potential secrets/config file")
            severity = "SUSPICIOUS"

        # New network imports (Python)
        if old_record and new_record and change.path.endswith(".py"):
            old_imps = set(json.loads(old_record.import_list or "[]"))
            new_imps = set(json.loads(new_record.import_list or "[]"))
            added_imps = new_imps - old_imps
            network_mods = {"socket", "requests", "httpx", "urllib", "smtplib", "paramiko"}
            net_added = added_imps.intersection(network_mods)
            if net_added:
                change.new_imports = list(added_imps)
                reasons.append(f"Network capability added: {', '.join(net_added)}")
                severity = "SUSPICIOUS"

    # Default to ROUTINE
    change.severity = severity
    change.severity_reasons = reasons
    if new_record:
        change.file_type = new_record.file_type
        
    return change
