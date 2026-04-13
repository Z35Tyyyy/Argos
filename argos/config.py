"""
argos.config
~~~~~~~~~~~~
Configuration file loading, .argosignore parsing, and ignore-rule matching.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml


@dataclass
class ArgosConfig:
    """Runtime configuration consolidated from file + CLI flags."""
    algorithm: str = "sha256"
    snapshot_name: str = "default"
    db_path: Optional[str] = None
    exclude_patterns: List[str] = field(default_factory=list)
    include_extensions: List[str] = field(default_factory=list)
    max_depth: Optional[int] = None
    follow_symlinks: bool = False
    watch_interval: int = 60
    output_format: str = "terminal"   # terminal | json | csv | html
    explain: bool = False


def load_config_file(directory: str) -> Dict[str, Any]:
    """
    Look for .argos.yml or .argos.yaml in *directory* and return its contents
    as a dict.  Returns empty dict when no config file is found.
    """
    base = Path(directory)
    for name in (".argos.yml", ".argos.yaml"):
        cfg_path = base / name
        if cfg_path.is_file():
            try:
                with open(cfg_path, "r", encoding="utf-8") as fh:
                    data = yaml.safe_load(fh)
                    return data if isinstance(data, dict) else {}
            except (yaml.YAMLError, OSError):
                return {}
    return {}


def load_ignore_patterns(directory: str) -> List[str]:
    """
    Parse a .argosignore file (gitignore-style) in the given directory.

    Returns a list of glob patterns.  Blank lines and lines starting with
    ``#`` are ignored.
    """
    ignore_file = Path(directory) / ".argosignore"
    patterns: List[str] = []
    if ignore_file.is_file():
        try:
            with open(ignore_file, "r", encoding="utf-8") as fh:
                for raw_line in fh:
                    line = raw_line.strip()
                    if not line or line.startswith("#"):
                        continue
                    patterns.append(line)
        except OSError:
            pass
    return patterns


def should_ignore(
    rel_path: str,
    ignore_patterns: List[str],
    exclude_patterns: List[str],
    include_extensions: List[str],
) -> bool:
    """
    Decide whether *rel_path* (relative to the scanned root) should be
    skipped.

    Parameters
    ----------
    rel_path : str
        Forward-slash normalised relative path, e.g. ``src/utils/helper.py``.
    ignore_patterns : list[str]
        Patterns loaded from ``.argosignore``.
    exclude_patterns : list[str]
        Extra ``--exclude`` CLI patterns.
    include_extensions : list[str]
        If non-empty, **only** files whose suffix is in this list are kept.
    """
    # Normalise separators to forward slash for matching
    norm = rel_path.replace("\\", "/")
    basename = os.path.basename(norm)

    # Always skip the argos database itself, .git, __pycache__
    always_skip = {".git", "__pycache__", ".argos", "node_modules"}
    parts = norm.split("/")
    for part in parts:
        if part in always_skip:
            return True

    # Extension filter (whitelist)
    if include_extensions:
        ext = os.path.splitext(basename)[1].lower()
        if ext not in include_extensions:
            return True

    # .argosignore + --exclude patterns (blacklist)
    all_patterns = ignore_patterns + exclude_patterns
    for pattern in all_patterns:
        # Match against basename and full relative path
        if fnmatch.fnmatch(basename, pattern) or fnmatch.fnmatch(norm, pattern):
            return True
        # Support directory patterns like "build/"
        if pattern.endswith("/"):
            dir_pat = pattern.rstrip("/")
            for part in parts:
                if fnmatch.fnmatch(part, dir_pat):
                    return True

    return False
