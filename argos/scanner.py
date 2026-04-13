"""
argos.scanner
~~~~~~~~~~~~~
Recursive directory traversal, metadata collection, and file hashing.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Generator, List, Optional, Tuple

from .config import load_ignore_patterns, should_ignore
from .database import ScanRecord
from .fingerprint import fingerprint_file


def compute_hash(file_path: str, algorithm: str = "sha256") -> str:
    """Compute the cryptographic hash of a file's content."""
    hash_obj = hashlib.new(algorithm)
    try:
        with open(file_path, "rb") as f:
            # Read in 64kb chunks
            for chunk in iter(lambda: f.read(65536), b""):
                hash_obj.update(chunk)
    except (OSError, PermissionError):
        # Fallback for files that disappear or are locked
        return "ERROR: UNREADABLE"
    return hash_obj.hexdigest()


def get_metadata(file_path: str) -> Tuple[int, str, str, float]:
    """
    Get file metadata: size, permissions (octal), owner, and mtime.
    """
    try:
        st = os.stat(file_path)
        size = st.st_size
        permissions = oct(stat.S_IMODE(st.st_mode))
        # Owner as string (UID if name lookup fails)
        try:
            import pwd
            owner = pwd.getpwuid(st.st_uid).pw_name
        except (ImportError, KeyError):
            owner = str(st.st_uid)
        mtime = st.st_mtime
    except (OSError, PermissionError):
        return 0, "0o000", "unknown", 0.0
    
    return size, permissions, owner, mtime


def scan_directory(
    directory: str,
    algorithm: str = "sha256",
    exclude_patterns: Optional[List[str]] = None,
    include_extensions: Optional[List[str]] = None,
    max_depth: Optional[int] = None,
    follow_symlinks: bool = False,
) -> Generator[ScanRecord, None, None]:
    """
    Recursively scan the directory and yield ScanRecord objects.
    """
    root_path = Path(directory).resolve()
    ignore_patterns = load_ignore_patterns(str(root_path))
    exclude_patterns = exclude_patterns or []
    include_extensions = include_extensions or []

    for root, dirs, files in os.walk(str(root_path), followlinks=follow_symlinks):
        rel_root = os.path.relpath(root, str(root_path))
        if rel_root == ".":
            rel_root = ""

        # Depth control
        if max_depth is not None:
            depth = rel_root.count(os.sep) if rel_root else 0
            if depth >= max_depth:
                dirs[:] = []  # Don't recurse deeper
                continue

        # Prune directories based on ignore rules
        dirs[:] = [
            d for d in dirs
            if not should_ignore(
                os.path.join(rel_root, d),
                ignore_patterns,
                exclude_patterns,
                []  # Don't filter dirs by extension
            )
        ]

        for filename in files:
            rel_path = os.path.join(rel_root, filename)
            abs_path = os.path.join(root, filename)

            if should_ignore(rel_path, ignore_patterns, exclude_patterns, include_extensions):
                continue

            size, permissions, owner, mtime = get_metadata(abs_path)
            hash_val = compute_hash(abs_path, algorithm)

            record = ScanRecord(
                path=rel_path,
                hash_value=hash_val,
                size=size,
                permissions=permissions,
                owner=owner,
                mtime=mtime
            )
            
            # Add behavioral fingerprint
            yield fingerprint_file(abs_path, record)
