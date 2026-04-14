"""
argos.fingerprint
~~~~~~~~~~~~~~~~~
Behavioral fingerprinting for files: Shannon entropy, printable strings,
and AST-based analysis for Python (imports, functions, risky calls).
"""

from __future__ import annotations

import ast
import math
import mimetypes
import os
import re
import string
from collections import Counter
from typing import Any, Dict, List, Optional, Set, Tuple

from .database import ScanRecord


def is_binary(file_path: str) -> bool:
    """
    Check if a file is binary by looking for null bytes in the first 1KB.
    """
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(1024)
            return b"\0" in chunk
    except OSError:
        return False


def is_executable_ext(file_path: str) -> bool:
    """
    Check if a file has a known executable extension (mostly for Windows).
    """
    exts = {".exe", ".bat", ".cmd", ".com", ".ps1", ".vbs", ".msi", ".py"}
    return os.path.splitext(file_path)[1].lower() in exts


def calculate_entropy(file_path: str) -> float:
    """
    Calculate Shannon Entropy of a file (0.0 to 8.0).
    High entropy often indicates encrypted or compressed data.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read()
            if not data:
                return 0.0
            
            counter = Counter(data)
            data_len = len(data)
            entropy = 0.0
            for count in counter.values():
                p_x = count / data_len
                entropy += - p_x * math.log2(p_x)
            return round(entropy, 2)
    except OSError:
        return 0.0


def count_printable_strings(file_path: str, min_length: int = 6) -> int:
    """
    Count occurrences of printable sequences of at least min_length.
    Similar to the 'strings' utility behavior.
    """
    try:
        with open(file_path, "rb") as f:
            data = f.read().decode("ascii", errors="ignore")
            # Find sequences of printable characters
            pattern = f"[{re.escape(string.printable)}]{{{min_length},}}"
            matches = re.findall(pattern, data)
            return len(matches)
    except OSError:
        return 0


class PythonASTVisitor(ast.NodeVisitor):
    """
    Traverse Python AST to extract metadata and identify risky calls.
    """
    def __init__(self):
        self.functions = 0
        self.classes = 0
        self.imports: Set[str] = set()
        self.exec_calls: List[str] = []
        
        # Risky call patterns
        self.risky_functions = {"eval", "exec", "os.system", "subprocess.run", "subprocess.call", "subprocess.Popen"}

    def visit_FunctionDef(self, node):
        self.functions += 1
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node):
        self.functions += 1
        self.generic_visit(node)

    def visit_ClassDef(self, node):
        self.classes += 1
        self.generic_visit(node)

    def visit_Import(self, node):
        for name in node.names:
            self.imports.add(name.name)
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.add(node.module)
        self.generic_visit(node)

    def visit_Call(self, node):
        # Identify eval/exec
        if isinstance(node.func, ast.Name):
            if node.func.id in {"eval", "exec"}:
                self.exec_calls.append(node.func.id)
        # Identify os.system, etc.
        elif isinstance(node.func, ast.Attribute):
            full_name = self._get_attribute_name(node.func)
            if any(risk in full_name for risk in ["os.system", "subprocess"]):
                self.exec_calls.append(full_name)
        
        self.generic_visit(node)

    def _get_attribute_name(self, node: ast.Attribute) -> str:
        if isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        elif isinstance(node.value, ast.Attribute):
            return f"{self._get_attribute_name(node.value)}.{node.attr}"
        return node.attr


def analyze_python_file(file_path: str) -> Dict[str, Any]:
    """
    Perform AST analysis on a Python file.
    """
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            tree = ast.parse(f.read())
            visitor = PythonASTVisitor()
            visitor.visit(tree)
            
            return {
                "functions": visitor.functions,
                "classes": visitor.classes,
                "imports": sorted(list(visitor.imports)),
                "exec_calls": visitor.exec_calls,
                "has_exec": len(visitor.exec_calls) > 0
            }
    except (SyntaxError, OSError, UnicodeDecodeError):
        return {
            "functions": 0, "classes": 0, "imports": [], 
            "exec_calls": [], "has_exec": False
        }


def fingerprint_file(file_path: str, record: ScanRecord) -> ScanRecord:
    """
    Collect fingerprinting data and update the ScanRecord.
    """
    # Basic data
    record.entropy = calculate_entropy(file_path)
    record.printable_string_count = count_printable_strings(file_path)
    
    # Improved executable detection (especially for Windows)
    if os.name == "nt":
        # On Windows, os.access(X_OK) is synonymous with R_OK.
        # We supplement with extension and binary content checks.
        record.is_executable = is_executable_ext(file_path) or is_binary(file_path)
    else:
        record.is_executable = os.access(file_path, os.X_OK)
    
    mtype, _ = mimetypes.guess_type(file_path)
    record.file_type = mtype or "application/octet-stream"
    
    # Python specific analysis
    if file_path.endswith(".py"):
        py_data = analyze_python_file(file_path)
        record.function_count = py_data["functions"]
        record.class_count = py_data["classes"]
        import json
        record.import_list = json.dumps(py_data["imports"])
        record.has_exec_calls = py_data["has_exec"]
        record.exec_call_list = json.dumps(py_data["exec_calls"])
        
    return record
