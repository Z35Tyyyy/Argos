"""
argos.semantic_diff
~~~~~~~~~~~~~~~~~~~
AST-based semantic diffing for Python files. Detects changes in functions,
classes, and imports rather than just line-by-line diffs.
"""

from __future__ import annotations

import ast
import difflib
import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class SemanticDiff:
    """Structure for storing code-level semantic changes."""
    added_functions: List[str] = field(default_factory=list)
    removed_functions: List[str] = field(default_factory=list)
    modified_functions: List[str] = field(default_factory=list)
    added_classes: List[str] = field(default_factory=list)
    removed_classes: List[str] = field(default_factory=list)
    added_imports: List[str] = field(default_factory=list)
    removed_imports: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "added_functions": self.added_functions,
            "removed_functions": self.removed_functions,
            "modified_functions": self.modified_functions,
            "added_classes": self.added_classes,
            "removed_classes": self.removed_classes,
            "added_imports": self.added_imports,
            "removed_imports": self.removed_imports
        }


def get_nodes_info(tree: ast.AST) -> Tuple[Dict[str, str], Dict[str, str], Set[str]]:
    """
    Extract hashes of function bodies, class bodies, and the set of imports.
    """
    functions: Dict[str, str] = {}
    classes: Dict[str, str] = {}
    imports: Set[str] = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
            # Compute a hash of the function body AST representation
            body_dump = ast.dump(node)
            functions[node.name] = hashlib.sha256(body_dump.encode()).hexdigest()
        
        elif isinstance(node, ast.ClassDef):
            body_dump = ast.dump(node)
            classes[node.name] = hashlib.sha256(body_dump.encode()).hexdigest()
            
        elif isinstance(node, ast.Import):
            for name in node.names:
                imports.add(name.name)
        
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imports.add(node.module)

    return functions, classes, imports


def diff_python_files(old_path: str, new_path: str) -> Optional[SemanticDiff]:
    """
    Perform semantic diffing on two Python files.
    """
    try:
        with open(old_path, "r", encoding="utf-8") as f:
            old_tree = ast.parse(f.read())
        with open(new_path, "r", encoding="utf-8") as f:
            new_tree = ast.parse(f.read())
            
        old_funcs, old_classes, old_imports = get_nodes_info(old_tree)
        new_funcs, new_classes, new_imports = get_nodes_info(new_tree)
        
        diff = SemanticDiff()
        
        # Function diff
        for name in new_funcs:
            if name not in old_funcs:
                diff.added_functions.append(name)
            elif new_funcs[name] != old_funcs[name]:
                diff.modified_functions.append(name)
        for name in old_funcs:
            if name not in new_funcs:
                diff.removed_functions.append(name)
                
        # Class diff
        for name in new_classes:
            if name not in old_classes:
                diff.added_classes.append(name)
        for name in old_classes:
            if name not in new_classes:
                diff.removed_classes.append(name)
                
        # Import diff
        diff.added_imports = sorted(list(new_imports - old_imports))
        diff.removed_imports = sorted(list(old_imports - new_imports))
        
        return diff
    except Exception:
        return None


def line_diff(old_path: str, new_path: str) -> str:
    """
    Fall back to a standard line diff for non-code files.
    """
    try:
        with open(old_path, "r", encoding="utf-8", errors="ignore") as f1, \
             open(new_path, "r", encoding="utf-8", errors="ignore") as f2:
            lines1 = f1.readlines()
            lines2 = f2.readlines()
            diff = difflib.unified_diff(lines1, lines2, lineterm="")
            return "\n".join(list(diff)[:10])  # limit to first 10 lines
    except Exception:
        return ""
