#!/usr/bin/env python3
"""
Is every module CLAASP imports actually installed?

    python3 check_deps.py

CLAASP's setup.py declares three requirements and imports fifteen: the
project assumes its own Docker image, where the rest happens to be present.
`pip install claasp` therefore succeeds and then fails at run time, with a
ModuleNotFoundError raised partway through an unrelated import chain, naming
a module the user never mentioned.

This walks every import in the installed package and reports what is missing,
so the answer arrives at build time and all at once rather than one rebuild
per module.

Modules only reachable through paths this toolchain does not use are listed
as optional: gurobipy needs a commercial licence, and tensorflow and keras
are a large dependency for the neural-distinguisher module alone.
"""

import ast
import glob
import importlib.util
import os
import sys

OPTIONAL = {
    "gurobipy": "MILP via Gurobi; needs a commercial licence",
    "tensorflow": "neural distinguishers only; large",
    "keras": "neural distinguishers only; large",
    "plotly": "interactive plots only; digtrail writes SVG instead",
}


def imports_of(package_root):
    found = set()
    for path in glob.glob(os.path.join(package_root, "**", "*.py"),
                          recursive=True):
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                tree = ast.parse(fh.read())
        except (SyntaxError, OSError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    found.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.module \
                    and node.level == 0:
                found.add(node.module.split(".")[0])
    return found


def main():
    try:
        import claasp
    except ImportError:
        print("claasp is not installed")
        return 1
    root = list(claasp.__path__)[0]

    std = set(sys.stdlib_module_names)
    skip = std | {"claasp", "sage", "__future__"}
    mods = sorted(m for m in imports_of(root) if m not in skip)

    missing, optional_missing = [], []
    for m in mods:
        if importlib.util.find_spec(m) is None:
            (optional_missing if m in OPTIONAL else missing).append(m)

    print(f"checked {len(mods)} third-party imports in claasp")
    for m in optional_missing:
        print(f"  --  {m} absent ({OPTIONAL[m]})")

    if missing:
        print()
        print("MISSING, and needed:")
        for m in missing:
            print(f"  {m}")
        print()
        print("  pip install " + " ".join(
            {"yaml": "pyyaml"}.get(m, m) for m in missing))
        return 1

    print("every required import resolves")
    return 0


if __name__ == "__main__":
    sys.exit(main())
