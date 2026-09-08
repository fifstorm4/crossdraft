#!/usr/bin/env python3
"""
Make CLAASP work on passagemath.

    python3 setup_sage.py

passagemath ships SageMath as focused wheels rather than one monolith, so
`sage.all` does not exist.  CLAASP imports exactly one name from it -- ZZ.
This writes a shim providing that, next to whichever sage package is
installed.  It does nothing if a real Sage is present.

Nothing else here is patched: the circular-import ordering is handled by
preload.py, and the two external binaries CLAASP shells out to (espresso,
kissat) have to be installed separately -- see the README.
"""
import os
import sys


def main():
    try:
        import sage
    except ImportError:
        sys.exit("sage is not installed; pip install passagemath-modules "
                 "passagemath-symbolics passagemath-brial passagemath-glpk "
                 "passagemath-polyhedra passagemath-combinat")

    root = list(sage.__path__)[0]
    target = os.path.join(root, "all.py")

    if os.path.exists(target):
        try:
            from sage.all import ZZ  # noqa: F401
            print(f"sage.all already works ({target}); nothing to do")
            return 0
        except Exception:
            print(f"replacing a broken {target}")

    with open(target, "w") as fh:
        fh.write(SHIM)
    print(f"wrote {target}")

    try:
        import sage.rings.integer       # noqa: F401
        import sage.rings.integer_ring  # noqa: F401
        from sage.all import ZZ
        print(f"verified: sage.all.ZZ = {ZZ}")
    except Exception as e:
        print(f"shim written but verification failed: {e}")
        return 1
    return 0


SHIM = '''"""Minimal sage.all shim for passagemath.

passagemath omits the monolithic `sage.all`; CLAASP imports one name from it.
Resolution is deferred to __getattr__ so that importing this module does not
itself trigger the sage.rings.integer / integer_ring circular import.
"""


def __getattr__(name):
    if name == "ZZ":
        import sage.rings.integer          # noqa: F401  (order matters)
        from sage.rings.integer_ring import ZZ
        globals()["ZZ"] = ZZ
        return ZZ
    raise AttributeError(
        f"module 'sage.all' has no attribute {name!r}; this is a minimal "
        f"shim providing only the names CLAASP imports")
'''


if __name__ == "__main__":
    raise SystemExit(main())
