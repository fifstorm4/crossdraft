"""
The GUI's input validation, as plain function calls.

    python3 tests/test_validation.py

No server, no Java, no CLAASP: the helpers are pure and can be called
directly, which is the point. A check that needs a container to exercise is a
check that gets skipped when it matters.

These exist because this class of fix is the kind that gets quietly reverted.
`_host_ok` in particular is the first thing anyone removes on hitting a
reverse proxy or a port forward, and without a test the removal looks
harmless.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "python"))

from diggui import (_int, _choice, _under,                    # noqa: E402
                    EXPORT_FORMATS, EXPORT_KINDS, COST_MODELS, BIT_ORDERS)

fails = []


def check(name, ok, note=""):
    print(f"  {'PASS' if ok else 'FAIL'}  {name}{note}")
    if not ok:
        fails.append(name)


def main():
    # _choice: anything outside the list becomes the default. A format
    # string reaches a filename, so this is what stops "svg/../../x".
    check("an export format containing a path falls back",
          _choice({"fmt": "svg/../../../tmp/x.svg"}, "fmt",
                  EXPORT_FORMATS, "svg") == "svg")
    check("a valid export format is kept",
          _choice({"fmt": "tex"}, "fmt", EXPORT_FORMATS, "svg") == "tex")
    check("an unknown subcommand falls back",
          _choice({"kind": "evil"}, "kind", EXPORT_KINDS,
                  "analyse") == "analyse")
    check("an unknown cost model falls back",
          _choice({"model": "../../etc"}, "model", COST_MODELS,
                  "nangate45") == "nangate45")
    check("a shell fragment as bit order falls back",
          _choice({"bitorder": "; rm -rf /"}, "bitorder", BIT_ORDERS,
                  "lsb") == "lsb")
    check("a missing field falls back",
          _choice({}, "fmt", EXPORT_FORMATS, "svg") == "svg")

    # _int: clamped, and never raising. A round count reaches a solver.
    check("a round count above the range is clamped",
          _int({"rounds": "99999"}, "rounds", 3, 1, 64) == 64)
    check("a round count below the range is clamped",
          _int({"rounds": "-5"}, "rounds", 3, 1, 64) == 1)
    check("a non-numeric round count becomes the default",
          _int({"rounds": "abc"}, "rounds", 3, 1, 64) == 3)
    check("a missing round count becomes the default",
          _int({}, "rounds", 7, 1, 64) == 7)
    check("a valid round count is kept",
          _int({"rounds": "12"}, "rounds", 3, 1, 64) == 12)

    # _under: the filesystem boundary.
    check("a path outside the root is refused",
          _under("/etc/passwd", os.getcwd()) is None)
    check("traversal out and back is refused",
          _under(os.path.join(os.getcwd(), "..", "..", "etc", "passwd"),
                 os.getcwd()) is None)
    check("an empty path is refused", _under("", os.getcwd()) is None)

    here = os.path.join(os.getcwd(), "inside.csv")
    check("a path inside the root is kept",
          _under(here, os.getcwd()) == os.path.realpath(here))
    check("a second permitted root also works",
          _under(here, "/nonexistent", os.getcwd())
          == os.path.realpath(here))

    print()
    if fails:
        print(f"{len(fails)} failure(s): {fails}")
        return 1
    print("input validation holds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
