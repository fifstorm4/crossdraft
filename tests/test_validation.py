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

    _gate_checks()

    print()
    if fails:
        print(f"{len(fails)} failure(s): {fails}")
        return 1
    print("input validation holds")
    return 0


def _gate_checks():
    """
    The verify gate, without a solver anywhere near it.

    Worth testing offline for the same reason the gate sits before the
    CLAASP import: it has to work on a machine where the analysis stack is
    absent, or the people who most need to see its message never will.
    """
    import json
    import shutil
    import tempfile
    import types

    import digcli
    from ciphers import REGISTRY

    spec = REGISTRY["present"]

    with tempfile.TemporaryDirectory() as out:
        args = types.SimpleNamespace(unverified=False)

        # No record at all.
        try:
            digcli._require_verified(spec, out, 3, args)
            check("an unverified circuit is refused", False)
        except SystemExit:
            check("an unverified circuit is refused", True)

        # ...unless asked for.
        args.unverified = True
        try:
            digcli._require_verified(spec, out, 3, args)
            check("--unverified proceeds", True)
        except SystemExit:
            check("--unverified proceeds", False)
        args.unverified = False

        # A record naming a netlist that is not there fails on the digest,
        # which is the same path a modified circuit takes.
        json.dump({"digests": {"present_round.json": "0" * 64},
                   "rounds_checked": [1, 2, 5, 31], "vectors": "4/4",
                   "trials": 8, "seed": 0,
                   "definition": digcli._spec_digest(spec)},
                  open(os.path.join(out, digcli.VERIFIED), "w"))
        try:
            digcli._require_verified(spec, out, 3, args)
            check("a changed circuit is refused", False)
        except SystemExit:
            check("a changed circuit is refused", True)

        # A record with no digests at all: only the definition is checked,
        # so a stale definition must still be caught.
        json.dump({"digests": {}, "rounds_checked": [1, 2, 5, 31],
                   "vectors": "4/4", "trials": 8, "seed": 0,
                   "definition": "0" * 64},
                  open(os.path.join(out, digcli.VERIFIED), "w"))
        try:
            digcli._require_verified(spec, out, 3, args)
            check("a changed definition is refused", False)
        except SystemExit:
            check("a changed definition is refused", True)

        # A record from before the definition digest existed.
        json.dump({"digests": {}, "rounds_checked": [1, 2, 5, 31],
                   "vectors": "4/4", "reference": "0" * 64},
                  open(os.path.join(out, digcli.VERIFIED), "w"))
        try:
            digcli._require_verified(spec, out, 3, args)
            check("a record in the old format is refused", False)
        except SystemExit:
            check("a record in the old format is refused", True)

        # A sound record passes, and says so.
        json.dump({"digests": {}, "rounds_checked": [1, 2, 5, 20],
                   "vectors": "4/4", "trials": 8, "seed": 0,
                   "definition": digcli._spec_digest(spec)},
                  open(os.path.join(out, digcli.VERIFIED), "w"))
        try:
            digcli._require_verified(spec, out, 3, args)
            check("a sound record passes", True)
        except SystemExit:
            check("a sound record passes", False)

    # The digest must move when anything reaching the model does.
    import copy
    other = copy.copy(spec)
    other["params"] = lambda i, key: {"rk": 0}
    check("changing the round constants changes the digest",
          digcli._spec_digest(other) != digcli._spec_digest(spec))

    other = copy.copy(spec)
    other["block_bits"] = 128
    check("changing the block size changes the digest",
          digcli._spec_digest(other) != digcli._spec_digest(spec))

    check("the digest is stable across calls",
          digcli._spec_digest(spec) == digcli._spec_digest(spec))

    # A record from before rounds_checked became a list must still be read,
    # since it is only the definition digest that forces a re-verify.
    import io
    import contextlib
    with tempfile.TemporaryDirectory() as out:
        json.dump({"digests": {}, "rounds_checked": 31, "vectors": "4/4",
                   "trials": 8, "seed": 0,
                   "definition": digcli._spec_digest(spec)},
                  open(os.path.join(out, digcli.VERIFIED), "w"))
        buf = io.StringIO()
        try:
            with contextlib.redirect_stdout(buf):
                digcli._require_verified(
                    spec, out, 3, types.SimpleNamespace(unverified=False))
            check("a scalar rounds_checked is still readable", True)
        except SystemExit:
            check("a scalar rounds_checked is still readable", False)


if __name__ == "__main__":
    sys.exit(main())
