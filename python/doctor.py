#!/usr/bin/env python3
"""
Check that this installation can actually do what it claims.

    python3 doctor.py

Turns "it doesn't work" into a specific diagnosis with a specific fix.

Every failure this project has hit on a user's machine took a round trip to
report, reproduce and explain -- a missing dependency CLAASP does not declare,
a server bound to a loopback address a container cannot expose, a port held by
something invisible. None of those said what was wrong, and none of them
could be guessed from the symptom. This asks each question directly and says
what to do about the answer.

Exit status is 0 when everything needed for `build` and `verify` is present,
even if the analysis stack is not: those two are useful on their own.
"""

import os
import shutil
import subprocess
import sys

CHECKS = []


def check(name, needed_for):
    def wrap(fn):
        CHECKS.append((name, needed_for, fn))
        return fn
    return wrap


def _run(cmd, timeout=20):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.SubprocessError) as e:
        return 1, str(e)


# ---------------------------------------------------------------- core

@check("java", "build, verify")
def _java():
    if not shutil.which("java"):
        return False, "not on PATH", "install a JDK 8 or newer"
    rc, out = _run(["java", "-version"])
    return rc == 0, out.strip().splitlines()[0] if out else "?", ""


@check("Digital.jar", "build, verify")
def _digital():
    jar = os.environ.get("DIGITAL_JAR")
    if not jar:
        return (False, "DIGITAL_JAR is not set",
                "point it at Digital.jar from "
                "github.com/hneemann/Digital/releases/latest")
    if not os.path.exists(jar):
        return False, f"{jar} does not exist", "check the path"
    return True, jar, ""


@check("netlist extractor", "build, verify")
def _bridge():
    jar = os.environ.get("BRIDGE_JAR")
    if not jar or not os.path.exists(jar):
        return (False, f"{jar or 'BRIDGE_JAR'} not found",
                "cd java && make DIGITAL_JAR=/path/to/Digital.jar")
    dj = os.environ.get("DIGITAL_JAR", "")
    # os.pathsep, not ':' -- Windows separates classpath entries with ';'
    # and reads a colon-joined string as one path, failing with a
    # ClassNotFoundException for a class that is plainly there.
    rc, out = _run(["java", "-cp", os.pathsep.join([dj, jar]),
                    "digbridge.DigNetlist"])
    ok = "usage:" in out or "DigNetlist" in out
    return ok, jar if ok else out.strip()[:120], \
        "" if ok else "rebuild it against this Digital.jar"


# ------------------------------------------------------------- analysis

@check("CLAASP", "analyse, replicate, cluster")
def _claasp():
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import preload            # noqa: F401
        import claasp             # noqa: F401
    except Exception as e:
        return (False, f"{type(e).__name__}: {e}",
                "pip install claasp, then run setup_sage.py and "
                "patch_claasp.py")
    return True, "importable", ""


@check("CLAASP dependencies", "analyse, replicate, cluster")
def _deps():
    here = os.path.dirname(os.path.abspath(__file__))
    rc, out = _run([sys.executable, os.path.join(here, "check_deps.py")])
    if rc == 0:
        return True, "every required import resolves", ""
    missing = [ln.strip() for ln in out.splitlines()
               if ln.startswith("  ") and "absent" not in ln]
    return (False, "missing: " + ", ".join(missing[:6]),
            "the check_deps.py output lists the pip command")


@check("kissat", "analyse, replicate, cluster")
def _kissat():
    if not shutil.which("kissat"):
        return (False, "not on PATH",
                "build it from github.com/arminbiere/kissat. CaDiCaL will "
                "not substitute: CLAASP parses statistics it does not print")
    rc, out = _run(["kissat", "--version"])
    return rc == 0, out.strip(), ""


@check("espresso", "analyse, replicate, cluster")
def _espresso():
    if not shutil.which("espresso"):
        return (False, "not on PATH",
                "build it from github.com/classabbyamp/espresso-logic; "
                "S-box constraints cannot be generated without it")
    return True, "present", ""


# -------------------------------------------------------------- optional

@check("NIST STS", "random --nist")
def _nist():
    p = "/usr/local/bin/sts-2.1.2/assess"
    if not os.path.exists(p):
        return False, "not installed", "python3 setup_nist.py"
    return True, p, ""


@check("matplotlib", "--export .pdf .png .jpg")
def _mpl():
    try:
        import matplotlib          # noqa: F401
    except ImportError:
        return (False, "not installed",
                "pip install matplotlib, or export .svg which needs nothing")
    return True, matplotlib.__version__, ""


# --------------------------------------------------------------------------

def main():
    print("CrossDraft environment check")
    print()

    results = []
    for name, needed_for, fn in CHECKS:
        try:
            ok, detail, fix = fn()
        except Exception as e:                       # a check must not crash
            ok, detail, fix = False, f"{type(e).__name__}: {e}", ""
        results.append((name, needed_for, ok, detail, fix))
        mark = "ok     " if ok else "MISSING"
        print(f"  {mark}  {name:<24} {detail}")
        if not ok:
            print(f"          needed for: {needed_for}")
            if fix:
                print(f"          fix: {fix}")

    core = [r for r in results if "build" in r[1]]
    core_ok = all(r[2] for r in core)
    analysis = [r for r in results if "analyse" in r[1]]
    analysis_ok = all(r[2] for r in analysis)

    print()
    if core_ok and analysis_ok:
        print("  Everything is present. `selftest` will confirm it works.")
    elif core_ok:
        print("  Drawing and verifying circuits will work; analysis will "
              "not.")
        print("  `build` and `verify` are useful on their own -- they check a "
              "cipher against")
        print("  its published test vectors without a solver anywhere in "
              "sight.")
    else:
        print("  Not usable yet: the items above marked MISSING under "
              "'build, verify'")
        print("  have to be resolved first.")
    return 0 if core_ok else 1


if __name__ == "__main__":
    sys.exit(main())
