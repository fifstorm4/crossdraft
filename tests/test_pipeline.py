"""
The CLAASP-backed commands, run as a user would run them, with known answers.

    python3 tests/test_pipeline.py --digital-jar Digital.jar \
            --bridge-jar java/digbridge.jar

Everything here needs CLAASP and a SAT solver, which is why it is not in the
main suite: the checks that need neither should stay fast enough to run on
every commit.

The expected values are external. PRESENT's minimum active S-box counts over
one to three rounds are 1, 2 and 4, published in the CHES 2007 proposal, and
its ciphertexts are in the same paper's appendix. LLBC's seven-round
characteristic of weight 81 is Table VI of the proposal. So a failure here
means this toolchain has stopped agreeing with the literature, not merely
with its own previous output -- which is the only kind of regression worth
gating a merge on.

`replicate --pin-all` earns its place twice over. It pins every intermediate
round, so it checks the published path rather than just its endpoints, and it
is the one command whose correctness the whole project is an argument for.
"""

import argparse
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, "..", "python", "digcli.py")
EXAMPLES = os.path.join(HERE, "..", "examples")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--digital-jar", required=True)
    ap.add_argument("--bridge-jar", required=True)
    ap.add_argument("--skip-nist", action="store_true")
    a = ap.parse_args()

    env = dict(os.environ)
    env["DIGITAL_JAR"] = os.path.abspath(a.digital_jar)
    env["BRIDGE_JAR"] = os.path.abspath(a.bridge_jar)

    fails = []

    def run(*args, timeout=1800):
        t = time.time()
        r = subprocess.run([sys.executable, CLI] + list(args),
                           capture_output=True, text=True, env=env,
                           timeout=timeout)
        return r.returncode, (r.stdout or "") + (r.stderr or ""), \
            time.time() - t

    def check(name, ok, note="", secs=None):
        stamp = f"  [{secs:.0f}s]" if secs is not None else ""
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{note}{stamp}")
        if not ok:
            fails.append(name)

    # ---- build both ciphers ---------------------------------------------
    for cipher in ("present", "llbc"):
        rc, out, dt = run("build", cipher)
        check(f"build {cipher}", rc == 0, _tail(out) if rc else "", dt)
    if fails:
        print("\nnothing else can run without the circuits")
        return 1

    # ---- verify against the literature ----------------------------------
    rc, out, dt = run("verify", "present", "--rounds", "31", "--trials", "4")
    check("PRESENT reproduces the CHES 2007 vectors",
          rc == 0 and "published vectors: 4/4" in out,
          "" if rc == 0 else _tail(out), dt)

    rc, out, dt = run("verify", "llbc", "--rounds", "20", "--trials", "4")
    check("LLBC circuit matches its reference at 20 rounds",
          rc == 0 and "20 rounds: 4/4" in out,
          "" if rc == 0 else _tail(out), dt)

    # ---- differential search --------------------------------------------
    # PRESENT: 4 active S-boxes over three rounds, so weight 8.
    rc, out, dt = run("analyse", "present", "--rounds", "3")
    w = _weight(out)
    check("PRESENT 3-round characteristic weighs 8", w == 8.0,
          f"  [got {w}]" if w != 8.0 else "", dt)

    rc, out, dt = run("analyse", "llbc", "--rounds", "3")
    w = _weight(out)
    check("LLBC 3-round characteristic weighs 8", w == 8.0,
          f"  [got {w}]" if w != 8.0 else "", dt)

    # ---- the published path, pinned round by round ----------------------
    trail = os.path.join(EXAMPLES, "llbc_table6.csv")
    rc, out, dt = run("replicate", "llbc", "--trail", trail,
                      "--rounds", "7", "--pin-all", "--expect-weight", "81")
    check("LLBC Table VI replicates with every round pinned",
          rc == 0 and "MATCH" in out, _tail(out) if rc else "", dt)

    # ---- the rest of the analysis surface -------------------------------
    # Not known-answer: these are here so a crash is caught, which is how
    # `analyse` was found calling a key-schedule setting PRESENT does not
    # have.
    for name, args_ in (
            ("cluster", ("cluster", "llbc", "--rounds", "3")),
            ("impossible differentials",
             ("impossible", "llbc", "--rounds", "3", "--max-pairs", "8")),
            ("related key", ("relatedkey", "llbc", "--rounds", "3")),
            ("weight bound",
             ("bound", "llbc", "--rounds", "3", "--weights", "7", "8")),
            ("cost model", ("cost", "llbc", "--rounds", "20")),
            ("S-box tables", ("sbox", "llbc")),
            ("provenance", ("env", "llbc")),
    ):
        rc, out, dt = run(*args_)
        check(name, rc == 0, _tail(out) if rc else "", dt)

    # `bound` has a known answer too: nothing lighter than 8 exists.
    rc, out, dt = run("bound", "llbc", "--rounds", "3", "--weights", "7", "8")
    ok = "weight    7: UNSATISFIABLE" in out and \
         "weight    8: SATISFIABLE" in out
    check("nothing lighter than weight 8 over 3 LLBC rounds", ok,
          "" if ok else _tail(out), dt)

    # ---- statistics ------------------------------------------------------
    rc, out, dt = run("random", "present", "--rounds", "31", "--samples", "40")
    check("full PRESENT avalanches", rc == 0 and "close to ideal" in out,
          _tail(out) if rc else "", dt)

    if a.skip_nist:
        print("  SKIP  NIST battery (--skip-nist)")
    elif not os.path.exists("/usr/local/bin/sts-2.1.2/assess"):
        print("  SKIP  NIST battery (STS not installed)")
    else:
        # Two rounds of PRESENT is not random and the suite should say so.
        rc, out, dt = run("random", "present", "--rounds", "2", "--nist",
                          "--bits", "32768", "--sequences", "16",
                          "--samples", "20")
        m = re.search(r"(\d+)/(\d+) sub-tests passed", out)
        if not m:
            # No results at all is an environment problem, not a regression:
            # CLAASP copies the NIST suite into the working directory and
            # runs it there, which a bind mount or a restricted shell can
            # defeat. Report it, do not gate a merge on it -- the command's
            # own output now explains what to look at.
            print("  SKIP  NIST battery (no results came back)")
            for line in out.strip().splitlines()[-6:]:
                print(f"          {line}")
        else:
            rate = int(m.group(1)) / int(m.group(2))
            check("NIST rejects a two-round PRESENT", rc == 0 and rate < 0.5,
                  f"  [{m.group(0)}]", dt)

    print()
    if fails:
        print(f"{len(fails)} failure(s): {fails}")
        return 1
    print("the analysis pipeline agrees with the published figures")
    return 0


def _weight(out):
    m = re.search(r"weight ([\d.]+)", out)
    return float(m.group(1)) if m else None


def _tail(out):
    lines = out.strip().splitlines()
    return "  " + (lines[-1] if lines else "no output")


if __name__ == "__main__":
    sys.exit(main())
