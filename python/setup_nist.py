#!/usr/bin/env python3
"""
Build the NIST statistical test suite CLAASP shells out to.

    python3 setup_nist.py

CLAASP runs /usr/local/bin/sts-2.1.2/assess and parses its report, so the
binary has to exist at exactly that path.  NIST distributes STS 2.1.2 as a zip
from csrc.nist.gov; this fetches a GitHub mirror of the same release instead,
because that is reachable from more build environments.

CLAASP ships patched copies of assess.c, utilities.c and utilities.h -- the
stock ones prompt interactively and cannot be driven from a script -- so those
are copied over the mirror's before building.

Also creates the per-test output folders under experiments/AlgorithmTesting.
The stock makefile does not, and without them assess fails with "LOG FILES
COULD NOT BE OPENED" and writes an empty report that CLAASP then cannot parse.

Needs gcc, make, git.  Everything else here works without it; only `digstat.nist`
does not.
"""
import os
import shutil
import subprocess
import sys
import tempfile

MIRROR = "https://github.com/terrillmoore/NIST-Statistical-Test-Suite.git"
TARGET = "/usr/local/bin/sts-2.1.2"

TESTS = ["Frequency", "BlockFrequency", "Runs", "LongestRun", "Rank", "FFT",
         "NonOverlappingTemplate", "OverlappingTemplate", "Universal",
         "LinearComplexity", "Serial", "ApproximateEntropy",
         "CumulativeSums", "RandomExcursions", "RandomExcursionsVariant"]


def main():
    if os.path.exists(os.path.join(TARGET, "assess")):
        print(f"already installed: {TARGET}/assess")
        _make_dirs()
        return 0

    for tool in ("git", "make", "gcc"):
        if not shutil.which(tool):
            sys.exit(f"{tool} is required")

    try:
        import claasp
        deps = os.path.join(os.path.dirname(os.path.dirname(
            list(claasp.__path__)[0])), "required_dependencies")
    except ImportError:
        deps = None

    with tempfile.TemporaryDirectory() as tmp:
        print(f"fetching {MIRROR}")
        subprocess.run(["git", "clone", "-q", "--depth", "1", MIRROR, tmp],
                       check=True)
        src = os.path.join(tmp, "sts")
        if not os.path.isdir(src):
            sys.exit(f"unexpected mirror layout: no sts/ in {tmp}")

        # CLAASP's patched sources drive assess non-interactively.
        patched = 0
        for name, sub in (("assess.c", "src"), ("utilities.c", "src"),
                          ("utilities.h", "include")):
            for base in filter(None, [deps, os.path.join(
                    os.path.dirname(os.path.abspath(__file__)),
                    "required_dependencies")]):
                p = os.path.join(base, name)
                if os.path.exists(p):
                    shutil.copy(p, os.path.join(src, sub, name))
                    patched += 1
                    break
        if patched < 3:
            print("  warning: CLAASP's patched assess.c was not found, so "
                  "the stock interactive version will be built and CLAASP "
                  "will not be able to drive it")

        os.makedirs(os.path.join(src, "obj"), exist_ok=True)
        for t in TESTS:
            os.makedirs(os.path.join(src, "experiments", "AlgorithmTesting",
                                     t), exist_ok=True)

        print("building")
        r = subprocess.run(["make"], cwd=src, capture_output=True, text=True)
        if not os.path.exists(os.path.join(src, "assess")):
            sys.exit(f"build failed:\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}")

        os.makedirs(TARGET, exist_ok=True)
        for item in os.listdir(src):
            s, d = os.path.join(src, item), os.path.join(TARGET, item)
            (shutil.copytree if os.path.isdir(s) else shutil.copy)(
                s, d, dirs_exist_ok=True) if os.path.isdir(s) \
                else shutil.copy(s, d)

    _make_dirs()
    link = "/usr/local/bin/niststs"
    if not os.path.exists(link):
        os.symlink(os.path.join(TARGET, "assess"), link)
    print(f"installed {TARGET}/assess")
    return 0


def _make_dirs():
    """assess writes one report per test and will not create the folders."""
    made = 0
    for t in TESTS:
        p = os.path.join(TARGET, "experiments", "AlgorithmTesting", t)
        if not os.path.isdir(p):
            os.makedirs(p, exist_ok=True)
            made += 1
    if made:
        print(f"created {made} output folder(s) under "
              f"experiments/AlgorithmTesting")


if __name__ == "__main__":
    sys.exit(main())
