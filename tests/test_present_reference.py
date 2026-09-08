"""
Check the PRESENT model against CLAASP's own PRESENT.

    python3 tests/test_present_reference.py \
        --digital-jar Digital.jar --bridge-jar java/digbridge.jar

CLAASP ships a hand-written PRESENT that has been in use since 2023.  Running
it beside the model this toolchain derives from a schematic is the strongest
check available here: two independent descriptions of the same cipher, solved
by the same engine.  Agreement on the trails -- not merely on the ciphertext --
is what says the translation preserved the differential structure and not just
the function.

Three rounds is deliberate.  The minimum active S-box counts for PRESENT are
1, 2, 4 over rounds 1..3, published in the CHES 2007 proposal, so the numbers
have an external reference too and the search still finishes in seconds.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "python"))

# Published in Bogdanov et al., CHES 2007.
KNOWN_ACTIVE_SBOXES = {1: 1, 2: 2, 3: 4}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--digital-jar", required=True)
    ap.add_argument("--bridge-jar", required=True)
    ap.add_argument("--rounds", type=int, default=3)
    ap.add_argument("--solver", default="KISSAT_EXT")
    a = ap.parse_args()

    os.environ["DIGITAL_JAR"] = os.path.abspath(a.digital_jar)
    os.environ["BRIDGE_JAR"] = os.path.abspath(a.bridge_jar)

    import preload                     # noqa: F401  (passagemath ordering)
    from ciphers import PRESENT, load
    from claasp.ciphers.block_ciphers.present_block_cipher \
        import PresentBlockCipher
    from claasp.cipher_modules.models.utils import set_fixed_variables
    from claasp.cipher_modules.models.sat.sat_models \
        .sat_xor_differential_model import SatXorDifferentialModel

    out = os.path.join(os.getcwd(), "build", "present")
    rj = os.path.join(out, "present_round.json")
    if not os.path.exists(rj):
        print("building the circuit first")
        subprocess.run([sys.executable,
                        os.path.join(HERE, "..", "python", "digcli.py"),
                        "build", "present"], check=True)

    failures = []

    # --- 1. ciphertext ----------------------------------------------------
    print("test vectors (CHES 2007 appendix)")
    built = PresentBlockCipher(key_bit_size=80, number_of_rounds=31)
    for p, k, c in PRESENT["vectors"]:
        b = built.evaluate([p, k])
        m = PRESENT["reference"](p, k, 31)
        ok = (b == c == m)
        print(f"  {'PASS' if ok else 'FAIL'}  P={p:016X} K={k:020X} "
              f"-> {c:016X}")
        if not ok:
            failures.append(f"vector {p:016X}")

    # --- 2. differential trails ------------------------------------------
    print()
    print("lowest-weight differential characteristic, built-in vs derived")

    def lowest(cipher):
        model = SatXorDifferentialModel(cipher)
        fixed = [
            set_fixed_variables("key", "equal", list(range(80)), [0] * 80),
            set_fixed_variables("plaintext", "not_equal",
                                list(range(64)), [0] * 64),
        ]
        t = model.find_lowest_weight_xor_differential_trail(
            fixed_values=fixed, solver_name=a.solver)
        active = sum(1 for k, v in t["components_values"].items()
                     if "sbox" in k and v.get("weight"))
        return t["total_weight"], active

    for n in range(1, a.rounds + 1):
        wb, ab = lowest(PresentBlockCipher(key_bit_size=80,
                                           number_of_rounds=n))
        derived = load("present", n, out)
        wm, am = lowest(derived)

        agree = (wb, ab) == (wm, am)
        known = KNOWN_ACTIVE_SBOXES.get(n)
        matches_paper = known is None or ab == known
        ok = agree and matches_paper
        note = f"  paper: {known} active" if known else ""
        print(f"  {'PASS' if ok else 'FAIL'}  {n} round(s): "
              f"built-in weight {wb} / {ab} active, "
              f"derived weight {wm} / {am} active{note}")
        if not ok:
            failures.append(f"{n}-round trail")

    print()
    if failures:
        print(f"{len(failures)} failure(s): {failures}")
        return 1
    print("the derived model agrees with CLAASP's own PRESENT")
    return 0


if __name__ == "__main__":
    sys.exit(main())
