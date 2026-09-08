"""
The analysis extras: cost estimation, benchmarks, clustering, impossible
differentials, weight bounds.

    python3 tests/test_analysis.py --digital-jar Digital.jar \
                                  --bridge-jar java/digbridge.jar

Costing and the benchmark registry need no solver.  The rest do, and are
skipped with a message rather than failing if CLAASP is not installed.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "python"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--digital-jar", required=True)
    ap.add_argument("--bridge-jar", required=True)
    ap.add_argument("--rounds", type=int, default=3)
    a = ap.parse_args()
    os.environ["DIGITAL_JAR"] = os.path.abspath(a.digital_jar)
    os.environ["BRIDGE_JAR"] = os.path.abspath(a.bridge_jar)

    fails = []

    def check(name, ok, note=""):
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{note}")
        if not ok:
            fails.append(name)

    out = os.path.join(os.getcwd(), "build", "present")
    if not os.path.exists(os.path.join(out, "present_round.json")):
        subprocess.run([sys.executable,
                        os.path.join(HERE, "..", "python", "digcli.py"),
                        "build", "present"], check=True,
                       capture_output=True)

    from dig2claasp import Netlist
    from digcost import (estimate, software_cost, compare, cite,
                         ENVIRONMENTS, GATE_MODELS, BENCHMARKS)

    nl = Netlist(os.path.join(out, "present_round.json"))

    # --- costing ---------------------------------------------------------
    for model in GATE_MODELS:
        r = estimate(nl, model=model, unrolled_rounds=31)
        check(f"cost model {model}",
              r["total"] > 0 and r["sboxes"] == 16 and r["caveat"],
              f"  [{r['total']:,.0f} {r['unit']}, {r['sboxes']} S-boxes]")

    sw = software_cost(nl, word_bits=32, unrolled_rounds=31)
    check("software cost", sw["cycles_total"] > 0 and sw["caveat"],
          f"  [~{sw['cycles_total']:,} word ops over 31 rounds]")

    # --- benchmark registry ----------------------------------------------
    # Every figure must name the environment it came from; a bare number
    # cannot be compared and must not be presentable as if it could.
    orphans = [(n, e) for n, e, _ in BENCHMARKS if e not in ENVIRONMENTS]
    check("every benchmark names a known environment", not orphans,
          f"  [{len(BENCHMARKS)} entries, {len(ENVIRONMENTS)} environments]")

    incomplete = [k for k, v in ENVIRONMENTS.items() if "source" not in v]
    check("every environment cites a source", not incomplete)

    groups = compare("area_ge")
    multi = len(groups) > 1
    check("area figures stay grouped by environment", multi,
          f"  [{len(groups)} groups, never ranked across]")

    # PRESENT appears in two ASIC environments with very different numbers;
    # that is the whole reason grouping is enforced.
    present = {g["environment"]: dict(g["rows"] and
                                      [(n, v) for n, v, _ in g["rows"]])
               for g in groups}
    a90 = present.get("gift_stm90_roundbased", {}).get("PRESENT-64-128")
    a180 = present.get("llbc_umc180_unrolled", {}).get("PRESENT-64-128")
    check("the same cipher differs across environments",
          a90 and a180 and a180 > a90 * 10,
          f"  [PRESENT-64-128: {a90:,} GE round-based 90nm vs "
          f"{a180:,} GE unrolled 0.18um]" if a90 and a180 else "")

    check("provenance is printable", "Table" in cite("llbc_nangate45_unrolled"))

    # --- solver-backed ---------------------------------------------------
    try:
        import preload            # noqa: F401
        from claasp.cipher_modules.models.sat.sat_models \
            .sat_xor_differential_model import SatXorDifferentialModel  # noqa
    except Exception as e:
        print(f"  SKIP  solver-backed checks (CLAASP unavailable: "
              f"{type(e).__name__})")
        print()
        return 1 if fails else 0

    from ciphers import load
    from digattack import differential_bound, impossible_differentials

    cipher = load("present", a.rounds, out)

    # PRESENT's minimum over 3 rounds is 4 active S-boxes, so weight 8.
    res = dict((w, st) for w, st, _ in differential_bound(
        cipher, [7, 8], key_bits=80, block_bits=64, verbose=False))
    check("weight bound brackets the known minimum",
          res.get(7) == "UNSATISFIABLE" and res.get(8) == "SATISFIABLE",
          f"  [weight 7 {res.get(7)}, weight 8 {res.get(8)}; "
          f"CHES 2007 gives 4 active S-boxes over 3 rounds]")

    r = impossible_differentials(cipher, cell_bits=4, key_bits=80,
                                 block_bits=64, max_pairs=16, verbose=False)
    check("impossible differentials come with UNSAT certificates",
          r["tested_pairs"] == 16 and "UNSAT" in r["note"],
          f"  [{len(r['impossible'])} of {r['tested_pairs']} proved, "
          f"{r['seconds']}s]")

    print()
    if fails:
        print(f"{len(fails)} failure(s): {fails}")
        return 1
    print("all analysis extras work")
    return 0


if __name__ == "__main__":
    sys.exit(main())
