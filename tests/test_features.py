"""
The optional features: sub-circuit expansion, trail export, S-box tables.

    python3 tests/test_features.py --digital-jar Digital.jar \
                                   --bridge-jar java/digbridge.jar

Each of these is opt-in -- nothing in build / verify / analyse imports them --
so they get their own suite rather than slowing the core one down.
"""
import argparse
import os
import random
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "python"))

S = [0x4, 0x7, 0x5, 0x1, 0xC, 0xB, 0xD, 0x8,
     0xE, 0xF, 0x6, 0x3, 0xA, 0x9, 0x2, 0x0]
M64 = (1 << 64) - 1


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--digital-jar", required=True)
    ap.add_argument("--bridge-jar", required=True)
    a = ap.parse_args()
    jar, bridge = os.path.abspath(a.digital_jar), os.path.abspath(a.bridge_jar)

    from digparts import Builder
    from digbuild import Circuit
    from dig2claasp import Netlist, evaluate
    from digtrail import Trail, sbox_tables

    fails = []

    def check(name, ok, note=""):
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{note}")
        if not ok:
            fails.append(name)

    with tempfile.TemporaryDirectory() as tmp:
        # ---- sub-circuit expansion -------------------------------------
        # A schematic stays readable by dropping a whole layer in as one box.
        # The netlist names the box by filename and says nothing about its
        # contents, so the translator has to open it and splice it in --
        # twice here, to check the two instances stay distinct.
        b = Builder()
        b.out("y", b.sbox_layer(b.inp("x", 64), S, tag="S"))
        b.write(os.path.join(tmp, "subcell.dig"), jar, bridge)

        c = Circuit()
        i0 = c.add("In", x=100, y=200, Label="a", Bits=64)
        i1 = c.add("In", x=100, y=400, Label="b", Bits=64)
        s0 = c.add("subcell.dig", x=500, y=200)
        s1 = c.add("subcell.dig", x=500, y=500)
        g = c.add("XOr", x=900, y=300, Bits=64, Inputs=2)
        o = c.add("Out", x=1300, y=300, Label="y", Bits=64)
        c.connect((i0, "out"), (s0, "x"))
        c.connect((i1, "out"), (s1, "x"))
        c.connect((s0, "y"), (g, "In_1"))
        c.connect((s1, "y"), (g, "In_2"))
        c.connect((g, "out"), (o, "in"))
        parent = os.path.join(tmp, "parent.dig")
        c.write(parent, jar, bridge)

        js = os.path.join(tmp, "parent.json")
        subprocess.run(["java", "-cp", f"{jar}:{bridge}",
                        "digbridge.DigNetlist", parent, js],
                       check=True, capture_output=True)
        nl = Netlist(js, digital_jar=jar, bridge_jar=bridge)

        def ref(x, y):
            f = lambda v: sum(S[(v >> (4 * i)) & 0xF] << (4 * i)
                              for i in range(16))
            return f(x) ^ f(y)

        random.seed(20)
        ok = True
        for _ in range(6):
            x, y = random.getrandbits(64), random.getrandbits(64)
            ok &= evaluate(nl, {"a": x, "b": y})["y"] == ref(x, y)
        check("sub-circuit expansion, two instances", ok,
              f"  [{len(nl.components)} components after flattening]")

        # ---- trail export ----------------------------------------------
        trail = Trail.from_states(
            states=[0x0000000000000040, 0x0000000200000002,
                    0x0000010100000101],
            state_bits=64, weights=[2, 2, 4], name="synthetic",
            active=[[3], [7], [1, 9]])

        native = [".svg", ".tex", ".tikz", ".csv", ".json", ".md", ".txt"]
        for ext in native:
            p = os.path.join(tmp, "t" + ext)
            try:
                trail.save(p)
                check(f"export {ext} (standard library only)",
                      os.path.getsize(p) > 0,
                      f"  [{os.path.getsize(p)} bytes]")
            except Exception as e:
                check(f"export {ext}", False, f"  {e}")

        try:
            import matplotlib  # noqa: F401
            have_mpl = True
        except ImportError:
            have_mpl = False
        for ext in (".pdf", ".png", ".jpg"):
            p = os.path.join(tmp, "t" + ext)
            if not have_mpl:
                print(f"  SKIP  export {ext} (matplotlib not installed)")
                continue
            try:
                trail.save(p)
                check(f"export {ext} (matplotlib)",
                      os.path.getsize(p) > 0,
                      f"  [{os.path.getsize(p)} bytes]")
            except Exception as e:
                check(f"export {ext}", False, f"  {e}")

        # ---- S-box tables ----------------------------------------------
        # PRESENT's published profile: bijective, max DDT entry 4, max LAT
        # deviation 4, so the maximum differential probability is 2^-2.
        r = sbox_tables(S, "S1")
        check("S-box DDT and LAT",
              r["bijective"] and r["ddt_max"] == 4 and r["lat_max"] == 4,
              f"  [DDTmax {r['ddt_max']}, LATmax {r['lat_max']}, "
              f"max DP {r['max_differential_probability']}]")

    print()
    if fails:
        print(f"{len(fails)} failure(s): {fails}")
        return 1
    print("all optional features work")
    return 0


if __name__ == "__main__":
    sys.exit(main())
