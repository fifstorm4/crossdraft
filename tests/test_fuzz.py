"""
Randomised cross-check: does the evaluator agree with Digital on circuits
nobody wrote by hand?

    python3 tests/test_fuzz.py --digital-jar Digital.jar \
            --bridge-jar java/digbridge.jar --cases 200

WHY THIS EXISTS
---------------
Three bugs in this toolchain have had the same shape:

  * splitter port names sorted as strings, so "10" came before "2" and every
    splitter with more than ten ports transposed its words;
  * Digital's bundle counting from the LSB against CLAASP's operands listing
    positions MSB-first, so any circuit slicing a register into words came
    out reversed;
  * splitter ports resolved by position instead of by name, so leaving one
    end of a slice unwired shifted every remaining port onto the wrong bits.

Each produced a **working circuit computing the wrong function**.  None was
caught by a unit test.  All three surfaced by accident, while building
something else, and the third only appeared once wide registers existed --
that is, once two features were combined.

Hand-written cases test the combinations someone thought of.  The failure
mode here is the combination nobody thought of, and a GUI exists precisely so
that users can make combinations the author never tried.  So the cases are
generated instead: random primitives, random widths, random bit orders,
stacked to random depth, with Digital's own simulator as the oracle.

Every failure prints the exact call sequence that produced it, so it can be
pasted into a file and shrunk by hand.  Runs are seeded: the same --seed
gives the same circuits.
"""

import argparse
import json
import os
import random
import subprocess
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "python"))
from javacp import classpath                    # noqa: E402


def rand_sbox(rng, bits):
    t = list(range(1 << bits))
    rng.shuffle(t)
    return t


class Recipe:
    """
    A generated circuit, kept as a list of steps so a failure can be printed
    as source rather than as a coordinate dump.
    """

    def __init__(self, rng, width, order, depth):
        self.rng = rng
        self.width = width
        self.order = order
        self.steps = []
        self.depth = depth

    def build(self, b):
        """Apply the steps to a Builder, returning the final port."""
        x = b.inp("x", self.width)
        for kind, arg in self.steps:
            if kind == "rotl":
                x = b.rotl(x, arg)
            elif kind == "rotr":
                x = b.rotr(x, arg)
            elif kind == "sbox":
                x = b.sbox_layer(x, arg, tag=f"S{len(self.steps)}")
            elif kind == "xor_const":
                x = b.xor(x, b.const(arg, x.bits))
            elif kind == "not":
                x = b.not_(x)
            elif kind == "words_reverse":
                x = b.join(list(reversed(b.words(x, arg))))
            elif kind == "permute":
                x = b.permute(x, arg)
            elif kind == "cut_join":
                lo, hi = arg
                pieces = []
                if lo:
                    pieces.append(b._cut(x, 0, lo))
                pieces.append(b._cut(x, lo, hi))
                if hi < x.bits:
                    pieces.append(b._cut(x, hi, x.bits))
                x = b.join_bits(pieces)
            elif kind == "xor_slices":
                lo, hi = arg
                piece = b._cut(x, lo, hi)
                x = b.xor(x, b.join_bits(
                    [piece] * (x.bits // (hi - lo))
                    if x.bits % (hi - lo) == 0 else [b.const(0, x.bits)]))
            else:
                raise AssertionError(kind)
        return x

    def apply(self, value):
        """The same steps, in plain Python, as the oracle for `expected`."""
        m = (1 << self.width) - 1
        n = self.width
        x = value & m

        def rol(v, k):
            k %= n
            return ((v << k) | (v >> (n - k))) & m if k else v

        for kind, arg in self.steps:
            if kind == "rotl":
                x = rol(x, arg if self.order == "lsb" else n - (arg % n))
            elif kind == "rotr":
                k = n - (arg % n)
                x = rol(x, k if self.order == "lsb" else n - (k % n))
            elif kind == "sbox":
                cell = max(1, (len(arg) - 1).bit_length())
                x = sum(arg[(x >> (cell * i)) & (len(arg) - 1)] << (cell * i)
                        for i in range(n // cell))
            elif kind == "xor_const":
                x ^= arg
            elif kind == "not":
                x = ~x & m
            elif kind == "words_reverse":
                cnt = n // arg
                w = [(x >> (arg * i)) & ((1 << arg) - 1) for i in range(cnt)]
                # words() hands back LSB-first under "lsb" and MSB-first under
                # "msb"; reversing then rejoining is a word swap either way.
                x = sum(w[cnt - 1 - i] << (arg * i) for i in range(cnt))
            elif kind == "permute":
                # Builder converts an msb-indexed mapping into Digital's
                # lsb indexing, so the oracle has to make the same trip:
                # under "msb" both the position being filled and the bit
                # filling it are mirrored.
                mapping = arg
                if self.order == "msb":
                    mapping = [n - 1 - mapping[n - 1 - j] for j in range(n)]
                x = sum(((x >> mapping[j]) & 1) << j for j in range(n))
            elif kind == "cut_join":
                pass                       # cut then rejoin is the identity
            elif kind == "xor_slices":
                lo, hi = arg
                w = hi - lo
                if n % w == 0:
                    piece = (x >> lo) & ((1 << w) - 1)
                    rep = sum(piece << (w * i) for i in range(n // w))
                    x ^= rep
            else:
                raise AssertionError(kind)
        return x & m

    def source(self):
        lines = [f"b = Builder(bit_order={self.order!r})",
                 f'x = b.inp("x", {self.width})']
        for kind, arg in self.steps:
            if kind in ("rotl", "rotr"):
                lines.append(f"x = b.{kind}(x, {arg})")
            elif kind == "sbox":
                lines.append(f"x = b.sbox_layer(x, {arg})")
            elif kind == "xor_const":
                lines.append(f"x = b.xor(x, b.const({arg:#x}, x.bits))")
            elif kind == "not":
                lines.append("x = b.not_(x)")
            elif kind == "words_reverse":
                lines.append(f"x = b.join(list(reversed(b.words(x, {arg}))))")
            elif kind == "permute":
                lines.append(f"x = b.permute(x, {arg})")
            elif kind == "cut_join":
                lines.append(f"x = <cut/join at {arg}>")
            elif kind == "xor_slices":
                lines.append(f"x = <xor with slice {arg} repeated>")
        lines.append('b.out("y", x)')
        return "\n".join("    " + ln for ln in lines)


def make_wide_recipe(rng, index):
    """
    A register wider than one Digital bus, exercised with rotations, slices
    and splices.

    Kept separate from the narrow recipes because the oracle is different:
    everything here is stated on the whole register, and the point is that
    the word boundary is invisible.  The bug that motivated wide registers --
    splitter ports resolved by position rather than name -- only appeared
    once slicing left ports unwired, which is exactly what these do.
    """
    bits = rng.choice([80, 96, 128, 192])
    steps = []
    for _ in range(rng.randint(1, 4)):
        kind = rng.choice(["rotl", "rotr", "slice_splice", "xor_const"])
        if kind in ("rotl", "rotr"):
            steps.append((kind, rng.randrange(1, bits)))
        elif kind == "slice_splice":
            w = rng.choice([4, 8, 16])
            src = rng.randrange(0, bits - w + 1)
            dst = rng.randrange(0, bits - w + 1)
            steps.append((kind, (src, src + w, dst)))
        else:
            steps.append((kind, rng.getrandbits(bits)))
    return bits, steps


def run_wide_case(bits, steps, jar, bridge, tmp, index):
    from digparts import Builder
    from dig2claasp import Netlist, evaluate, cross_check

    b = Builder()
    k = b.wide_in("k", bits)
    for kind, arg in steps:
        if kind == "rotl":
            k = b.wide_rotl(k, arg)
        elif kind == "rotr":
            k = b.wide_rotr(k, arg)
        elif kind == "slice_splice":
            lo, hi, dst = arg
            k = b.wide_splice(k, dst, b.wide_slice(k, lo, hi))
        elif kind == "xor_const":
            k = b.wide_xor(k, b.wide_const(arg, bits))
    b.wide_out("y", k)
    dig = os.path.join(tmp, f"wide{index}.dig")
    b.write(dig, jar, bridge)

    js = dig.replace(".dig", ".json")
    r = subprocess.run(["java", "-cp", classpath(jar, bridge),
                        "digbridge.DigNetlist", dig, js],
                       capture_output=True, text=True)
    if r.returncode:
        return False, f"netlist extraction failed:\n{r.stderr}"
    nl = Netlist(js)

    m = (1 << bits) - 1
    words = [min(64, bits - 64 * i) for i in range((bits + 63) // 64)]

    def oracle(v):
        x = v & m
        for kind, arg in steps:
            if kind == "rotl":
                n = arg % bits
                x = ((x << n) | (x >> (bits - n))) & m if n else x
            elif kind == "rotr":
                n = (bits - (arg % bits)) % bits
                x = ((x << n) | (x >> (bits - n))) & m if n else x
            elif kind == "slice_splice":
                lo, hi, dst = arg
                piece = (x >> lo) & ((1 << (hi - lo)) - 1)
                mask = ((1 << (hi - lo)) - 1) << dst
                x = (x & ~mask) | (piece << dst)
            elif kind == "xor_const":
                x ^= arg
        return x & m

    def split(v):
        out, off = {}, 0
        for i, w in enumerate(words):
            out[f"k_{i}"] = (v >> off) & ((1 << w) - 1)
            off += w
        return out

    def join(d, prefix="y"):
        v, off = 0, 0
        for i, w in enumerate(words):
            v |= d[f"{prefix}_{i}"] << off
            off += w
        return v

    rng = random.Random(index)
    values = [0, m, 1, 1 << (bits - 1)] + [rng.getrandbits(bits)
                                           for _ in range(3)]
    pairs = []
    for v in values:
        want = oracle(v)
        got = join(evaluate(nl, split(v)))
        if got != want:
            return False, (f"evaluator disagrees\n"
                           f"    input    {v:#x}\n"
                           f"    got      {got:#x}\n"
                           f"    expected {want:#x}")
        pairs.append((split(v), {f"y_{i}": (want >> sum(words[:i]))
                                 & ((1 << w) - 1)
                                 for i, w in enumerate(words)}))
    if not cross_check(dig, js, jar, pairs, verbose=False):
        return False, "Digital's simulator disagrees with the evaluator"
    return True, ""


def make_recipe(rng, seed):
    width = rng.choice([8, 16, 32, 64])
    order = rng.choice(["lsb", "msb"])
    depth = rng.randint(1, 5)
    r = Recipe(rng, width, order, depth)

    choices = ["rotl", "rotr", "xor_const", "not", "cut_join"]
    if width % 4 == 0:
        choices += ["sbox", "words_reverse", "xor_slices"]
    if width <= 32:
        choices += ["permute"]

    for _ in range(depth):
        kind = rng.choice(choices)
        if kind in ("rotl", "rotr"):
            r.steps.append((kind, rng.randrange(1, width)))
        elif kind == "sbox":
            cell = rng.choice([c for c in (2, 4) if width % c == 0])
            r.steps.append(("sbox", rand_sbox(rng, cell)))
        elif kind == "xor_const":
            r.steps.append(("xor_const", rng.getrandbits(width)))
        elif kind == "not":
            r.steps.append(("not", None))
        elif kind == "words_reverse":
            w = rng.choice([c for c in (2, 4, 8, 16) if width % c == 0
                            and width // c > 1])
            r.steps.append(("words_reverse", w))
        elif kind == "permute":
            p = list(range(width))
            rng.shuffle(p)
            r.steps.append(("permute", p))
        elif kind == "cut_join":
            lo = rng.randrange(0, width - 1)
            hi = rng.randrange(lo + 1, width + 1)
            r.steps.append(("cut_join", (lo, hi)))
        elif kind == "xor_slices":
            # Needs at least two repetitions: with one, join_bits returns the
            # slice unchanged and the step is x ^ x = 0, which is a valid
            # circuit but a dull test.
            w = rng.choice([c for c in (2, 4, 8)
                            if width % c == 0 and width // c > 1])
            lo = rng.randrange(0, width - w + 1)
            r.steps.append(("xor_slices", (lo, lo + w)))
    return r


def run_case(recipe, jar, bridge, tmp, index, vectors=6):
    from digparts import Builder
    from dig2claasp import Netlist, evaluate, cross_check

    b = Builder(bit_order=recipe.order)
    b.out("y", recipe.build(b))
    dig = os.path.join(tmp, f"fuzz{index}.dig")
    b.write(dig, jar, bridge)

    js = dig.replace(".dig", ".json")
    r = subprocess.run(["java", "-cp", classpath(jar, bridge),
                        "digbridge.DigNetlist", dig, js],
                       capture_output=True, text=True)
    if r.returncode:
        return False, f"netlist extraction failed:\n{r.stderr}"

    nl = Netlist(js)
    rng = random.Random(index)
    values = [0, (1 << recipe.width) - 1, 1, 1 << (recipe.width - 1)]
    values += [rng.getrandbits(recipe.width)
               for _ in range(max(0, vectors - len(values)))]

    pairs = []
    for v in values:
        want = recipe.apply(v)
        got = evaluate(nl, {"x": v})["y"]
        if got != want:
            w = recipe.width
            return False, (f"evaluator disagrees with the recipe\n"
                           f"    input    {v:#0{w // 4 + 2}x}\n"
                           f"    got      {got:#0{w // 4 + 2}x}\n"
                           f"    expected {want:#0{w // 4 + 2}x}")
        pairs.append(({"x": v}, {"y": want}))

    if not cross_check(dig, js, jar, pairs, verbose=False):
        return False, "Digital's simulator disagrees with the evaluator"
    return True, ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--digital-jar", required=True)
    ap.add_argument("--bridge-jar", required=True)
    ap.add_argument("--cases", type=int, default=100)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--wide", action="store_true", default=True,
                    help="include registers wider than one bus")
    ap.add_argument("--no-wide", dest="wide", action="store_false")
    ap.add_argument("--stop-after", type=int, default=5,
                    help="give up after this many distinct failures")
    a = ap.parse_args()

    jar = os.path.abspath(a.digital_jar)
    bridge = os.path.abspath(a.bridge_jar)

    print(f"generating {a.cases} random circuits, seed {a.seed}")
    print("each is run through Digital's simulator and the evaluator, and "
          "checked against a plain-Python model of the same steps")
    print()

    failures, errors = [], []
    with tempfile.TemporaryDirectory() as tmp:
        for i in range(a.cases):
            rng = random.Random(a.seed * 100000 + i)
            wide = a.wide and (i % 3 == 2)
            try:
                if wide:
                    bits, steps = make_wide_recipe(rng, i)
                    ok, why = run_wide_case(bits, steps, jar, bridge, tmp, i)
                    label = f"{bits} bits wide, {len(steps)} steps"
                    src = "\n".join(f"    {k}: {v}" for k, v in steps)
                else:
                    recipe = make_recipe(rng, i)
                    ok, why = run_case(recipe, jar, bridge, tmp, i)
                    label = (f"{recipe.width} bits, {recipe.order}, "
                             f"{len(recipe.steps)} steps")
                    src = recipe.source()
            except Exception:
                ok, why, label, src = False, traceback.format_exc(limit=3), \
                    "exception", ""
            if not ok:
                failures.append((i, label, why))
                print(f"  FAIL case {i}  ({label})")
                print(f"    {why.rstrip()}")
                print(src)
                print()
                if len(failures) >= a.stop_after:
                    print(f"  stopping after {a.stop_after} failures")
                    break
            elif (i + 1) % 25 == 0:
                print(f"  {i + 1}/{a.cases} ok")

    print()
    if failures:
        print(f"{len(failures)} of {a.cases} generated circuits disagree.")
        print("Each block above is a runnable recipe; shrink it by deleting "
              "steps until the disagreement goes away, and the last step "
              "removed is the culprit.")
        return 1
    print(f"all {a.cases} generated circuits agree, across widths "
          f"8/16/32/64" + (" plus 80/96/128/192 wide registers" if a.wide
                           else "") + ", both bit orders")
    return 0


if __name__ == "__main__":
    sys.exit(main())
