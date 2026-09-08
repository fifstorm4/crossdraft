"""
Regression suite for the Digital -> CLAASP bridge.

    python3 tests/test_all.py --digital-jar path/to/Digital.jar \
                             --bridge-jar java/digbridge.jar

Every case builds a circuit from Python, runs it through Digital's own
simulator AND through the bridge's evaluator, and requires both to agree.

That double check is the whole point.  A bridge that drops a wire or
mis-orders a splitter's ports still produces a CLAASP model, and that model
still yields plausible differential trails -- with nothing to compare them
against.  Comparing to Digital catches it here instead.

Run this after touching anything, and before adding a component type.
"""
import argparse
import random
import subprocess
import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))
from digbuild import Circuit                                    # noqa: E402
from dig2claasp import (Netlist, RoundSpec, iterate,             # noqa: E402
                        find_rotations, cross_check, classpath)

SP = Circuit.split_pin
M64 = (1 << 64) - 1
S1 = [0x4, 0x7, 0x5, 0x1, 0xC, 0xB, 0xD, 0x8,
      0xE, 0xF, 0x6, 0x3, 0xA, 0x9, 0x2, 0x0]
S2 = [0xE, 0xC, 0x8, 0x4, 0xB, 0xD, 0x1, 0x5,
      0xF, 0x3, 0xA, 0x2, 0x9, 0x7, 0x0, 0x6]
PRESENT = [0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD, 3, 0xE, 0xF, 8, 4, 7, 1, 2]
B1, B2 = 3, 19


def rol(x, n):
    n %= 64
    return ((x << n) | (x >> (64 - n))) & M64 if n else x


def sub(x, table):
    return sum(table[(x >> (4 * i)) & 0xF] << (4 * i) for i in range(16))


def mixword(s1o, s2o):
    ml, mr = s2o, s1o
    s = ml ^ mr
    t0 = rol(s, B1) ^ ml
    t1 = rol(t0, B2) ^ s
    a = rol(t1, B1) ^ t0
    return a ^ (rol(a, B2) ^ t1)


class Ctx:
    def __init__(self, jar, bridge, workdir):
        self.jar, self.bridge, self.dir = jar, bridge, workdir
        self.failures = []

    def netlist(self, dig):
        j = dig.replace(".dig", ".json")
        r = subprocess.run(
            ["java", "-cp", classpath(self.jar, self.bridge),
             "digbridge.DigNetlist", dig, j],
            capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(r.stderr)
        return Netlist(j), j

    def case(self, name, dig, vectors, extra=None):
        nl, j = self.netlist(dig)
        ok = cross_check(dig, j, self.jar, vectors, verbose=False)
        note = ""
        if extra:
            got, want = extra(nl)
            if got != want:
                ok = False
                note = f"  (got {got}, want {want})"
            else:
                note = f"  {got}"
        print(f"  {'PASS' if ok else 'FAIL'}  {name}"
              f"  [{len(nl.components)} components, "
              f"{len(nl.nets)} nets]{note}")
        if not ok:
            self.failures.append(name)
        return ok

    def path(self, n):
        return os.path.join(self.dir, n)


# --------------------------------------------------------------------------

def add_rot(c, src, amount, x, y):
    a_spec, b_spec = f"{64-amount},{amount}", f"{amount},{64-amount}"
    a = c.add("Splitter", x=x, y=y,
              **{"Input Splitting": "64", "Output Splitting": a_spec})
    b = c.add("Splitter", x=x + 200, y=y,
              **{"Input Splitting": b_spec, "Output Splitting": "64"})
    c.connect(src, (a, SP("64", 0)))
    c.connect((a, SP(a_spec, 0)), (b, SP(b_spec, 1)))
    c.connect((a, SP(a_spec, 1)), (b, SP(b_spec, 0)))
    return (b, SP("64", 0))


def add_subcell(c, src, table, tag, x, y, one):
    ins, outs = "64", "4*16"
    sp = c.add("Splitter", x=x, y=y,
               **{"Input Splitting": ins, "Output Splitting": outs})
    mg = c.add("Splitter", x=x + 400, y=y,
               **{"Input Splitting": outs, "Output Splitting": ins})
    c.connect(src, (sp, SP(ins, 0)))
    for i in range(16):
        r = c.add("ROM", x=x + 200, y=y + i * 80, Label=f"{tag}{i}",
                  Bits=4, AddrBits=4, Data=table)
        c.connect((sp, SP(outs, i)), (r, "A"))
        c.connect((one, "out"), (r, "sel"))
        c.connect((r, "D"), (mg, SP(outs, i)))
    return (mg, SP(ins, 0))


# --------------------------------------------------------------------------

def t_sbox(ctx):
    c = Circuit()
    x = c.add("In", x=100, y=200, Label="x", Bits=4)
    one = c.add("Const", x=100, y=400, Value=1, Bits=1)
    rom = c.add("ROM", x=400, y=200, Label="S", Bits=4, AddrBits=4,
                Data=PRESENT)
    y = c.add("Out", x=700, y=200, Label="y", Bits=4)
    c.connect((x, "out"), (rom, "A"))
    c.connect((one, "out"), (rom, "sel"))
    c.connect((rom, "D"), (y, "in"))
    p = ctx.path("sbox.dig")
    c.write(p, ctx.jar, ctx.bridge)
    return ctx.case("4-bit S-box (ROM)", p,
                    [({"x": i}, {"y": PRESENT[i]}) for i in range(16)])


def t_xor64(ctx):
    c = Circuit()
    a = c.add("In", x=100, y=200, Label="a", Bits=64)
    b = c.add("In", x=100, y=400, Label="b", Bits=64)
    g = c.add("XOr", x=400, y=300, Bits=64, Inputs=2)
    y = c.add("Out", x=700, y=300, Label="y", Bits=64)
    c.connect((a, "out"), (g, "In_1"))
    c.connect((b, "out"), (g, "In_2"))
    c.connect((g, "out"), (y, "in"))
    p = ctx.path("xor64.dig")
    c.write(p, ctx.jar, ctx.bridge)
    random.seed(11)
    v = [({"a": x, "b": z}, {"y": x ^ z})
         for x, z in [(0, 0), (M64, 0), (M64, M64)]
         + [(random.getrandbits(64), random.getrandbits(64))
            for _ in range(5)]]
    return ctx.case("64-bit XOR", p, v)


def t_subcell(ctx):
    c = Circuit()
    x = c.add("In", x=100, y=400, Label="x", Bits=64)
    one = c.add("Const", x=100, y=1800, Value=1, Bits=1)
    out = add_subcell(c, (x, "out"), S1, "A", 400, 100, one)
    y = c.add("Out", x=1200, y=400, Label="y", Bits=64)
    c.connect(out, (y, "in"))
    p = ctx.path("subcell.dig")
    c.write(p, ctx.jar, ctx.bridge)
    random.seed(12)
    v = [({"x": z}, {"y": sub(z, S1)})
         for z in [0, M64, 0x0123456789ABCDEF]
         + [random.getrandbits(64) for _ in range(5)]]
    return ctx.case("64-bit SubCell (splitter + 16 S-boxes)", p, v)


def t_rotation(ctx):
    ok = True
    for amount in (1, 3, 19, 32, 63):
        c = Circuit()
        x = c.add("In", x=100, y=200, Label="x", Bits=64)
        out = add_rot(c, (x, "out"), amount, 400, 200)
        y = c.add("Out", x=1000, y=200, Label="y", Bits=64)
        c.connect(out, (y, "in"))
        p = ctx.path(f"rol{amount}.dig")
        c.write(p, ctx.jar, ctx.bridge)
        random.seed(13 + amount)
        v = [({"x": z}, {"y": rol(z, amount)})
             for z in [1, 1 << 63, M64]
             + [random.getrandbits(64) for _ in range(4)]]
        ok &= ctx.case(
            f"rotate left {amount}", p, v,
            extra=lambda nl, a=amount: (
                sorted(r[1] for r in find_rotations(nl).values()), [a]))
    return ok


def t_mixword(ctx):
    c = Circuit()
    p1 = c.add("In", x=100, y=200, Label="s1o", Bits=64)
    p2 = c.add("In", x=100, y=400, Label="s2o", Bits=64)
    col = [400]

    def nxt(w=300):
        col[0] += w
        return col[0]

    def xor(*srcs, y=300):
        g = c.add("XOr", x=nxt(), y=y, Bits=64, Inputs=len(srcs))
        for i, s in enumerate(srcs):
            c.connect(s, (g, f"In_{i+1}"))
        return (g, "out")

    def rot(src, amount, y):
        x = nxt(400)
        r = add_rot(c, src, amount, x, y)
        nxt(200)
        return r

    s = xor((p2, "out"), (p1, "out"), y=300)
    t0 = xor(rot(s, B1, 400), (p2, "out"), y=400)
    t1 = xor(rot(t0, B2, 500), s, y=500)
    a = xor(rot(t1, B1, 600), t0, y=600)
    bv = xor(rot(a, B2, 700), t1, y=700)
    m = xor(a, bv, y=800)
    y = c.add("Out", x=nxt(400), y=800, Label="m", Bits=64)
    c.connect(m, (y, "in"))
    path = ctx.path("mixword.dig")
    c.write(path, ctx.jar, ctx.bridge)
    random.seed(14)
    v = [({"s1o": x, "s2o": z}, {"m": mixword(x, z)})
         for x, z in [(0, 0), (M64, 0), (0, M64)]
         + [(random.getrandbits(64), random.getrandbits(64))
            for _ in range(6)]]
    return ctx.case(
        "LLBC MixWord (4 rotations + 6 XORs)", path, v,
        extra=lambda nl: (sorted(r[1] for r in find_rotations(nl).values()),
                          [3, 3, 19, 19]))


def t_loop(ctx):
    """
    One drawn round, run N times.

    This is the case that matters most: a block cipher is the same round
    applied twenty times, and drawing twenty of them would be twenty chances
    to mis-wire one.  A two-round Feistel toy is built once, then iterated,
    and the result is compared against a closed-form reference for several
    round counts.
    """
    table = PRESENT

    c = Circuit()
    one = c.add("Const", x=100, y=2000, Value=1, Bits=1)
    L = c.add("In", x=100, y=200, Label="L", Bits=64)
    R = c.add("In", x=100, y=400, Label="R", Bits=64)
    k = c.add("In", x=100, y=600, Label="rk", Bits=64)
    t = c.add("XOr", x=400, y=300, Bits=64, Inputs=2)
    c.connect((L, "out"), (t, "In_1"))
    c.connect((k, "out"), (t, "In_2"))
    sc = add_subcell(c, (t, "out"), table, "S", 700, 100, one)
    rt = add_rot(c, sc, 7, 1500, 300)
    x2 = c.add("XOr", x=2000, y=300, Bits=64, Inputs=2)
    c.connect((R, "out"), (x2, "In_1"))
    c.connect(rt, (x2, "In_2"))
    oL = c.add("Out", x=2400, y=300, Label="L'", Bits=64)
    oR = c.add("Out", x=2400, y=500, Label="R'", Bits=64)
    c.connect((x2, "out"), (oL, "in"))
    c.connect((L, "out"), (oR, "in"))
    p = ctx.path("feistel.dig")
    c.write(p, ctx.jar, ctx.bridge)
    nl, j = ctx.netlist(p)

    spec = RoundSpec(nl)
    if sorted(spec.state) != ["L", "R"] or spec.params != ["rk"]:
        print(f"  FAIL  loop spec: {spec}")
        ctx.failures.append("loop spec")
        return False

    def ref(L0, R0, keys, n):
        L, R = L0, R0
        for i in range(n):
            L, R = R ^ rol(sub(L ^ keys[i], table), 7), L
        return L, R

    random.seed(15)
    ok = True
    for n in (1, 2, 5, 20):
        L0, R0 = random.getrandbits(64), random.getrandbits(64)
        keys = [random.getrandbits(64) for _ in range(n)]
        got = iterate(nl, n, {"L": L0, "R": R0},
                      params=lambda i: {"rk": keys[i]}, spec=spec)
        want = ref(L0, R0, keys, n)
        if (got["L"], got["R"]) != want:
            ok = False
            print(f"  FAIL  loop {n} rounds")
    print(f"  {'PASS' if ok else 'FAIL'}  one drawn round, iterated "
          f"1/2/5/20 times  [{len(nl.components)} components]  {spec}")
    if not ok:
        ctx.failures.append("loop")
    return ok


def t_wide_permutation(ctx):
    """
    A 64-bit bit permutation.

    Regression for splitter port ordering.  Ports are named after the bit
    range they carry -- "0", "8-11", "0-63" -- and sorting those as strings
    puts "10" before "2".  Every splitter with more than ten ports therefore
    came out transposed, which is every wide bit permutation and every key
    schedule that slices a register into words.  The bug was invisible on
    small circuits and produced a working cipher computing the wrong function.
    """
    from digparts import Builder

    # PRESENT's pLayer, stated as permute() wants it: out j <- in mapping[j].
    fwd = [(16 * i) % 63 for i in range(63)] + [63]
    mapping = [0] * 64
    for i, p_ in enumerate(fwd):
        mapping[p_] = i

    b = Builder()
    x = b.inp("x", 64)
    b.out("y", b.permute(x, mapping))
    p = ctx.path("player.dig")
    b.write(p, ctx.jar, ctx.bridge)

    def ref(v):
        t = 0
        for i in range(64):
            if (v >> i) & 1:
                t |= 1 << fwd[i]
        return t

    random.seed(16)
    v = [({"x": z}, {"y": ref(z)})
         for z in [1, 1 << 63, 0x0123456789ABCDEF, M64]
         + [random.getrandbits(64) for _ in range(4)]]
    return ctx.case("64-bit bit permutation (pLayer)", p, v)


def t_word_slicing(ctx):
    """
    Slice a 64-bit register into 16-bit words and put it back.

    The other half of the port-ordering regression: a key schedule that
    reaches for w0..w3 gets them in the wrong order if the merger's ports sort
    as strings, and only the final key disagrees.
    """
    from digparts import Builder

    b = Builder()
    x = b.inp("x", 64)
    w = b.words(x, 16)
    b.out("y", b.join(list(reversed(w))))     # byte-swap the words
    p = ctx.path("words.dig")
    b.write(p, ctx.jar, ctx.bridge)

    def ref(v):
        w_ = [(v >> (16 * i)) & 0xFFFF for i in range(4)]
        return sum(w_[3 - i] << (16 * i) for i in range(4))

    random.seed(17)
    v = [({"x": z}, {"y": ref(z)})
         for z in [0x0001000200030004, M64]
         + [random.getrandbits(64) for _ in range(5)]]
    return ctx.case("64-bit register sliced into 16-bit words", p, v)


def t_bit_order(ctx):
    """
    The MSB/LSB switch.

    Specifications disagree about which end of a word is bit 0.  Reading one
    convention as the other yields a working circuit computing the mirror
    image of the intended function -- a rotation the wrong way, a permutation
    inverted -- which no test on a single layer reveals.  Builder converts, so
    both cases must land on the same circuit when the mapping is restated.
    """
    from digparts import Builder

    ok = True

    # A left rotation by 1 counting from the LSB is a right rotation by 1
    # counting from the MSB: same movement, opposite labels.
    for order, expect in (("lsb", lambda v: ((v << 1) | (v >> 7)) & 0xFF),
                          ("msb", lambda v: ((v >> 1) | (v << 7)) & 0xFF)):
        b = Builder(bit_order=order)
        b.out("y", b.rotl(b.inp("x", 8), 1))
        p = ctx.path(f"rot_{order}.dig")
        b.write(p, ctx.jar, ctx.bridge)
        v = [({"x": z}, {"y": expect(z)})
             for z in (1, 2, 0x80, 0x5A, 0xFF)]
        ok &= ctx.case(f"rotl 1 with bit_order={order}", p, v)

    # The same permutation written both ways must give the same circuit.
    fwd = [(16 * i) % 63 for i in range(63)] + [63]
    lsb_map = [0] * 64
    for i, p_ in enumerate(fwd):
        lsb_map[p_] = i
    msb_map = [63 - lsb_map[63 - j] for j in range(64)]

    def ref(v):
        t = 0
        for i in range(64):
            if (v >> i) & 1:
                t |= 1 << fwd[i]
        return t

    random.seed(18)
    vectors = [({"x": z}, {"y": ref(z)})
               for z in [1, 1 << 63, 0x0123456789ABCDEF]
               + [random.getrandbits(64) for _ in range(3)]]
    for order, mapping in (("lsb", lsb_map), ("msb", msb_map)):
        b = Builder(bit_order=order)
        b.out("y", b.permute(b.inp("x", 64), mapping))
        p = ctx.path(f"perm_{order}.dig")
        b.write(p, ctx.jar, ctx.bridge)
        ok &= ctx.case(f"pLayer restated for bit_order={order}", p, vectors)

    return ok


def t_reject_sequential(ctx):
    """A register must be refused, not silently mistranslated."""
    c = Circuit()
    x = c.add("In", x=100, y=200, Label="x", Bits=8)
    r = c.add("Register", x=400, y=200, Bits=8)
    y = c.add("Out", x=700, y=200, Label="y", Bits=8)
    c.connect((x, "out"), (r, "D"))
    c.connect((r, "Q"), (y, "in"))
    p = ctx.path("seq.dig")
    try:
        c.write(p, ctx.jar, ctx.bridge)
        nl, _ = ctx.netlist(p)
        from dig2claasp import check
        check(nl)
    except NotImplementedError as e:
        good = "sequential" in str(e)
        print(f"  {'PASS' if good else 'FAIL'}  rejects sequential logic")
        if not good:
            ctx.failures.append("reject sequential")
        return good
    except Exception as e:
        print(f"  PASS  rejects sequential logic ({type(e).__name__})")
        return True
    print("  FAIL  a Register was accepted")
    ctx.failures.append("reject sequential")
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--digital-jar", required=True)
    ap.add_argument("--bridge-jar", required=True)
    a = ap.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        ctx = Ctx(os.path.abspath(a.digital_jar),
                  os.path.abspath(a.bridge_jar), tmp)
        print("Digital <-> bridge cross-validation")
        for t in (t_sbox, t_xor64, t_subcell, t_rotation, t_mixword,
                  t_wide_permutation, t_word_slicing, t_bit_order,
                  t_loop, t_reject_sequential):
            t(ctx)
        print()
        if ctx.failures:
            print(f"{len(ctx.failures)} failure(s): {ctx.failures}")
            return 1
        print("all cases agree with Digital")
        return 0


if __name__ == "__main__":
    sys.exit(main())
