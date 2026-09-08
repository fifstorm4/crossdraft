"""Build one LLBC-128-128 round in Digital and cross-check it.

Round function, with the R_i that Algorithm 1 of the LLBC paper omits but
Fig. 2 shows:

    T      = L xor RK_hi xor RC
    L_next = R xor MixWord(SubCell1(L <<< 3), SubCell2(T <<< 19)) xor RK_lo
    R_next = T

MixWord takes SubCell2's output as its M_L port, per the geometry of Fig. 1
and Fig. 2; the opposite assignment makes the published characteristics
unrealisable.
"""
import subprocess, random, sys
from digbuild import Circuit
from dig2claasp import Netlist, find_rotations, cross_check
from javacp import classpath                    # noqa: E402

JAR = "../Digital/Digital.jar"; BR = "../digbridge.jar"; SP = Circuit.split_pin
S1 = [0x4,0x7,0x5,0x1,0xC,0xB,0xD,0x8,0xE,0xF,0x6,0x3,0xA,0x9,0x2,0x0]
S2 = [0xE,0xC,0x8,0x4,0xB,0xD,0x1,0x5,0xF,0x3,0xA,0x2,0x9,0x7,0x0,0x6]
B1, B2, RC0 = 3, 19, 0x243F6A88
M64 = (1 << 64) - 1

def rol(x, n): n %= 64; return ((x << n) | (x >> (64 - n))) & M64 if n else x
def sub(x, S): return sum(S[(x >> (4*i)) & 0xF] << (4*i) for i in range(16))
def mixword(s1o, s2o):
    ML, MR = s2o, s1o
    s = ML ^ MR; t0 = rol(s, B1) ^ ML; t1 = rol(t0, B2) ^ s
    A = rol(t1, B1) ^ t0
    return A ^ (rol(A, B2) ^ t1)
def ref_round(L, R, rk_lo, rk_hi, rc):
    T = L ^ rk_hi ^ rc
    F = mixword(sub(rol(L, B1), S1), sub(rol(T, B2), S2)) ^ rk_lo
    return R ^ F, T

class B:
    def __init__(self, c, one): self.c, self.one, self.x = c, one, 100
    def col(self, w=300): self.x += w; return self.x
    def xor(self, *srcs, y=200):
        g = self.c.add("XOr", x=self.col(), y=y, Bits=64, Inputs=len(srcs))
        for i, s in enumerate(srcs): self.c.connect(s, (g, f"In_{i+1}"))
        return (g, "out")
    def rot(self, src, amount, y=200):
        A, Bs = f"{64-amount},{amount}", f"{amount},{64-amount}"
        x = self.col()
        a = self.c.add("Splitter", x=x, y=y, **{"Input Splitting":"64","Output Splitting":A})
        b = self.c.add("Splitter", x=x+200, y=y, **{"Input Splitting":Bs,"Output Splitting":"64"})
        self.c.connect(src, (a, SP("64",0)))
        self.c.connect((a, SP(A,0)), (b, SP(Bs,1)))
        self.c.connect((a, SP(A,1)), (b, SP(Bs,0)))
        self.col(200)
        return (b, SP("64",0))
    def subcell(self, src, table, tag, y=200):
        IN, OUT = "64", "4*16"; x = self.col()
        sp = self.c.add("Splitter", x=x, y=y, **{"Input Splitting":IN,"Output Splitting":OUT})
        mg = self.c.add("Splitter", x=x+400, y=y, **{"Input Splitting":OUT,"Output Splitting":IN})
        self.c.connect(src, (sp, SP(IN,0)))
        for i in range(16):
            r = self.c.add("ROM", x=x+200, y=y+i*80, Label=f"{tag}{i}",
                           Bits=4, AddrBits=4, Data=table)
            self.c.connect((sp, SP(OUT,i)), (r, "A"))
            self.c.connect((self.one, "out"), (r, "sel"))
            self.c.connect((r, "D"), (mg, SP(OUT,i)))
        self.col(400)
        return (mg, SP(IN,0))

def build(path, rc):
    c = Circuit()
    one = c.add("Const", x=100, y=3000, Value=1, Bits=1)
    L  = c.add("In",  x=100, y=200,  Label="L",     Bits=64)
    R  = c.add("In",  x=100, y=400,  Label="R",     Bits=64)
    kl = c.add("In",  x=100, y=600,  Label="rk_lo", Bits=64)
    kh = c.add("In",  x=100, y=800,  Label="rk_hi", Bits=64)
    rcc = c.add("Const", x=100, y=1000, Value=rc, Bits=64)
    b = B(c, one)
    T   = b.xor((L,"out"), (kh,"out"), (rcc,"out"), y=800)
    s1  = b.subcell(b.rot((L,"out"), B1, y=200), S1, "A", y=200)
    s2  = b.subcell(b.rot(T,        B2, y=1500), S2, "B", y=1500)
    s   = b.xor(s2, s1, y=300)
    t0  = b.xor(b.rot(s,  B1, y=400), s2, y=400)
    t1  = b.xor(b.rot(t0, B2, y=500), s,  y=500)
    A   = b.xor(b.rot(t1, B1, y=600), t0, y=600)
    Bv  = b.xor(b.rot(A,  B2, y=700), t1, y=700)
    M   = b.xor(A, Bv, y=800)
    Ln  = b.xor((R,"out"), M, (kl,"out"), y=900)
    oL = c.add("Out", x=b.col(600), y=900,  Label="Lnext", Bits=64)
    oR = c.add("Out", x=b.x,        y=1000, Label="Rnext", Bits=64)
    c.connect(Ln, (oL,"in")); c.connect(T, (oR,"in"))
    c.write(path, JAR, BR)

if __name__ == "__main__":
    rc = RC0 << 32
    build("llbc_round.dig", rc)
    j = "llbc_round.json"
    r = subprocess.run(["java","-cp",classpath(JAR,BR),"digbridge.DigNetlist","llbc_round.dig",j],
                       capture_output=True, text=True)
    if r.returncode: print(r.stderr); sys.exit(1)
    nl = Netlist(j)
    print(f"コンポーネント {len(nl.components)}個, ネット {len(nl.nets)}本")
    rots = find_rotations(nl)
    print(f"回転検出 {len(rots)}個: {sorted(v[1] for v in rots.values())}  (期待 [3,3,3,19,19,19])")
    random.seed(7)
    vecs = []
    for _ in range(8):
        L, R, kl, kh = (random.getrandbits(64) for _ in range(4))
        Ln, Rn = ref_round(L, R, kl, kh, rc)
        vecs.append(({"L":L,"R":R,"rk_lo":kl,"rk_hi":kh},
                     {"Lnext":Ln,"Rnext":Rn}))
    print("=== LLBC 1ラウンド 相互検証 ===")
    cross_check("llbc_round.dig", j, JAR, vecs)
