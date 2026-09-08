"""LLBC-128-128: draw ONE round, run twenty.

Two circuits are drawn, each exactly once:

    llbc_round.dig    L, R, rk_lo, rk_hi, rc  ->  L', R'
    llbc_keystep.dig  k0, k1, rc              ->  k0', k1'

Both declare their loop by naming: an In "X" paired with an Out "X'" is state
threaded to the next round; an In with no partner is a per-round argument.
The round count is an argument to iterate(), not something drawn.
"""
import subprocess, random, sys
from digbuild import Circuit
from dig2claasp import Netlist, RoundSpec, iterate, find_rotations, cross_check
from javacp import classpath                    # noqa: E402

JAR="../Digital/Digital.jar"; BR="../digbridge.jar"; SP=Circuit.split_pin
S1=[0x4,0x7,0x5,0x1,0xC,0xB,0xD,0x8,0xE,0xF,0x6,0x3,0xA,0x9,0x2,0x0]
S2=[0xE,0xC,0x8,0x4,0xB,0xD,0x1,0x5,0xF,0x3,0xA,0x2,0x9,0x7,0x0,0x6]
B1,B2,RC0=3,19,0x243F6A88
M64=(1<<64)-1

def rol(x,n,w=64): n%=w; return ((x<<n)|(x>>(w-n)))&((1<<w)-1) if n else x
def rc(i):
    k=i%32
    r=((RC0<<k)|(RC0>>(32-k)))&0xFFFFFFFF if k else RC0
    return r<<32
def sub(x,S): return sum(S[(x>>(4*i))&0xF]<<(4*i) for i in range(16))
def mixword(s1o,s2o):
    ML,MR=s2o,s1o
    s=ML^MR; t0=rol(s,B1)^ML; t1=rol(t0,B2)^s
    A=rol(t1,B1)^t0; return A^(rol(A,B2)^t1)
def G(k):
    w=[(k>>(16*(3-i)))&0xFFFF for i in range(4)]
    r0,r1=rol(w[0],3,16),rol(w[1],1,16)
    o=[r0^w[2],r1^w[3],r0,r1]
    return sum(o[i]<<(16*(3-i)) for i in range(4))
def ref_encrypt(P,K,n):
    L,R=(P>>64)&M64,P&M64
    ks=[(K>>64)&M64,K&M64]
    for j in range(n): ks.append(G(G(ks[j+1]))^ks[j]^rc(j))
    for i in range(n):
        lo,hi=ks[i],ks[i+1]
        T=L^hi^rc(i)
        F=mixword(sub(rol(L,B1),S1),sub(rol(T,B2),S2))^lo
        L,R=R^F,T
    return (L<<64)|R

# ---------------- circuit helpers ----------------
class B:
    def __init__(s,c,one=None): s.c,s.one,s.x=c,one,100
    def col(s,w=300): s.x+=w; return s.x
    def xor(s,*srcs,y=200,bits=64):
        g=s.c.add("XOr",x=s.col(),y=y,Bits=bits,Inputs=len(srcs))
        for i,v in enumerate(srcs): s.c.connect(v,(g,f"In_{i+1}"))
        return (g,"out")
    def rot(s,src,amount,y=200,bits=64):
        A,Bs=f"{bits-amount},{amount}",f"{amount},{bits-amount}"
        x=s.col(400)
        a=s.c.add("Splitter",x=x,y=y,**{"Input Splitting":str(bits),"Output Splitting":A})
        b=s.c.add("Splitter",x=x+200,y=y,**{"Input Splitting":Bs,"Output Splitting":str(bits)})
        s.c.connect(src,(a,SP(str(bits),0)))
        s.c.connect((a,SP(A,0)),(b,SP(Bs,1)))
        s.c.connect((a,SP(A,1)),(b,SP(Bs,0)))
        s.col(200); return (b,SP(str(bits),0))
    def subcell(s,src,table,tag,y=200):
        IN,OUT="64","4*16"; x=s.col(400)
        sp=s.c.add("Splitter",x=x,y=y,**{"Input Splitting":IN,"Output Splitting":OUT})
        mg=s.c.add("Splitter",x=x+400,y=y,**{"Input Splitting":OUT,"Output Splitting":IN})
        s.c.connect(src,(sp,SP(IN,0)))
        for i in range(16):
            r=s.c.add("ROM",x=x+200,y=y+i*80,Label=f"{tag}{i}",Bits=4,AddrBits=4,Data=table)
            s.c.connect((sp,SP(OUT,i)),(r,"A")); s.c.connect((s.one,"out"),(r,"sel"))
            s.c.connect((r,"D"),(mg,SP(OUT,i)))
        s.col(400); return (mg,SP(IN,0))

def build_round(path):
    c=Circuit()
    one=c.add("Const",x=100,y=3200,Value=1,Bits=1)
    L =c.add("In",x=100,y=200 ,Label="L"    ,Bits=64)
    R =c.add("In",x=100,y=400 ,Label="R"    ,Bits=64)
    kl=c.add("In",x=100,y=600 ,Label="rk_lo",Bits=64)
    kh=c.add("In",x=100,y=800 ,Label="rk_hi",Bits=64)
    rcv=c.add("In",x=100,y=1000,Label="rc"  ,Bits=64)
    b=B(c,one)
    T  =b.xor((L,"out"),(kh,"out"),(rcv,"out"),y=900)
    s1 =b.subcell(b.rot((L,"out"),B1,y=200),S1,"A",y=200)
    s2 =b.subcell(b.rot(T,B2,y=1700),S2,"B",y=1700)
    s  =b.xor(s2,s1,y=300)
    t0 =b.xor(b.rot(s ,B1,y=400),s2,y=400)
    t1 =b.xor(b.rot(t0,B2,y=500),s ,y=500)
    A  =b.xor(b.rot(t1,B1,y=600),t0,y=600)
    Bv =b.xor(b.rot(A ,B2,y=700),t1,y=700)
    M  =b.xor(A,Bv,y=800)
    Ln =b.xor((R,"out"),M,(kl,"out"),y=1000)
    oL=c.add("Out",x=b.col(600),y=1000,Label="L'",Bits=64)
    oR=c.add("Out",x=b.x       ,y=1100,Label="R'",Bits=64)
    c.connect(Ln,(oL,"in")); c.connect(T,(oR,"in"))
    c.write(path,JAR,BR)

def build_keystep(path):
    """k0' = k1 ; k1' = G(G(k1)) xor k0 xor rc"""
    c=Circuit()
    k0=c.add("In",x=100,y=200,Label="k0",Bits=64)
    k1=c.add("In",x=100,y=400,Label="k1",Bits=64)
    rcv=c.add("In",x=100,y=600,Label="rc",Bits=64)
    b=B(c)
    def g(src,y):
        """G: four 16-bit words w0..w3 (w0 = most significant)."""
        IN,OUT="64","16*4"; x=b.col(400)
        sp=c.add("Splitter",x=x,y=y,**{"Input Splitting":IN,"Output Splitting":OUT})
        c.connect(src,(sp,SP(IN,0)))
        # port i covers bits 16i..16i+15; CLAASP/Digital bit 0 is the LSB of
        # the bundle, so word index counts from the low end: port 3 is w0.
        w=[(sp,SP(OUT,3-i)) for i in range(4)]
        r0=b.rot(w[0],3,y=y+100,bits=16)
        r1=b.rot(w[1],1,y=y+200,bits=16)
        o0=b.xor(r0,w[2],y=y+300,bits=16)
        o1=b.xor(r1,w[3],y=y+400,bits=16)
        x2=b.col(400)
        mg=c.add("Splitter",x=x2,y=y,**{"Input Splitting":OUT,"Output Splitting":IN})
        for i,src_i in enumerate([o0,o1,r0,r1]):
            c.connect(src_i,(mg,SP(OUT,3-i)))
        b.col(400)
        return (mg,SP(IN,0))
    g2=g(g((k1,"out"),200),1000)
    n1=b.xor(g2,(k0,"out"),(rcv,"out"),y=1800)
    o0=c.add("Out",x=b.col(600),y=200 ,Label="k0'",Bits=64)
    o1=c.add("Out",x=b.x       ,y=1800,Label="k1'",Bits=64)
    c.connect((k1,"out"),(o0,"in")); c.connect(n1,(o1,"in"))
    c.write(path,JAR,BR)

def netlist(dig):
    j=dig.replace('.dig','.json')
    r=subprocess.run(["java","-cp",classpath(JAR,BR),"digbridge.DigNetlist",dig,j],
                     capture_output=True,text=True)
    if r.returncode: print(r.stderr); sys.exit(1)
    return Netlist(j), j

if __name__=="__main__":
    build_round("llbc_round1.dig"); build_keystep("llbc_keystep.dig")
    nr,jr=netlist("llbc_round1.dig"); nk,jk=netlist("llbc_keystep.dig")
    sr,sk=RoundSpec(nr),RoundSpec(nk)
    print("round  :",sr)
    print("keystep:",sk)
    print(f"  round   {len(nr.components)} components, {len(nr.nets)} nets, "
          f"rotations {sorted(v[1] for v in find_rotations(nr).values())}")
    print(f"  keystep {len(nk.components)} components, {len(nk.nets)} nets, "
          f"rotations {sorted(v[1] for v in find_rotations(nk).values())}")
    print()

    def encrypt(P,K,rounds):
        ks=iterate(nk,rounds,{"k0":(K>>64)&M64,"k1":K&M64},
                   params=lambda i:{"rc":rc(i)},spec=sk)
        # re-run to collect every intermediate key, not just the last
        keys=[((K>>64)&M64,K&M64)]
        st={"k0":keys[0][0],"k1":keys[0][1]}
        for i in range(rounds):
            st=iterate(nk,1,st,params=lambda _ ,i=i:{"rc":rc(i)},spec=sk)
            keys.append((st["k0"],st["k1"]))
        state={"L":(P>>64)&M64,"R":P&M64}
        def params(i): return {"rk_lo":keys[i][0],"rk_hi":keys[i][1],"rc":rc(i)}
        out=iterate(nr,rounds,state,params=params,spec=sr)
        return (out["L"]<<64)|out["R"]

    print("=== 1ラウンド回路を N 回まわす vs 検証済み参照実装 ===")
    random.seed(21); bad=0
    for n in (1,2,3,5,10,20):
        for _ in range(3):
            P,K=random.getrandbits(128),random.getrandbits(128)
            got,want=encrypt(P,K,n),ref_encrypt(P,K,n)
            if got!=want:
                bad+=1
                print(f"  {n:2d}ラウンド MISMATCH  got 0x{got:032x} want 0x{want:032x}")
        print(f"  {n:2d}ラウンド: {'OK' if bad==0 else 'FAIL'}")
    print()
    print("結果:", "全一致" if bad==0 else f"{bad}件不一致")
