# CrossDraft

**Draw a cipher once. Check it twice.**

Draw a block cipher in [Digital](https://github.com/hneemann/Digital), a free
schematic-capture logic simulator, and hand the same circuit to
[CLAASP](https://github.com/Crypto-TII/claasp) for differential cryptanalysis.

```sh
python3 diggui.py                              # browser GUI on :8765
```

or from the terminal:

```sh
python3 digcli.py build     present              # draw circuits, extract netlists
python3 digcli.py build     present --with-tests # ...and make F8 work in Digital
python3 digcli.py verify    present              # circuit vs reference vs vectors
python3 digcli.py analyse   present --rounds 3   # emit CLAASP, search for trails

python3 digcli.py selftest                       # does this install reproduce?
python3 digcli.py env       present              # for a methodology section
python3 digcli.py replicate present --trail published.csv --expect-weight 81
```

The circuit is drawn **once**. Digital checks it against the paper's test
vectors; CLAASP searches it for differential trails. Neither side is
transcribed by hand, so neither can quietly disagree with the other.

---

## Opening the circuit in Digital

`build` writes `.dig` files into `build/<cipher>/` in the working directory,
and they open in Digital like any other schematic. That is the point of
producing them: the thing handed to CLAASP is a drawing somebody can read.

Add `--with-tests` and Digital's own **F8** works on the generated circuit:

```sh
python3 digcli.py build present --with-tests
```

The expected values come from evaluating the circuit itself, not from the
cipher's reference implementation. That sounds circular and is not — the
evaluator reads the netlist and applies each component's semantics in Python,
while Digital simulates the same drawing with its own engine. A disagreement
means the two read the same circuit differently, which is the class of bug
this project exists to catch, and F8 catches it on the drawing in front of
you. Whether the circuit computes the *cipher* is a separate question, and
the one `verify` answers.

Signals are drawn as wires. Digital joins two of them only where an **end
point** is shared: crossings stay independent, so do overlapping collinear
runs, and so does an endpoint landing partway along another wire. That
narrow rule is what makes routing tractable — paths may cross freely, and the
only things to avoid are two nets sharing a corner and a corner landing on a
pin. Each net gets a vertical channel of its own, chosen from an x nobody
else occupies.

`Circuit.write(..., wires=False)` falls back on named tunnels, which cannot
short against anything. It is there as somewhere to retreat to if a drawn
circuit ever comes out wrong.

---

## Three commands that exist for papers, not for convenience

### `selftest` — is this installation sound?

```sh
python3 digcli.py selftest              # ~4 min
python3 digcli.py selftest --level quick   # ~80 s, for a pre-commit hook
python3 digcli.py selftest --level full    # adds NIST and the analysis extras
```

Runs the suites and says plainly whether this machine reproduces the
reference results. That matters because the checks compare against Digital's
own simulator and against CLAASP's own PRESENT — so a pass is evidence about
**your** install, not about the author's.

```
  PASS  cross-validation against Digital  [79s]
  PASS  PRESENT against CLAASP's own model  [4s]
  PASS  randomised circuits  [144s]

  3/3 suites passed in 227s
  This installation reproduces the reference results.
```

### `env` — what was run, on what, against which circuit

```
CrossDraft 0.1.0

environment
  Digital     present     java     21.0.12      CLAASP     3.0.0
  kissat      4.0.4       espresso present      NIST STS   2.1.2
  passagemath 10.8.11     numpy    2.4.4        host       x86_64 Linux

circuits analysed
  present_round.json    sha256:81754110f9db0f7b…  244 components, 102 nets
  present_keystep.json  sha256:0187eed6f595c83e…   59 components,  17 nets
```

Versions alone do not make a result reproducible. Two people running
identical CLAASP and identical Kissat on circuits that differ by one wire
will disagree, and no version string says so. The digests are what make the
claim checkable. `--latex` writes the table straight into a paper.

### `replicate` — check somebody else's published trail

```sh
python3 digcli.py replicate llbc --trail table6.csv --expect-weight 81
```

This is the case the whole toolchain is shaped around. A paper reports a
characteristic as a table of round differences and a probability; the search
that produced it ran in the authors' own model, which nobody else has.

Copy the table into a CSV — a `round` column and one `delta_*` column per
state variable, in hex — and this asks a *different* model, built from a
schematic, whether the same path is realisable and costs the same.

```
  REPLICATED: weight 8.0 (probability 2^-8.0)
  published weight 8.0 -> MATCH
```

`--pin-all` pins every intermediate round, not just the endpoints. That
distinction matters: without it the solver is free to reach the published
output difference by its own route, so a match says the endpoints are joinable
at that weight, not that the published path is. With it, the table itself is
what gets checked.

`--show` prints the round-by-round breakdown, and `--export` writes it as a
figure or a LaTeX table:

```
  R   weight  active  state
  0      8.0       4  00000000000000001800010000000000
  1      0.0       0  18000100000000000000000000000000
  2      9.0       4  37e00954017800041800010000000000
  3     47.0      18  180001000000000037e0095401780004
  4      9.0       4  00000000000000001800010000000000
  5      0.0       0  18000100000000000000000000000000
  6      8.0       4  ba60027201ce00121800010000000000

  active S-boxes: 34
```

Agreement is real corroboration: nothing was shared but the numbers in the
paper. Disagreement localises itself — the round where the solver first
refuses is the round to look at.

Hand-built models are how this field works and there is nothing wrong with
that. What has been missing is a second opinion that costs an afternoon
rather than a month.

---

## The GUI

```sh
./run.ps1 gui        # or ./run.sh gui
```

serves a page on `127.0.0.1:8765`. The launcher publishes the port and
changes the entrypoint; `run.ps1 gui` is the whole command.

Four tabs, because the CLI is already complete and what a browser adds is
different: seeing what is possible without reading `--help`, changing a round
count and running again, and reading a trail as a table rather than as a wall
of log.

| tab | what it does |
|---|---|
| **Pipeline** | build, verify, analyse — each greyed out until the one before it is green |
| **Replicate** | pick a trail CSV, pin every round, check a published characteristic |
| **S-boxes** | DDT, LAT and the maximum differential probability |
| **Cost** | gate estimate under a stated model, and the published figures beside it |

The trail table is parsed out of the command's own output rather than
recomputed, so the numbers on screen and the numbers in a paper cannot drift
apart. Export buttons write the same files the CLI writes — but anything
meant for a paper should still go through the command line, where the command
is the record of what was done. Digital is already the
schematic editor, so this is not another one — it covers the part that
otherwise lives in a terminal: pick a cipher, run the three stages, see which
have passed.

Each stage stays greyed out until the one before it is green, because the
order carries the argument: published vectors pin down the reference, the
reference pins down the circuit, the circuit pins down the CLAASP model.

Stages run as subprocesses. Sage and the SAT solvers install signal handlers
and Python only allows that from the main thread, so calling them in a request
handler dies with *"signal only works in main thread"*; running out of process
also means a solver that runs away cannot take the server with it.

The server binds `0.0.0.0`, not loopback. Inside a container 127.0.0.1 is the
container's own loopback and nothing outside reaches it -- `-p 8765:8765`
forwards to the container's external interface, finds nobody listening, and
the browser reports the page as simply not working with nothing anywhere to
explain why. Set `DIGGUI_HOST=127.0.0.1` to keep it to the local machine when
running outside a container.

Single file, standard library only, no build step.

---

## Registers wider than one bus

Digital's wires top out at 64 bits. Key registers do not: PRESENT-80 rotates
an 80-bit register by 61, SKINNY carries a 384-bit tweakey, a 256-bit key is
ordinary. `Wide` keeps the words together and the helpers do the arithmetic,
so the word boundary never reaches the cipher's source:

```python
k = b.wide_in("k", 80)                       # two ports, k_0 and k_1
b.out("rk", b.wide_slice(k, 16, 80))         # the leading 64 bits
k = b.wide_rotl(k, 61)                       # crosses the boundary
top = b.sbox_layer(b.wide_slice(k, 76, 80), PRESENT_SBOX)
k = b.wide_splice(k, 76, top)
k = b.wide_xor(k, rc)
b.wide_out("k'", k)                          # k_0' and k_1'
```

That is PRESENT-80's whole key schedule, drawn as a circuit. The loop
convention is unchanged: `k_0` pairs with `k_0'`, so RoundSpec finds the state
without being told.

Verified to 192 bits by the fuzzer, and against PRESENT's published test
vectors end to end.

---

## Bit order: LSB or MSB

Specifications disagree about which end of a word is bit 0. PRESENT counts
from the LSB — its pLayer is *"input bit i moves to output bit 16i mod 63"*,
counting up from the least significant end. Other papers write the leading
digit as bit 0.

Reading one convention as the other produces a **working circuit computing the
mirror image** of the intended function: a rotation the wrong way, a
permutation inverted. Nothing about the circuit looks wrong, and no test on a
single layer catches it.

So it is explicit. The toggle in the GUI, `--bit-order` on the CLI, or
`"bit_order"` in the cipher's own dictionary:

```python
b = Builder(bit_order="msb")
b.rotl(x, 3)              # left by 3 counting from the MSB
b.permute(x, mapping)     # out j <- in mapping[j], MSB-indexed
w = b.words(x, 16)        # w[0] is the leading word
```

Every helper converts to Digital's LSB-first indexing internally, so a
cipher's source can match the notation of its paper.

---

## Draw one round, run twenty

Almost every block cipher is the same round applied N times. Drawing twenty of
them is wasted work and twenty chances to mis-wire one — and Digital could not
simulate the result any better than it simulates one. So the schematic holds
**one** round, and the round count is an argument.

The loop is declared by naming, so the schematic still says what it does
without a separate config file:

| on the schematic | meaning |
|---|---|
| `In "L"` paired with `Out "L'"` | **state** — threaded into the next round |
| `In "rk"` with no matching Out | **per-round argument** — supplied by the driver |

`X_next` is accepted instead of `X'`. A key schedule is just another one-round
circuit with its own state, iterated in step.

---

## Writing a cipher

`ADD_A_CIPHER_ja.md` walks through this in Japanese, with the failure modes
and what each one means.

Circuits are composed from parts, not coordinates:

```python
from digparts import Builder

def present_round(b):
    state = b.inp("state", 64)
    rk    = b.inp("rk", 64)
    x = b.xor(state, rk)
    x = b.sbox_layer(x, PRESENT_SBOX)
    x = b.permute(x, PRESENT_PMAP)
    b.out("state'", x)
```

That is the whole round. Layout, splitters, the constant every ROM's select pin
needs, and the tunnels that carry signals without shorting against crossing
wires are all handled.

| helper | emits |
|---|---|
| `xor(a, b, …)` `gate("And", …)` `not_(x)` | a gate across the whole bus |
| `modadd(a, b)` | addition modulo 2^n — the A in ARX |
| `rotl(x, n)` `rotr(x, n)` | two splitters, later recognised as one CLAASP rotate |
| `sbox_layer(x, table)` | splitter, one ROM per cell, merger |
| `words(x, 16)` `join([…])` | slice a register into words and back |
| `permute(x, mapping)` | bit permutation, `out j <- in mapping[j]` |
| `mix_columns(cells, matrix, cell_bits, poly)` | a matrix over GF(2^m), as XOR |
| `inp` `out` `const` `testcase` | boundary and test data |

A cipher is then one dictionary in `ciphers.py`:

```python
LLBC = {
    "name": "llbc",
    "parts": {"round": llbc_round, "keystep": llbc_keystep},
    "reference": llbc_reference,     # plain Python, from the specification
    "vectors": [...],                # published test vectors
    "state": ["L", "R"],
    "key_state": ["k0", "k1"],
    "key_map": {"rk_lo": "k0", "rk_hi": "k1"},
    "block_bits": 128, "key_bits": 128, "rounds": 20,
    "params": lambda i, key: {"rc": llbc_rc(i)},
}
```

`mix_columns` takes the matrix as a specification writes it and expands it
into the equivalent matrix over GF(2), so nothing has to be looked up. A
multiplication by a constant in GF(2^m) is a linear map on the m bits of a
cell, which is an m-by-m binary matrix; a MixColumns over any field with any
irreducible polynomial is therefore just a bigger one. SKINNY and Midori pass
`poly=None` because their matrices are already binary; AES passes `0x11B`.

The alternative — a lookup table per constant per field — is worse twice
over. It needs a new table for every design, and in the model a table becomes
an S-box, so an 8-bit multiplication turns into 256 entries standing in for a
map that is linear and therefore free. As XOR, a difference passes with
probability one, which is what actually happens.

`modadd` ties the adder's carry in low and discards its carry out, which is
what makes the operation modular: the overflow is thrown away rather than
widening the word. Without it Speck, LEA, HIGHT and Chaskey cannot be drawn
at all, and the differential behaviour of an adder — which depends on the
values and not only on the difference — is the thing S-box ciphers never
exercise.

Copy any of the six worked examples and replace the round function.

| example | shape | what it exercises |
|---|---|---|
| PRESENT-80 | SPN | bit permutation, an 80-bit key register drawn as a `Wide` |
| LLBC-128-128 | Feistel | rotations, two S-box banks, a drawn key schedule |
| Speck32/64 | ARX | `modadd`, where the differential depends on values not just differences |
| GIFT-64-128 | SPN | a round key that reaches only two bits per nibble |
| Simon32/64 | AND-RX | a bitwise AND as the non-linearity — no table, no carry |
| SKINNY-64-128 | SPN | MixColumns, and a tweakey schedule that is a shuffle |

GIFT is worth a note. Its S-box has DDT entries that are not powers of two,
so a transition can have probability 6/16 — and a SAT model, which spends one
variable per bit of weight, cannot say that. `analyse` detects this and points
at CLAASP's SMT and MILP models instead of crashing. The cipher is fine;
`verify` still checks it against the paper. It is the solver that cannot
follow. Nothing else in the
toolchain needs to know about the new cipher.

### Why three descriptions of the same cipher

The published vectors pin down the reference implementation; the reference pins
down the circuit; the circuit pins down the CLAASP model. `verify` checks each
link. Skip one and a mistake there becomes invisible — a mistranslated CLAASP
model still produces plausible differential trails, with nothing to compare
them against.

---

## Install

### With Docker — recommended

```powershell
$env:IMAGE = "ghcr.io/fifstorm4/crossdraft:0.1.0"
.\run.ps1 selftest
.\run.ps1 build present
.\run.ps1 analyse present --rounds 3 --export fig.svg
```

With `IMAGE` set to a published release the launcher pulls it — about two
minutes. Without it, or if the pull fails, it builds locally, which is twenty
to forty because most of that time is fetching SageMath.

Files land in the directory you ran it from. The first call builds the image;
after that it starts in a second.

The image is worth having because the analysis stack has four failure modes
that each cost an hour to diagnose and none of which says what is wrong:

| | symptom |
|---|---|
| passagemath omits `sage.all`, which CLAASP imports | `ModuleNotFoundError` |
| `sage.rings.integer` and `integer_ring` initialise each other | circular-import error naming a module you never touched |
| CaDiCaL prints none of the statistics CLAASP's parser reads | `IndexError` deep inside the parser |
| CLAASP masks a `uint8` array with `0xffff` | `OverflowError` on NumPy 2 |

All four are pinned in the `Dockerfile`, along with Kissat, espresso, NIST
STS 2.1.2 and Digital itself. The build fails rather than ship an image whose
analysis path is broken: it runs PRESENT and checks the ciphertext against the
CHES 2007 vector.

For a paper, pin the digest rather than the tag — a tag can be moved, a
digest cannot. Every release prints its digest in the workflow summary:

```powershell
$env:IMAGE = "ghcr.io/fifstorm4/crossdraft@sha256:..."
.\run.ps1 env present
```

### Without Docker

**Digital and the bridge** — enough for `build` and `verify`:

```sh
# Digital.jar from https://github.com/hneemann/Digital/releases/latest
cd java && make DIGITAL_JAR=/path/to/Digital.jar
export DIGITAL_JAR=/path/to/Digital.jar
```

**CLAASP** — additionally needed for `analyse`:

```sh
pip install passagemath-modules passagemath-symbolics passagemath-brial \
            passagemath-glpk passagemath-polyhedra passagemath-combinat
pip install claasp
python3 python/setup_sage.py     # the sage.all shim passagemath omits
python3 python/patch_claasp.py   # the NumPy 2 fix
python3 python/setup_nist.py     # optional: builds NIST STS 2.1.2
```

`preload.py` must be imported before `claasp` to break the circular import;
every entry point here already does.

Two external binaries are shelled out to and are easy to miss:

| binary | why | where |
|---|---|---|
| `espresso` | S-box constraint generation | `github.com/classabbyamp/espresso-logic` ships a built one in `bin/` |
| `kissat` | SAT solving | `github.com/arminbiere/kissat`, `./configure && make` |

**CaDiCaL will not work.** CLAASP reads `real time` and `size of process` out
of the solver's output; CaDiCaL prints neither and the result parser fails with
an `IndexError`. Kissat prints `process-time` and `maximum-resident-set-size`,
which is what `KISSAT_EXT` expects.

---

## Verification

```sh
python3 tests/test_all.py --digital-jar Digital.jar --bridge-jar java/digbridge.jar
```

Each case builds a circuit from Python, then requires **Digital's own simulator
and the bridge's evaluator to agree** on the same vectors. Measured, not
asserted:

| case | size | result |
|---|---|---|
| 4-bit S-box (ROM) | 10 components | both agree |
| 64-bit XOR | 10 components | both agree |
| 64-bit SubCell (splitter + 16 S-boxes) | 106 components | both agree |
| rotate left 1, 3, 19, 32, 63 | 12 components each | agree, amount recovered |
| LLBC MixWord | 62 components | agree, `[3,3,19,19]` recovered |
| 64-bit bit permutation (pLayer) | 136 components | both agree |
| 64-bit register sliced into 16-bit words | 16 components | both agree |
| one drawn round, iterated 1/2/5/20 | 128 components | matches closed form |
| a Register | — | correctly refused |

### Randomised cross-checking

```sh
python3 tests/test_fuzz.py --digital-jar Digital.jar \
        --bridge-jar java/digbridge.jar --cases 100
```

Hand-written cases test the combinations someone thought of. Every bug found
in this toolchain so far has been a **working circuit computing the wrong
function**, and every one surfaced by accident while building something else.
So the cases are generated: random primitives, random widths, random bit
orders, stacked to random depth, with Digital's own simulator as the oracle.
Failures print the recipe that produced them, and runs are seeded.

It earned its place immediately. Six real bugs, none caught by the 17
hand-written cases:

| bug | symptom |
|---|---|
| 64-bit constants exceed Java's signed `long` | **the circuit file will not load** |
| `join_bits` wrapping a single port | net driven twice |
| `const()` placing every constant at one coordinate | net driven twice, but only with two constants |
| splitter ports resolved by position, not name | **silently wrong function** |
| a one-cell `sbox_layer` emitting identity splitters | net driven twice |
| `wide_out` putting the prime in the middle of a name | loop not declared |

Only one of those was silent, but the others reported themselves as *"net
driven twice"* with nothing pointing at the cause, which costs about as much
to find.

The layout now prevents the collision class outright — `Builder` tracks
occupied cells, so it cannot place two components on one point — and
`Circuit.write()` catches it for hand-placed circuits with a message naming
both components and the coordinate.

### Against CLAASP's own PRESENT

```sh
python3 tests/test_present_reference.py \
    --digital-jar Digital.jar --bridge-jar java/digbridge.jar
```

CLAASP ships a hand-written PRESENT. Running it beside the model derived from
a schematic is the strongest check available: two independent descriptions of
the same cipher, solved by the same engine. Agreement on the **trails**, not
merely on the ciphertext, is what says the translation preserved the
differential structure rather than just the function.

| check | built-in | derived | CHES 2007 |
|---|---|---|---|
| test vectors | 4/4 | 4/4 | — |
| 1 round | weight 2, 1 active | weight 2, 1 active | 1 active |
| 2 rounds | weight 4, 2 active | weight 4, 2 active | 2 active |
| 3 rounds | weight 8, 4 active | weight 8, 4 active | 4 active |

Three rounds is deliberate: the minimum active S-box counts 1, 2, 4 are
published in the proposal, so the numbers have an external reference too, and
the search still finishes in seconds.

### End to end, through the CLI

| cipher | check | result |
|---|---|---|
| PRESENT | published vectors, key schedule drawn | 4/4 |
| Speck32/64 | published vector (ePrint 2013/404) | 1/1 |
| GIFT-64-128 | published vectors (CHES 2017) | 2/2 |
| Simon32/64 | published vector (ePrint 2013/404) | 1/1 |
| SKINNY-64-128 | published vector (CRYPTO 2016) | 1/1 |
| SKINNY-64-128 | minimum active S-boxes, 1–5 rounds | 1, 2, 5, 8, 12 — the published bounds |
| Simon32/64 | trails vs CLAASP's own Simon, 2–6 rounds | weights 2, 4, 6, 8, 12 — identical |
| Speck32/64 | trails vs CLAASP's own Speck, 2–5 rounds | weights 1, 3, 5, 9 — identical |
| PRESENT | circuit vs reference, 1/2/5/31 rounds | all agree |
| PRESENT | key avalanche, 31 rounds | 32.70 of 64 bits, ideal 32 |
| PRESENT | differential, 3 and 4 rounds | weight 8 and 12 — 4 and 6 active S-boxes, the known bounds |
| LLBC | circuit vs reference, 1…20 rounds | all agree |
| LLBC | differential, 2 and 3 rounds | weight 4 and 8, matching a hand-written CLAASP model |

The optional features have their own suites, so the core one stays fast:

```sh
python3 tests/test_features.py --digital-jar Digital.jar --bridge-jar java/digbridge.jar
```

| case | result |
|---|---|
| sub-circuit expansion, two instances | 16 components become 222, evaluation agrees |
| export svg tex tikz csv json md txt | all written, standard library only |
| export pdf png jpg | all written via matplotlib |
| S-box DDT and LAT | DDTmax 4, LATmax 4, max DP 2^-2 — PRESENT's published profile |

```sh
python3 tests/test_analysis.py --digital-jar Digital.jar --bridge-jar java/digbridge.jar
```

| case | result |
|---|---|
| cost models nangate45 / umc180 / nand_transistors | 13,888 GE / 15,217 GE / 17,856 transistors for 31 unrolled rounds |
| software cost | ~2,046 word operations over 31 rounds |
| every benchmark names a known environment | 54 entries, 8 environments |
| every environment cites a source | yes |
| area figures stay grouped | 4 groups, never ranked across |
| the same cipher differs across environments | PRESENT-64-128: 1,560 GE vs 56,722 GE |
| weight bound brackets the known minimum | weight 7 UNSAT, weight 8 SAT — CHES 2007 gives 4 active S-boxes |
| impossible differentials carry UNSAT certificates | 16 of 16 proved in 0.3s |

Run the core suite before adding a component type. A bridge that drops a wire or
mis-orders a splitter's ports still produces a CLAASP model, and that model
still yields plausible trails.

---

## Why the Java half exists

A `.dig` file records wires as bare coordinate pairs:

```xml
<wire><p1 x="200" y="280"/><p2 x="220" y="280"/></wire>
```

There is no logical netlist in the file. Recovering connectivity means knowing
where every component's pins sit, which depends on the component type, its
rotation, its bit width, its input count, and shape rules that live inside
Digital. `DigNetlist.java` calls Digital's own `NetList` instead — ~300 lines
that cannot drift from Digital's semantics, because they *are* Digital's
semantics.

JSON is the boundary. The Java side links against `Digital.jar` and inherits
GPLv3; the Python side only reads JSON.

---

## Optional extras

None of these are imported by the build / verify / analyse pipeline. They are
there when a paper needs them and cost nothing when it does not.

### Sub-circuit expansion

Digital lets a whole layer be dropped into a schematic as one box, which is
how a drawing stays readable — an S-box layer becomes one symbol instead of
forty. The netlist names the box by filename and says nothing about its
contents, so the translator opens it and splices it in, recursively, renaming
as it goes so two copies stay distinct:

```python
nl = Netlist("parent.json", digital_jar=JAR, bridge_jar=BRIDGE)
```

Ports are stitched by matching the sub-circuit's `In`/`Out` labels against the
box's pin names, which is what Digital does too — and why a sub-circuit's
ports have to be labelled.

### Trail export

```sh
python3 digcli.py analyse present --rounds 3 --show \
        --export fig3.svg --export fig3.pdf --export table6.tex
```

| format | needs |
|---|---|
| `.svg` `.tex` `.tikz` `.csv` `.json` `.md` `.txt` | nothing — standard library |
| `.pdf` `.png` `.jpg` | matplotlib |

PDF and the bitmaps sit behind an optional dependency on purpose: a SAT search
should not require a plotting stack, and LaTeX takes SVG directly through
`\includegraphics` with the pdf backend.

The picture is the one these papers always draw — rounds down, S-box positions
across, a mark where the box is active, darker for the cheaper transitions.
It is the view that makes the shape of a trail legible: where the difference
narrows to one nibble, where a round costs nothing because the branch entering
the round function is zero, whether the pattern repeats. A wall of hex does
not show that.

`.tex` gives a booktabs table of the propagation, ready to `\input`; `.tikz`
gives the same grid in the document's own fonts. Retyping a trail out of a
terminal is how transcription errors reach print.

### S-box tables

```sh
python3 digcli.py sbox present --show --export ddt.tex
```

DDT, LAT, bijectivity and the maximum differential probability — the table
quoted beside every new S-box, computed rather than copied.

### Beyond one characteristic

```sh
python3 digcli.py bound      present --rounds 3 --weights 6,7,8,9
python3 digcli.py cluster    present --rounds 3
python3 digcli.py impossible present --rounds 3
python3 digcli.py impossible present --rounds 3 --linear   # zero correlation
```

**`bound`** asks whether a characteristic of a given weight exists, one weight
at a time, instead of minimising. Minimising has to prove nothing lighter
exists, which is where the time goes — the LLBC designers report 482 hours for
a 7-round optimum. A designer's claim is usually *"no trail beats 2^-n"*, and
that is a satisfiability question at a single weight:

```
  weight 6: UNSATISFIABLE  no characteristic of this weight  [5.6s]
  weight 7: UNSATISFIABLE  no characteristic of this weight  [0.5s]
  weight 8: SATISFIABLE    a characteristic of this weight exists
```

**`cluster`** sums every characteristic joining one input difference to one
output difference. A trail search returns a single characteristic; an attack
is governed by the differential, the sum over all of them. The gap is free
probability — the distinguisher can only get stronger. That matters when a key
recovery sits near a bound: a data complexity of 2^127 against a 128-bit block
is at the edge of the codebook, and a few bits of clustering gain move the
result from *boundary case* to *attack*.

**`impossible`** sweeps single-active-cell pairs and keeps the ones the solver
reports UNSATISFIABLE. That is a proof; a pair that merely fails to appear in
a trail search proves nothing. `--linear` does the same over the linear model
for zero correlation. Both run on SAT rather than CLAASP's CP models, which
need a MiniZinc installation — asking for any characteristic and taking UNSAT
proves the same thing with only a SAT solver.

### Cost, and what the papers report

```sh
python3 digcli.py cost  present --rounds 31 --model nangate45
python3 digcli.py bench --metric area_ge --environment gift_stm90_roundbased
python3 digcli.py bench --environments      # every source, in full
python3 digcli.py bench --cite llbc_nangate45_unrolled
```

`cost` counts what is on the schematic and applies a stated gate model
(`nangate45`, `umc180`, or the NAND-transistor counts the LLBC proposal uses).
It is reproducible and it is an estimate — no sharing, no technology mapping,
no register cost — and it says so every time it prints.

`bench` holds figures copied from published papers, **each tagged with the
process, the architecture, the tool and the citation**. Entries from different
environments are grouped and never ranked together, because doing so is a
category error rather than a comparison:

| | PRESENT-64-128 |
|---|---|
| STM 90nm, round-based (GIFT, CHES 2017) | 1,560 GE |
| UMC 0.18um, fully unrolled (LLBC, IoT-J 2025) | 56,722 GE |

Same cipher, 36x apart. The LLBC proposal itself reports PRINCE at 8,512 GE on
0.18um and 9,874 GE on NanGate 45nm. A bare table across papers is not a
comparison.

Environments currently registered: NanGate 45nm and UMC 0.18um unrolled (LLBC
proposal Tables XII, XIII, VI), STM 90nm round-based (GIFT CHES 2017), Spartan-6
and Artix-7 FPGA and STM32L475 / ESP32-S3 software (LLBC Tables XI, XV) —
54 figures in all. `--export table.tex` writes a booktabs table with the source
note attached; `--export bench.json` gives the whole registry.

### From the GUI

`analyse` renders the activity grid straight into the page and writes
`build/<cipher>/trail.svg`. The other formats stay on the command line, where
the filename is the obvious place to say what is wanted.

---

## Supported subset

Digital has around a hundred component types; almost none mean anything to a
differential model. Anything outside this table is rejected **by name**.

| Digital | CLAASP |
|---|---|
| `In` `Out` | plaintext / key / cipher_output |
| `XOr` | `add_XOR_component` |
| `And` `Or` `Not` `NAnd` `NOr` | `add_AND` / `add_OR` / `add_NOT` |
| `ROM` | `add_SBOX_component` |
| `Splitter` | re-slicing, or `add_rotate_component` |
| `Const` | `add_constant_component` |
| `Tunnel` `Text` | — |

Flip-flops, registers, RAM, counters and clocks are refused: a cipher for
CLAASP has to be an unrolled DAG, because there is no notion of time in a
differential model.

---

## Facts measured against the tools, not read off documentation

**Test data number format.** Decimal and `0x`-prefixed hex are accepted; bare
hex (`C`, `B`) is rejected with *"Error parsing the test data"*, even though the
GUI editor appears to take it.

**Splitter attribute keys** are `Input Splitting` and `Output Splitting` — note
the capital S on the second, which the manual renders lowercase.

**Bit indexing runs both ways in the literature and only one way in Digital.**
Digital's splitter bundle counts from the LSB. A specification that counts
from the MSB, fed in unconverted, gives a circuit computing the mirror-image
function — see the `bit_order` switch above.

**Splitter pin names** are the bit ranges they carry: `0-63`, `8-11`, `3,4`,
`7`. Sorting those as strings puts `10` before `2`, which transposes every
splitter with more than ten ports — every wide bit permutation, every key
schedule that slices a register into words. This was a real bug here: it
produced a working cipher computing the wrong function, and only surfaced once
PRESENT's pLayer was built.

**Bit width.** 64 works everywhere, though the Data Bits dropdown only lists up
to 32; type the number rather than picking from the list.

**Wires join wherever they touch.** Routing a busy circuit with drawn wires
silently merges nets that only happen to cross. Everything here connects
through `Tunnel`s, which join by name.

**Bit order across the boundary.** Digital's splitter bundle counts from the
LSB; a CLAASP operand lists positions MSB first. Feeding one straight into the
other transposes every word — and the data path still evaluates correctly,
because its splitters are symmetric, so only a key schedule slicing 64 bits
into 16-bit words shows it, and only in the final answer.

---

## Licence and provenance

GPLv3, and not by preference. The netlist extractor links against
`Digital.jar` and the analysis side imports CLAASP; both are GPLv3, as is
SageMath underneath. See `NOTICE.md` for the full dependency table.

`NOTICE.md` also carries the disclosure that portions of this software were
developed with the assistance of a large language model, and what the
author's validation of that consisted of. The short version: `test_fuzz.py`
found six real defects, four of them in code that had already passed a
hand-written suite. The claim is not that the code was written carefully —
it is that its results are checked against an independent implementation,
every time.

---

## Known limits

- **Sequential circuits are out of scope** by design.
- `Circuit.write()` shells out to `java` twice per circuit, to ask Digital
  where the pins landed before drawing wires to them.


---

## When something does not work

```sh
./run.ps1 doctor
```

Asks every question the pipeline depends on and says what to do about each
answer:

```
  ok       java                     openjdk version "21.0.12"
  MISSING  Digital.jar              DIGITAL_JAR is not set
          needed for: build, verify
          fix: point it at Digital.jar from github.com/hneemann/Digital/releases/latest
  ok       CLAASP                   importable
  MISSING  kissat                   not on PATH
          needed for: analyse, replicate, cluster
          fix: build it from github.com/arminbiere/kissat. CaDiCaL will not
               substitute: CLAASP parses statistics it does not print
```

Every failure this project hit on somebody else's machine took a round trip to
report, reproduce and explain — a dependency CLAASP does not declare, a server
bound to a loopback address a container cannot reach, a port held by something
invisible. None said what was wrong and none could be guessed from the
symptom. `doctor` asks directly.

It also distinguishes the two halves: drawing and verifying circuits needs
only a JDK, and is worth having on its own.

---

New here? `QUICKSTART_ja.md` goes from a bare Windows machine to analysing a
cipher of your own, click by click.

---
