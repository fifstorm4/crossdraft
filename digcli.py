#!/usr/bin/env python3
"""
digcli -- draw a cipher, check it, analyse it.

    python3 digcli.py list
    python3 digcli.py build   llbc
    python3 digcli.py verify  llbc --rounds 20
    python3 digcli.py analyse llbc --rounds 3

    build     draw the cipher's circuits and extract their netlists
    verify    circuit vs reference implementation vs published vectors
    analyse   emit a CLAASP cipher and search for differential trails

Run them in that order.  Each stage checks the one before it, and skipping a
stage makes the next one's output untrustworthy in a way that is hard to see:
a mistranslated CLAASP model still produces plausible differential trails,
with nothing to compare them against.

Ciphers live in ciphers.py, one dictionary each.  Adding one needs no change
here.


SETUP
-----
    java        a JDK, and Digital.jar from
                https://github.com/hneemann/Digital/releases/latest
    bridge      cd java && make DIGITAL_JAR=/path/to/Digital.jar

`analyse` additionally needs CLAASP, and CLAASP needs three things that are
easy to miss:

    pip install passagemath-modules passagemath-symbolics passagemath-brial \
                passagemath-glpk passagemath-polyhedra passagemath-combinat
    pip install claasp

    espresso    S-box constraint generation shells out to it
                (github.com/classabbyamp/espresso-logic ships a binary)
    kissat      a SAT solver whose output CLAASP can parse
                (github.com/arminbiere/kissat).  CaDiCaL will not do: CLAASP
                reads "real time" and "size of process" out of the solver's
                output and CaDiCaL prints neither.

If passagemath is used rather than a full Sage, sage/all.py must be supplied;
see setup_sage.py in this directory.
"""

import argparse
import importlib
import re
import json
import os
import random
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def _env(args):
    jar = args.digital_jar or os.environ.get("DIGITAL_JAR")
    bridge = args.bridge_jar or os.environ.get(
        "BRIDGE_JAR", os.path.join(HERE, "java", "digbridge.jar"))
    if not jar or not os.path.exists(jar):
        sys.exit("set --digital-jar or DIGITAL_JAR to your Digital.jar")
    if not os.path.exists(bridge):
        sys.exit(f"{bridge} not found; run: "
                 f"cd java && make DIGITAL_JAR={jar}")
    return os.path.abspath(jar), os.path.abspath(bridge)


def _spec(name):
    from ciphers import REGISTRY
    if name not in REGISTRY:
        sys.exit(f"unknown cipher {name!r}; known: {sorted(REGISTRY)}")
    return REGISTRY[name]


def _outdir(spec, args):
    """
    Where circuits and netlists go: under `build/` in the working directory.

    Not beside this script.  In a container the script lives in the image and
    the working directory is the mounted volume, so writing next to the script
    puts the output somewhere that vanishes when the container exits -- and
    the next command then reports the netlist as missing, having just made it.
    Anywhere else it is simply what a user expects: files appear where the
    command was run.
    """
    d = args.outdir or os.path.join(os.getcwd(), "build", spec["name"])
    os.makedirs(d, exist_ok=True)
    return d


def _extract(dig, jar, bridge):
    js = dig.replace(".dig", ".json")
    r = subprocess.run(["java", "-cp", f"{jar}:{bridge}",
                        "digbridge.DigNetlist", dig, js],
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit(f"netlist extraction failed:\n{r.stderr}")
    return js


# --------------------------------------------------------------------------

def cmd_list(args):
    from ciphers import REGISTRY
    for name, spec in sorted(REGISTRY.items()):
        print(f"{name}")
        print(f"    block {spec['block_bits']}  key {spec['key_bits']}  "
              f"rounds {spec['rounds']}")
        print(f"    parts: {', '.join(spec['parts'])}")
        print(f"    published vectors: {len(spec['vectors'])}")
        if spec.get("note"):
            print(f"    note: {spec['note']}")
    return 0


def cmd_build(args):
    from digparts import Builder
    jar, bridge = _env(args)
    spec = _spec(args.cipher)
    out = _outdir(spec, args)

    order = (os.environ.get("DIGBRIDGE_BIT_ORDER")
             or spec.get("bit_order", "lsb"))
    for part, fn in spec["parts"].items():
        b = Builder(bit_order=order)
        fn(b)
        if args.with_tests:
            _embed_tests(b, spec, part, args.test_vectors, jar, bridge)
        dig = os.path.join(out, f"{spec['name']}_{part}.dig")
        b.write(dig, jar, bridge)
        js = _extract(dig, jar, bridge)
        data = json.load(open(js))
        # Unused splitter outputs are normal: cutting a range out of a word
        # always leaves the ends over, and that is how every rotation and
        # every wide register is built. A dangling pin anywhere else is a
        # real mistake and is invisible in the .dig file.
        types = {c["id"]: c["type"] for c in data["components"]}
        loose = [u for u in data.get("unconnected", [])
                 if not (types.get(u["component"]) == "Splitter"
                         and u["dir"] == "output")]
        print(f"  {part:8s} {len(data['components']):4d} components, "
              f"{len(data['nets']):3d} nets" +
              (f"  ** {len(loose)} UNCONNECTED PIN(S) **" if loose else ""))
        for u in loose[:5]:
            print(f"      {u['component']}.{u['pin']} at "
                  f"({u['x']},{u['y']})")
    print(f"  -> {out}")
    return 0


def _embed_tests(builder, spec, part, count, jar, bridge):
    """
    Put a Testcase component in the circuit so Digital's own F8 works.

    Without one, opening a generated circuit and pressing F8 answers "No test
    data found" -- correct, and unhelpful.

    The expected values come from evaluating the circuit itself, not from the
    cipher's reference implementation. That sounds circular and is not: the
    evaluator reads the netlist and applies each component's semantics in
    Python, while Digital simulates the same drawing with its own engine. A
    disagreement means the two read the same circuit differently, which is
    exactly the class of bug this project exists to catch -- and it is caught
    from inside the editor, on the drawing in front of you.

    Whether the circuit computes the *cipher* is a separate question, and the
    one `verify` answers by running the reference implementation.
    """
    import random
    import subprocess
    import tempfile

    from dig2claasp import Netlist, evaluate

    ins = [c for c in builder.c.components if c.type == "In"]
    outs = [c for c in builder.c.components if c.type == "Out"]
    if not ins or not outs:
        return

    names_in = [c.attrs.get("Label") for c in ins]
    names_out = [c.attrs.get("Label") for c in outs]
    if any(n is None for n in names_in + names_out):
        return
    bits = {c.attrs.get("Label"): int(c.attrs.get("Bits", 64))
            for c in ins + outs}

    # Write the circuit once without tests, read its netlist, and evaluate.
    with tempfile.TemporaryDirectory() as tmp:
        stage = os.path.join(tmp, "stage.dig")
        builder.write(stage, jar, bridge)
        js = os.path.join(tmp, "stage.json")
        r = subprocess.run(["java", "-cp", f"{jar}:{bridge}",
                            "digbridge.DigNetlist", stage, js],
                           capture_output=True, text=True)
        if r.returncode:
            return
        nl = Netlist(js)

        rng = random.Random(0)
        rows = []
        for _ in range(count):
            vals = {n: rng.getrandbits(bits[n]) for n in names_in}
            try:
                out = evaluate(nl, vals)
            except Exception:
                return
            rows.append([vals[n] for n in names_in]
                        + [out.get(n, 0) for n in names_out])

    if rows:
        builder.testcase(names_in + names_out, rows)


def cmd_verify(args):
    from dig2claasp import Netlist, RoundSpec, iterate, evaluate
    jar, bridge = _env(args)
    spec = _spec(args.cipher)
    out = _outdir(spec, args)
    rounds = args.rounds or spec["rounds"]

    nets, specs = {}, {}
    for part in spec["parts"]:
        js = os.path.join(out, f"{spec['name']}_{part}.json")
        if not os.path.exists(js):
            sys.exit(f"{js} missing; run `build` first")
        nets[part] = Netlist(js)
        specs[part] = RoundSpec(nets[part])
        print(f"  {part:8s} {specs[part]}")

    # 1. published vectors pin down the reference implementation
    ref = spec["reference"]
    if spec["vectors"]:
        bad = 0
        for p, k, c in spec["vectors"]:
            got = ref(p, k, spec["rounds"])
            if got != c:
                bad += 1
                print(f"  reference MISMATCH P={p:x} K={k:x} "
                      f"got {got:x} want {c:x}")
        print(f"  published vectors: "
              f"{len(spec['vectors']) - bad}/{len(spec['vectors'])}")
    else:
        print("  published vectors: none "
              f"({spec.get('note', 'not available')})")

    # 2. the reference pins down the circuit
    def run(pt, key, n):
        keys, extras = None, []
        if "keystep" in nets:
            ks = specs["keystep"]
            # Slice the master key across the schedule's state words, least
            # significant first, matching wide_in's numbering.
            # A schedule whose state came from wide_in numbers its words
            # least significant first, so the master key is sliced upward.
            # One built by hand -- LLBC's k0/k1 -- names them in the order
            # the specification writes them, most significant first.
            st, wide = {}, all(re.search(r"_\d+$", n) for n in ks.state)
            off = 0 if wide else spec["key_bits"]
            for name in ks.state:
                w = ks.bits[name]
                if wide:
                    st[name] = (key >> off) & ((1 << w) - 1)
                    off += w
                else:
                    off -= w
                    st[name] = (key >> off) & ((1 << w) - 1)
            keys = [[st[s] for s in ks.state]]
            for i in range(n + 1):
                kp = spec.get("key_params", lambda i, k: {})(i, key)
                extras.append(evaluate(nets["keystep"], {**st, **kp}))
                st = {s: extras[-1][ks.state_out[s]] for s in ks.state}
                keys.append([st[s] for s in ks.state])

        half = spec["block_bits"] // len(spec["state"])
        state = {}
        for j, s in enumerate(spec["state"]):
            shift = spec["block_bits"] - half * (j + 1)
            state[s] = (pt >> shift) & ((1 << half) - 1)

        def params(i):
            p = dict(spec["params"](i, key))
            if keys:
                for rin, kst in (spec.get("key_map") or {}).items():
                    p[rin] = keys[i][specs["keystep"].state.index(kst)]
                for rin, kout in (spec.get("key_extra") or {}).items():
                    p[rin] = extras[i][kout]
            return p

        fin = iterate(nets["round"], n, state, params=params,
                      spec=specs["round"])
        acc = 0
        for s in spec["state"]:
            acc = (acc << half) | fin[s]
        # Some ciphers whiten after the last round.  That XOR is not part of
        # the round function, so it is not drawn; applying it here keeps the
        # schematic a single clean round.
        if spec.get("final_key") and extras:
            acc ^= extras[n][spec["final_key"]]
        return acc

    random.seed(args.seed)
    bad = 0
    for _ in range(args.trials):
        pt = random.getrandbits(spec["block_bits"])
        key = random.getrandbits(spec["key_bits"])
        got, want = run(pt, key, rounds), ref(pt, key, rounds)
        if got != want:
            bad += 1
            if bad == 1:
                print(f"  circuit MISMATCH at {rounds} rounds\n"
                      f"    got  {got:0{spec['block_bits']//4}x}\n"
                      f"    want {want:0{spec['block_bits']//4}x}")
    print(f"  circuit vs reference at {rounds} rounds: "
          f"{args.trials - bad}/{args.trials}")
    return 1 if bad else 0


def cmd_analyse(args):
    try:
        import preload            # noqa: F401  (order matters for passagemath)
    except ImportError:
        pass
    from dig2claasp import build_cipher
    spec = _spec(args.cipher)
    out = _outdir(spec, args)
    rounds = args.rounds or 3

    # Via the shared loader, not by assembling the arguments here. A key
    # schedule is wired up by several optional settings -- key_map,
    # key_extra, final_key -- and a second copy of that assembly is a second
    # chance to name one the cipher does not have. PRESENT uses key_extra
    # and no key_map, and this is exactly where that crashed.
    cipher = _load_cipher(spec, out, rounds)
    print(f"  CLAASP cipher: {rounds} rounds, "
          f"{len(cipher.get_all_components_ids())} components")

    if args.no_search:
        return 0

    from claasp.cipher_modules.models.utils import set_fixed_variables
    from claasp.cipher_modules.models.sat.sat_models \
        .sat_xor_differential_model import SatXorDifferentialModel

    model = SatXorDifferentialModel(cipher)
    fixed = [
        set_fixed_variables("key", "equal",
                            list(range(spec["key_bits"])),
                            [0] * spec["key_bits"]),
        set_fixed_variables("plaintext", "not_equal",
                            list(range(spec["block_bits"])),
                            [0] * spec["block_bits"]),
    ]
    trail = model.find_lowest_weight_xor_differential_trail(
        fixed_values=fixed, solver_name=args.solver)
    w = trail["total_weight"]
    print(f"  best differential characteristic over {rounds} rounds: "
          f"weight {w}  (probability 2^-{w})")
    print(f"  active S-boxes at most: {int(w // 2)}")

    if args.show or args.export:
        from digtrail import Trail
        t = Trail.from_claasp(trail, cipher,
                              name=f"{spec['name'].upper()}, "
                                   f"{rounds} rounds")
        if args.show:
            print()
            print(t.text(radix=args.radix))
        for path in args.export or []:
            try:
                t.save(path)
                print(f"  wrote {path}")
            except Exception as e:
                print(f"  could not write {path}: {e}")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"rounds": rounds, "weight": w,
                       "components_values": {
                           k: v for k, v in
                           trail["components_values"].items()
                           if v.get("weight")}}, fh, indent=2, default=str)
        print(f"  trail written to {args.json}")
    return 0


def cmd_sbox(args):
    """DDT and LAT of a cipher's S-boxes -- the tables papers quote."""
    from digtrail import sbox_tables
    spec = _spec(args.cipher)
    tables = {}
    for key, val in vars(__import__("ciphers")).items():
        if key.startswith(spec["name"].upper()) and isinstance(val, list) \
                and len(val) in (16, 256) and sorted(val) == list(
                    range(len(val))):
            tables[key] = val
    if not tables:
        sys.exit(f"no S-box table found for {spec['name']} in ciphers.py")
    for name, table in tables.items():
        r = sbox_tables(table, name)
        print(f"{name}: {len(table)} entries, bijective={r['bijective']}, "
              f"DDTmax={r['ddt_max']}, LATmax={r['lat_max']}, "
              f"max differential probability {r['max_differential_probability']}")
        if args.show:
            print()
            print(r["text"])
        for path in args.export or []:
            target = path if len(tables) == 1 else \
                f"{os.path.splitext(path)[0]}_{name}{os.path.splitext(path)[1]}"
            with open(target, "w") as fh:
                fh.write(r["latex"] if target.endswith(".tex")
                         else json.dumps(r, indent=2, default=str))
            print(f"  wrote {target}")
    return 0


def _load_cipher(spec, out, rounds, key=0):
    """Build the CLAASP object, via the cipher's own wiring in ciphers.py."""
    from ciphers import load
    return load(spec["name"], rounds, out, key)


def _preload():
    try:
        import preload           # noqa: F401
    except ImportError:
        pass


def cmd_cluster(args):
    """Sum every characteristic sharing one input/output difference."""
    _preload()
    from digattack import cluster_from_trail
    from claasp.cipher_modules.models.utils import set_fixed_variables
    from claasp.cipher_modules.models.sat.sat_models \
        .sat_xor_differential_model import SatXorDifferentialModel

    spec = _spec(args.cipher)
    rounds = args.rounds or 3
    cipher = _load_cipher(spec, _outdir(spec, args), rounds)
    model = SatXorDifferentialModel(cipher)
    fixed = [
        set_fixed_variables("key", "equal", list(range(spec["key_bits"])),
                            [0] * spec["key_bits"]),
        set_fixed_variables("plaintext", "not_equal",
                            list(range(spec["block_bits"])),
                            [0] * spec["block_bits"]),
    ]
    trail = model.find_lowest_weight_xor_differential_trail(
        fixed_values=fixed, solver_name=args.solver)
    print(f"  best characteristic over {rounds} rounds: "
          f"weight {trail['total_weight']}")
    print()
    r = cluster_from_trail(cipher, trail, extra_weight=args.extra,
                           key_bits=spec["key_bits"],
                           block_bits=spec["block_bits"],
                           solver=args.solver)
    print()
    print(f"  {r['note']}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(r, fh, indent=2, default=str)
        print(f"  wrote {args.json}")
    return 0


def cmd_impossible(args):
    """Cell pairs that cannot occur, each with an UNSAT certificate."""
    _preload()
    from digattack import impossible_differentials, zero_correlation
    spec = _spec(args.cipher)
    rounds = args.rounds or 3
    cipher = _load_cipher(spec, _outdir(spec, args), rounds)
    fn = zero_correlation if args.linear else impossible_differentials
    kind = "zero-correlation" if args.linear else "impossible differential"
    print(f"  {kind} sweep over {rounds} rounds, "
          f"{spec['block_bits'] // args.cell_bits} cells per side")
    r = fn(cipher, cell_bits=args.cell_bits, key_bits=spec["key_bits"],
           block_bits=spec["block_bits"], solver=args.solver,
           max_pairs=args.max_pairs)
    key = "zero_correlation" if args.linear else "impossible"
    print(f"  {len(r[key])} of {r['tested_pairs']} pairs proved, "
          f"{r['seconds']}s")
    print(f"  {r['note']}")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(r, fh, indent=2, default=str)
        print(f"  wrote {args.json}")
    return 0


def cmd_bound(args):
    """Is there a characteristic of weight w?  Cheaper than minimising."""
    _preload()
    from digattack import differential_bound
    spec = _spec(args.cipher)
    rounds = args.rounds or 3
    cipher = _load_cipher(spec, _outdir(spec, args), rounds)
    print(f"  {rounds} rounds, satisfiability at each weight")
    weights = []
    for chunk in args.weights:
        weights += [int(w) for w in str(chunk).replace(",", " ").split()]
    differential_bound(cipher, weights,
                       key_bits=spec["key_bits"],
                       block_bits=spec["block_bits"], solver=args.solver)
    return 0


def cmd_cost(args):
    """What the drawn circuit costs, under a stated gate model."""
    from dig2claasp import Netlist
    from digcost import estimate, software_cost, GATE_MODELS
    spec = _spec(args.cipher)
    out = _outdir(spec, args)
    rounds = args.rounds or spec["rounds"]
    unit = "NAND transistors" if args.model == "nand_transistors" else "GE"

    total_hw = total_sw = 0
    hw = sw = None
    for part in spec["parts"]:
        js = os.path.join(out, f"{spec['name']}_{part}.json")
        if not os.path.exists(js):
            sys.exit(f"{js} missing; run `build` first")
        nl = Netlist(js)
        hw = estimate(nl, model=args.model, unrolled_rounds=rounds)
        sw = software_cost(nl, word_bits=args.word_bits,
                           unrolled_rounds=rounds)
        total_hw += hw["total"]
        total_sw += sw["cycles_total"]
        print(f"  {part}")
        print("    gates: " + ", ".join(f"{k} x{v}" for k, v
                                        in sorted(hw["gates"].items())))
        print(f"    {hw['per_round']:,.1f} {unit} per round "
              f"({hw['sboxes']} S-boxes, {hw['sbox_cost']:,.1f} {unit})")
        print(f"    {sw['cycles_per_round']:,} word operations per round "
              f"on a {sw['word_bits']}-bit machine")

    print()
    print(f"  {rounds} rounds unrolled : {total_hw:,.1f} {unit}")
    print(f"  {rounds} rounds in software: ~{total_sw:,} word operations")
    print()
    print(f"  model {args.model}: {GATE_MODELS[args.model]['note']}")
    print(f"  {GATE_MODELS[args.model]['source']}")
    print()
    if hw:
        print(f"  caveat: {hw['caveat']}")
    if sw:
        print(f"  caveat: {sw['caveat']}")
    print()
    print("  Published figures to compare against, with the environments "
          "they were measured in:")
    print("    digcli.py bench --metric area_ge")
    return 0


def cmd_bench(args):
    """Published figures, grouped by the environment they came from."""
    from digcost import (table_text, table_latex, cite, ENVIRONMENTS,
                         to_json)
    if args.environments:
        for name, e in ENVIRONMENTS.items():
            print(f"{name}  [{e['kind']}]")
            for k in ("process", "device", "architecture", "tool", "measure"):
                if k in e:
                    print(f"    {k}: {e[k]}")
            print(f"    source: {e['source']}")
            if "caution" in e:
                print(f"    caution: {e['caution']}")
            print()
        return 0
    if args.cite:
        print(cite(args.cite))
        return 0
    if args.export:
        for path in args.export:
            data = (to_json() if path.endswith(".json")
                    else table_latex(args.metric, args.environment,
                                     args.cipher_filter))
            with open(path, "w") as fh:
                fh.write(data)
            print(f"wrote {path}")
        return 0
    print(table_text(args.metric, args.environment, args.cipher_filter))
    return 0


def cmd_relatedkey(args):
    """Single-key against related-key, side by side."""
    _preload()
    from digstat import related_key, key_schedule_report
    spec = _spec(args.cipher)

    if args.sweep:
        lo, hi = (int(x) for x in args.sweep.split(","))
        print(f"  {spec['name']}, rounds {lo} to {hi}")
        print()
        print(f"  {'R':>3}  {'single':>8}  {'related':>8}  {'gap':>6}")
        print("  " + "-" * 32)
        rows = []
        for n in range(lo, hi + 1):
            c = _load_cipher(spec, _outdir(spec, args), n)
            r = related_key(c, key_bits=spec["key_bits"],
                            block_bits=spec["block_bits"],
                            solver=args.solver, verbose=False)
            rows.append((n, r["single_key"]["weight"],
                         r["related_key"]["weight"], r["gap_bits"]))
            print(f"  {n:>3}  {rows[-1][1]:>8g}  {rows[-1][2]:>8g}  "
                  f"{rows[-1][3]:>6g}")
        print()
        gaps = [g for _, _, _, g in rows]
        if len(gaps) > 1:
            trend = ("widens" if gaps[-1] > gaps[0]
                     else "closes" if gaps[-1] < gaps[0] else "holds steady")
            print(f"  the gap {trend} over this range. A gap that widens is "
                  f"the one worth reporting;")
            print(f"  one that closes says the data path catches up and the "
                  f"key schedule is doing its job.")
        if args.json:
            with open(args.json, "w") as fh:
                json.dump([{"rounds": n, "single": s_, "related": r_,
                            "gap": g} for n, s_, r_, g in rows], fh,
                          indent=2)
            print(f"  wrote {args.json}")
        return 0

    rounds = args.rounds or 3
    cipher = _load_cipher(spec, _outdir(spec, args), rounds)
    print(f"  {spec['name']}, {rounds} rounds")
    r = related_key(cipher, key_bits=spec["key_bits"],
                    block_bits=spec["block_bits"], solver=args.solver)

    print()
    if "keystep" in spec["parts"]:
        from dig2claasp import Netlist
        kj = os.path.join(_outdir(spec, args),
                          f"{spec['name']}_keystep.json")
        if os.path.exists(kj):
            ks = key_schedule_report(Netlist(kj), spec, rounds=rounds,
                                     samples=args.samples)
            print(f"  key schedule affine over GF(2): {ks['linear']}")
            print(f"  {ks['note']}")
    else:
        print("  key schedule is not drawn for this cipher, so its "
              "linearity is not measured here")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"related_key": {k: v for k, v in r.items()
                                       if not k.endswith("trail")},
                       "key_schedule": ks}, fh, indent=2, default=str)
        print(f"  wrote {args.json}")
    return 0


def cmd_random(args):
    """Diffusion, and optionally the NIST battery."""
    _preload()
    from digstat import avalanche, diffusion, nist
    spec = _spec(args.cipher)
    rounds = args.rounds or spec["rounds"]
    cipher = _load_cipher(spec, _outdir(spec, args), rounds)

    print(f"  {spec['name']}, {rounds} rounds")
    print()
    print("  avalanche")
    avalanche(cipher, samples=args.samples)
    print()
    trials = max(4, args.samples // 25)
    d = diffusion(cipher, trials_per_bit=trials)
    print(f"  diffusion: {d['input_bits_reaching_every_output']}/"
          f"{d['block_bits']} input bits reach every output bit"
          f"{'  (full diffusion)' if d['full_diffusion'] else ''}")
    print(f"  {d['note']}")
    if not d["full_diffusion"]:
        print(f"  Short of full on {trials} random pairs per input bit, which "
              f"is a sampling floor as much as a property of the cipher: a "
              f"dependency that fires rarely needs more pairs to appear. "
              f"Raise --samples to tighten it.")

    if args.nist:
        print()
        print("  NIST SP 800-22")
        try:
            nist(cipher, test_type=args.test_type,
                 bits_per_sequence=args.bits, sequences=args.sequences,
                 round_start=rounds - 1, round_end=rounds - 1)
        except RuntimeError as e:
            print(f"    {e}")
            return 1
    return 0


def cmd_doctor(args):
    """Check the environment and say what to do about anything missing."""
    import subprocess
    jar = args.digital_jar or os.environ.get("DIGITAL_JAR")
    bridge = args.bridge_jar or os.environ.get(
        "BRIDGE_JAR", os.path.join(HERE, "java", "digbridge.jar"))
    env = dict(os.environ)
    if jar:
        env["DIGITAL_JAR"] = jar
    if bridge:
        env["BRIDGE_JAR"] = bridge
    return subprocess.run([sys.executable,
                           os.path.join(HERE, "doctor.py")],
                          env=env).returncode


def cmd_env(args):
    """What was run, on what, against which circuit."""
    from provenance import report, text, latex
    spec = _spec(args.cipher) if args.cipher else None
    outdir = _outdir(spec, args) if spec else None
    rep = report(outdir=outdir, cipher=spec["name"] if spec else None,
                 digital_jar=args.digital_jar
                 or os.environ.get("DIGITAL_JAR"))
    if args.latex:
        print(latex(rep))
    elif args.json:
        with open(args.json, "w") as fh:
            json.dump(rep, fh, indent=2, default=str)
        print(f"wrote {args.json}")
    else:
        print(text(rep))
    return 0


#: The suites, cheapest first.  Split by cost because a check nobody runs
#: protects nothing: `--quick` has to stay short enough to run before every
#: commit, and the NIST battery is far too slow for that.
SUITES = [
    ("cross-validation against Digital", "test_all.py", "quick", []),
    ("PRESENT against CLAASP's own model", "test_present_reference.py",
     "normal", []),
    ("randomised circuits", "test_fuzz.py", "normal",
     ["--cases", "30", "--stop-after", "2"]),
    ("the GUI serves and its stages run", "test_gui.py", "normal",
     ["--rounds", "2"]),
    ("optional features", "test_features.py", "full", []),
    ("cost, benchmarks, attacks", "test_analysis.py", "full", []),
    ("related key, diffusion, NIST", "test_statistical.py", "full",
     ["--nist"]),
]


def cmd_selftest(args):
    """
    Run the suites and say plainly whether this installation is sound.

    Worth running on a new machine before trusting a number out of it: the
    checks compare this toolchain against Digital's simulator and against
    CLAASP's own PRESENT, so a passing run is evidence about *your* install,
    not about the author's.
    """
    import subprocess
    import time

    jar, bridge = _env(args)
    levels = {"quick": 1, "normal": 2, "full": 3}
    want = levels[args.level]
    tests = os.path.join(HERE, "..", "tests")

    results, t0 = [], time.time()
    for label, script, level, extra in SUITES:
        if levels[level] > want:
            continue
        path = os.path.join(tests, script)
        if not os.path.exists(path):
            print(f"  SKIP  {label} ({script} not found)")
            continue
        cmd = [sys.executable, path, "--digital-jar", jar,
               "--bridge-jar", bridge] + extra
        t = time.time()
        r = subprocess.run(cmd, capture_output=True, text=True)
        dt = time.time() - t
        ok = r.returncode == 0
        results.append((label, ok, dt, r.stdout + r.stderr))
        print(f"  {'PASS' if ok else 'FAIL'}  {label}  [{dt:.0f}s]")
        if not ok and not args.quiet:
            tail = (r.stdout + r.stderr).strip().splitlines()[-12:]
            for line in tail:
                print(f"        {line}")

    failed = [r for r in results if not r[1]]
    print()
    print(f"  {len(results) - len(failed)}/{len(results)} suites passed "
          f"in {time.time() - t0:.0f}s")
    if failed:
        print("  This installation does not reproduce the reference "
              "results. Do not rely on figures from it until the failures "
              "above are resolved.")
        return 1
    print("  This installation reproduces the reference results.")
    return 0


def cmd_replicate(args):
    """
    Check somebody else's published characteristic against your own model.

    This is the case the whole toolchain is shaped around.  A paper reports a
    trail as a table of round differences and a probability; the search that
    produced it ran in somebody's own model, which nobody else has.  Copying
    the table into a CSV and running it here asks a different model, built
    from a schematic, whether the same path is realisable and costs the same.

    Agreement is real corroboration, because nothing was shared but the
    numbers in the paper. Disagreement localises itself: the round where the
    solver first refuses is the round to look at.

    The CSV wants a `round` column and one `delta_*` column per state
    variable, in hex. A `weight` column is used if present.
    """
    _preload()
    import csv as csvmod
    from claasp.cipher_modules.models.utils import (set_fixed_variables,
                                                    integer_to_bit_list)
    from claasp.cipher_modules.models.sat.sat_models \
        .sat_xor_differential_model import SatXorDifferentialModel

    spec = _spec(args.cipher)
    rows = list(csvmod.DictReader(open(args.trail)))
    if not rows:
        sys.exit(f"{args.trail} has no rows")

    delta_cols = [c for c in rows[0] if c.lower().startswith("delta")]
    if not delta_cols:
        sys.exit(f"{args.trail} has no delta_* column; expected one per "
                 f"state variable, in hex")

    def value(row):
        v = 0
        for c in delta_cols:
            w = spec["block_bits"] // len(delta_cols)
            v = (v << w) | int(str(row[c]).replace("0x", "").strip() or "0",
                               16)
        return v

    states = [value(r) for r in rows]
    rounds = args.rounds or (len(states) - 1)
    cipher = _load_cipher(spec, _outdir(spec, args), rounds)
    block, key = spec["block_bits"], spec["key_bits"]

    print(f"  {args.trail}: {len(states)} states, "
          f"replicating over {rounds} rounds of {spec['name']}")
    print(f"  input  difference {states[0]:#0{block // 4 + 2}x}")
    print(f"  output difference {states[-1]:#0{block // 4 + 2}x}")
    print()

    model = SatXorDifferentialModel(cipher)
    last = cipher.get_all_components_ids()[-1]
    fixed = [
        set_fixed_variables("key", "equal", list(range(key)), [0] * key),
        set_fixed_variables("plaintext", "equal", list(range(block)),
                            integer_to_bit_list(states[0], block, "big")),
        set_fixed_variables(last, "equal", list(range(block)),
                            integer_to_bit_list(states[-1], block, "big")),
    ]

    if args.pin_all:
        # Pin every intermediate state too. Narrower, and it tells you which
        # round disagrees rather than only that some round does.
        ids = [c for c in cipher.get_all_components_ids()
               if c.startswith("intermediate_output_")]
        for i, cid in enumerate(ids[:len(states) - 2]):
            fixed.append(set_fixed_variables(
                cid, "equal", list(range(block)),
                integer_to_bit_list(states[i + 1], block, "big")))

    sol = model.find_lowest_weight_xor_differential_trail(
        fixed_values=fixed, solver_name=args.solver)
    status, got = sol.get("status"), sol.get("total_weight")

    if status != "SATISFIABLE":
        print(f"  NOT REPLICATED: the solver reports {status}.")
        print("  This model has no characteristic joining those differences "
              "at all.")
        print("  Either the published trail assumes a different reading of "
              "the specification,")
        print("  or the circuit here does. Re-run with --pin-all to find "
              "the first round")
        print("  that disagrees.")
        return 1

    print(f"  REPLICATED: weight {got} (probability 2^-{got})")

    if args.show or args.export:
        from digtrail import Trail
        t = Trail.from_claasp(
            sol, cipher,
            name=f"{spec['name'].upper()}, {rounds} rounds"
                 + (" (published path pinned)" if args.pin_all else ""))
        if args.show:
            print()
            print(t.text(radix=args.radix))
        for path in args.export or []:
            try:
                t.save(path)
                print(f"  wrote {path}")
            except Exception as e:
                print(f"  could not write {path}: {e}")

    if args.expect_weight is not None:
        same = abs(got - args.expect_weight) < 1e-9
        print(f"  published weight {args.expect_weight} -> "
              f"{'MATCH' if same else 'DIFFERS'}")
        if not same:
            print(f"  A lighter weight here means this model finds a cheaper "
                  f"path than the one published; a heavier one means the "
                  f"published path is not optimal in this model, or the two "
                  f"models differ.")
    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"trail": args.trail, "rounds": rounds,
                       "weight": got, "expected": args.expect_weight,
                       "status": status}, fh, indent=2, default=str)
        print(f"  wrote {args.json}")
    return 0


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--digital-jar")
    ap.add_argument("--bridge-jar")
    ap.add_argument("--outdir")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="show the known ciphers")
    sub.add_parser("doctor",
                   help="check the environment and say what is missing")

    p = sub.add_parser("build", help="draw the circuits and extract netlists")
    p.add_argument("cipher")
    p.add_argument("--with-tests", action="store_true",
                   help="embed a Testcase component so Digital's F8 works "
                        "on the generated circuit")
    p.add_argument("--test-vectors", type=int, default=8,
                   help="how many vectors to embed")
    p.add_argument("--bit-order", choices=("lsb", "msb"),
                   help="which end of a word is bit 0; overrides the "
                        "cipher's own setting")

    p = sub.add_parser("verify", help="circuit vs reference vs vectors")
    p.add_argument("cipher")
    p.add_argument("--rounds", type=int)
    p.add_argument("--trials", type=int, default=8)
    p.add_argument("--seed", type=int, default=0)

    p = sub.add_parser("analyse", help="emit CLAASP and search for trails")
    p.add_argument("cipher")
    p.add_argument("--rounds", type=int)
    p.add_argument("--solver", default="KISSAT_EXT")
    p.add_argument("--no-search", action="store_true",
                   help="build the CLAASP object but do not solve")
    p.add_argument("--json", help="write the raw trail here")
    p.add_argument("--show", action="store_true",
                   help="print the trail round by round")
    p.add_argument("--radix", choices=("hex", "bin", "both"), default="hex")
    p.add_argument("--export", action="append", metavar="FILE",
                   help="write the trail as .svg .pdf .png .jpg .tex .tikz "
                        ".csv .json .md .txt; repeat for several")

    p = sub.add_parser("sbox", help="DDT and LAT of the cipher's S-boxes")
    p.add_argument("cipher")
    p.add_argument("--show", action="store_true")
    p.add_argument("--export", action="append", metavar="FILE")

    p = sub.add_parser("cluster",
                       help="sum the characteristics sharing one differential")
    p.add_argument("cipher")
    p.add_argument("--rounds", type=int)
    p.add_argument("--extra", type=int, default=0,
                   help="also count characteristics this much heavier")
    p.add_argument("--solver", default="KISSAT_EXT")
    p.add_argument("--json")

    p = sub.add_parser("impossible",
                       help="impossible differentials, or --linear for "
                            "zero correlation; proved by UNSAT")
    p.add_argument("cipher")
    p.add_argument("--rounds", type=int)
    p.add_argument("--cell-bits", type=int, default=4)
    p.add_argument("--linear", action="store_true")
    p.add_argument("--max-pairs", type=int)
    p.add_argument("--solver", default="KISSAT_EXT")
    p.add_argument("--json")

    p = sub.add_parser("bound",
                       help="is there a characteristic of weight w? "
                            "cheaper than minimising")
    p.add_argument("cipher")
    p.add_argument("--rounds", type=int)
    # PowerShell splits an unquoted 6,7,8,9 into four arguments before the
    # process ever sees it, so accept both that and a single "6,7,8,9".
    p.add_argument("--weights", nargs="+", default=["8", "12", "16", "20"],
                   help="weights to test; 8 12 16 or 8,12,16 both work")
    p.add_argument("--solver", default="KISSAT_EXT")

    p = sub.add_parser("cost", help="what the drawn circuit costs")
    p.add_argument("cipher")
    p.add_argument("--rounds", type=int)
    p.add_argument("--model", default="nangate45",
                   choices=("nangate45", "umc180", "nand_transistors"))
    p.add_argument("--word-bits", type=int, default=32)

    p = sub.add_parser("relatedkey",
                       help="single-key against related-key, side by side")
    p.add_argument("cipher")
    p.add_argument("--rounds", type=int)
    p.add_argument("--sweep", metavar="A,B",
                   help="run every round count in the range, so the gap can "
                        "be seen to widen or close")
    p.add_argument("--samples", type=int, default=500,
                   help="pairs used for the key-linearity check")
    p.add_argument("--solver", default="KISSAT_EXT")
    p.add_argument("--json")

    p = sub.add_parser("random",
                       help="avalanche and diffusion; --nist adds SP 800-22")
    p.add_argument("cipher")
    p.add_argument("--rounds", type=int)
    p.add_argument("--samples", type=int, default=200)
    p.add_argument("--nist", action="store_true",
                   help="also run the NIST battery (needs setup_nist.py)")
    p.add_argument("--test-type", default="avalanche",
                   choices=("avalanche", "correlation", "cbc", "random",
                            "low_density", "high_density"))
    p.add_argument("--bits", type=int, default=131072,
                   help="bits per sequence; NIST recommends >= 10^6")
    p.add_argument("--sequences", type=int, default=32,
                   help="sequences; NIST recommends >= 55")

    p = sub.add_parser("env",
                       help="versions and circuit digests, for a paper's "
                            "methodology section")
    p.add_argument("cipher", nargs="?")
    p.add_argument("--latex", action="store_true")
    p.add_argument("--json")

    p = sub.add_parser("selftest",
                       help="does this installation reproduce the reference "
                            "results?")
    p.add_argument("--level", choices=("quick", "normal", "full"),
                   default="normal")
    p.add_argument("--quiet", action="store_true")

    p = sub.add_parser("replicate",
                       help="check a published characteristic against your "
                            "own model")
    p.add_argument("cipher")
    p.add_argument("--trail", required=True, metavar="CSV",
                   help="round, delta_* columns in hex, optionally weight")
    p.add_argument("--rounds", type=int)
    p.add_argument("--expect-weight", type=float)
    p.add_argument("--pin-all", action="store_true",
                   help="pin every round, not just the endpoints")
    p.add_argument("--show", action="store_true",
                   help="print the round-by-round weights and active S-boxes")
    p.add_argument("--radix", choices=("hex", "bin", "both"), default="hex")
    p.add_argument("--export", action="append", metavar="FILE",
                   help="write the replicated trail as .svg .pdf .png .jpg "
                        ".tex .tikz .csv .json .md .txt; repeat for several")
    p.add_argument("--solver", default="KISSAT_EXT")
    p.add_argument("--json")

    p = sub.add_parser("bench",
                       help="published figures, grouped by environment")
    p.add_argument("--metric", default="area_ge")
    p.add_argument("--environment")
    p.add_argument("--cipher-filter")
    p.add_argument("--environments", action="store_true")
    p.add_argument("--cite", metavar="ENVIRONMENT")
    p.add_argument("--export", action="append", metavar="FILE")

    args = ap.parse_args()
    if getattr(args, "bit_order", None):
        os.environ["DIGBRIDGE_BIT_ORDER"] = args.bit_order
    return {"list": cmd_list, "doctor": cmd_doctor,
            "build": cmd_build, "verify": cmd_verify,
            "analyse": cmd_analyse, "sbox": cmd_sbox, "cluster": cmd_cluster,
            "impossible": cmd_impossible, "bound": cmd_bound,
            "cost": cmd_cost, "bench": cmd_bench, "env": cmd_env,
            "selftest": cmd_selftest, "replicate": cmd_replicate,
            "relatedkey": cmd_relatedkey,
            "random": cmd_random}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
