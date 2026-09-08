"""
digcost -- what a circuit costs, and what the literature says it costs.

    from digcost import estimate, BENCHMARKS, compare

    estimate(netlist)                       # from the drawing
    compare("PRESENT", metric="area")       # from the papers

Two very different things live here and they must not be confused:

  * `estimate()` counts what is actually on the schematic and applies a stated
    gate model.  It is reproducible and it is an estimate, not a synthesis
    result.  It will not match a real tool flow and does not try to.

  * `BENCHMARKS` holds figures copied out of published papers.  Each carries
    the paper, the process, the architecture and the tool, because without
    those a gate count means nothing.


WHY EVERY NUMBER CARRIES ITS ENVIRONMENT
----------------------------------------
Area and latency move by factors of two or three with the process library, the
architecture and the synthesis tool.  The LLBC proposal reports PRINCE at
8512 GE on a 0.18um library and 9874 GE on NanGate 45nm -- the same cipher,
the same paper, two numbers.  Round-based and fully unrolled implementations
of one design differ by an order of magnitude.  Serialised AES-128 has been
published anywhere from 1600 to 3400 GE depending on the datapath width.

So a bare table of gate counts across papers is not a comparison, it is a
category error.  Every entry here is tagged, `compare()` groups by environment
and refuses to rank across groups, and `cite()` prints the provenance so it
can go in a paper next to the number.

Nothing in this module is imported by build / verify / analyse.
"""

import json
import re
from collections import Counter, defaultdict

__all__ = ["estimate", "software_cost", "BENCHMARKS", "ENVIRONMENTS",
           "compare", "cite", "GATE_MODELS"]


# ==========================================================================
# Gate models
# ==========================================================================

#: Cost of each primitive, in gate equivalents (one GE = one 2-input NAND).
#:
#: Two models are offered because published papers use both and mixing them
#: silently is how incomparable numbers get compared.  Always say which one a
#: reported figure used.
GATE_MODELS = {
    "nangate45": {
        "note": "NanGate 45nm open cell library, the usual academic default",
        "source": "widely used in lightweight-cipher papers; the LLBC "
                  "proposal (IEEE IoT-J 12(21), 2025) reports its S-box and "
                  "unrolled figures on it",
        "NOT": 0.5, "AND": 1.5, "OR": 1.5, "NAND": 1.0, "NOR": 1.0,
        "XOR": 2.0, "XNOR": 2.0, "MUX": 2.5, "DFF": 4.5,
    },
    "umc180": {
        "note": "UMC 0.18um 1P6M, used for the older comparison tables",
        "source": "UMCL18G212T3 standard cell library",
        "NOT": 0.67, "AND": 1.33, "OR": 1.33, "NAND": 1.0, "NOR": 1.0,
        "XOR": 2.67, "XNOR": 2.67, "MUX": 2.33, "DFF": 6.0,
    },
    "nand_transistors": {
        "note": "transistor counts rather than gate equivalents",
        "source": "Table XIII of the LLBC proposal, which costs its key "
                  "recovery in these units",
        "NOT": 1, "AND": 2, "OR": 3, "NAND": 1, "NOR": 4,
        "XOR": 4, "XNOR": 5, "MUX": 6, "DFF": 12,
    },
}

#: An n-bit S-box implemented as a lookup table, in GE.  Real figures depend
#: entirely on the table: the LLBC proposal measures PRESENT's 4-bit S-box at
#: 24.33 GE and its own at 13.67 GE on the same library, a 1.8x spread.  These
#: are midpoints, and `estimate()` says so.
SBOX_GE = {2: 6.0, 3: 12.0, 4: 20.0, 5: 40.0, 6: 70.0, 8: 250.0}


def estimate(netlist, model="nangate45", sbox_ge=None, unrolled_rounds=1):
    """
    Cost the circuit from its netlist.

    This counts components and multiplies by a table.  It is reproducible and
    comparable against itself -- two designs costed the same way can be
    ranked -- and it is not a synthesis result.  Do not put it in a paper
    beside a figure from a tool flow without saying which is which.

    unrolled_rounds scales the round circuit to a fully unrolled design, which
    is what low-latency papers report; leave it at 1 for the round itself.
    """
    if model not in GATE_MODELS:
        raise ValueError(f"model must be one of {sorted(GATE_MODELS)}")
    m = GATE_MODELS[model]
    sbox_ge = sbox_ge or SBOX_GE

    kinds = Counter()
    bits = defaultdict(int)
    sboxes = []

    for c in netlist.components.values():
        t = c["type"]
        w = int(c["attrs"].get("Bits", 1) or 1)
        if t == "XOr":
            n_in = max(2, len(netlist.inputs_of(c["id"])))
            kinds["XOR"] += w * (n_in - 1)
            bits["XOR"] += w
        elif t in ("And", "Or", "NAnd", "NOr"):
            n_in = max(2, len(netlist.inputs_of(c["id"])))
            key = {"And": "AND", "Or": "OR",
                   "NAnd": "NAND", "NOr": "NOR"}[t]
            kinds[key] += w * (n_in - 1)
            bits[key] += w
        elif t == "Not":
            kinds["NOT"] += w
        elif t == "ROM":
            n = 1 << int(c["attrs"].get("AddrBits", 4) or 4)
            sboxes.append((c["attrs"].get("Label", "S"),
                           (n - 1).bit_length()))
        # Splitter, Const, Tunnel, In, Out: wiring only, no gates.

    gates = sum(kinds[k] * m.get(k, 0) for k in kinds)
    sbox_total = sum(sbox_ge.get(b, sbox_ge[4]) for _, b in sboxes)

    per_round = gates + sbox_total
    unit = "transistors" if model == "nand_transistors" else "GE"

    return {
        "model": model,
        "unit": unit,
        "model_note": m["note"],
        "model_source": m["source"],
        "gates": dict(kinds),
        "gate_cost": round(gates, 1),
        "sboxes": len(sboxes),
        "sbox_cost": round(sbox_total, 1),
        "per_round": round(per_round, 1),
        "rounds": unrolled_rounds,
        "total": round(per_round * unrolled_rounds, 1),
        "caveat": (
            "component count times a fixed per-gate cost. Not a synthesis "
            "result: no sharing, no technology mapping, no register cost. "
            "S-box cost is a midpoint -- measured 4-bit S-boxes range from "
            "13.67 GE (LLBC S1) to 24.33 GE (PRESENT) on one library."),
    }


def software_cost(netlist, word_bits=32, unrolled_rounds=1):
    """
    A rough cycle count for a software implementation.

    Counts the word operations a round needs on a `word_bits` machine: an
    XOR over a 64-bit state is two instructions on a 32-bit core, an S-box
    layer is one table lookup per cell plus the shifting to extract it.

    Deliberately crude.  Real figures depend on the instruction set, the
    compiler and whether the S-box is a table or bitsliced; the LLBC proposal
    measures AES-128 at 8616 cycles and TinyJAMBU at 4877 on the same
    STM32L475, which no static count would predict.  Use it to compare two
    designs costed the same way, not to predict a benchmark.
    """
    ops = Counter()
    for c in netlist.components.values():
        t = c["type"]
        w = int(c["attrs"].get("Bits", 1) or 1)
        words = max(1, -(-w // word_bits))
        if t == "XOr":
            n_in = max(2, len(netlist.inputs_of(c["id"])))
            ops["xor"] += words * (n_in - 1)
        elif t in ("And", "Or", "NAnd", "NOr", "Not"):
            ops["logic"] += words
        elif t == "ROM":
            ops["lookup"] += 1
            ops["shift_mask"] += 2      # extract the cell, place the result
        elif t == "Splitter":
            spec = str(c["attrs"].get("Output Splitting", ""))
            if re.fullmatch(r"\d+\s*,\s*\d+", spec):
                ops["rotate"] += words   # half of a rotation idiom
    cycles = (ops["xor"] + ops["logic"] + ops["lookup"] * 2
              + ops["shift_mask"] + ops["rotate"] * 2)
    return {
        "word_bits": word_bits,
        "ops": dict(ops),
        "cycles_per_round": cycles,
        "rounds": unrolled_rounds,
        "cycles_total": cycles * unrolled_rounds,
        "caveat": (
            "one cycle per word operation, table-based S-boxes, no pipelining "
            "or instruction-level parallelism. Compares two designs costed "
            "identically; does not predict a measured benchmark."),
    }


# ==========================================================================
# Published figures
# ==========================================================================

#: The measurement environments the tables below were produced in.  A number
#: only means something with one of these attached.
ENVIRONMENTS = {
    "llbc_nangate45_unrolled": {
        "kind": "ASIC",
        "process": "NanGate 45nm open cell library",
        "architecture": "fully unrolled (one block per clock)",
        "tool": "Synopsys Design Compiler A-2007.12-SP1",
        "source": "Y. Li, Y. Wei, E. Pasalic, L. Li, T. Fan, 'LLBC: A Novel "
                  "Feistel-Based Low-Latency Block Cipher for IoT "
                  "Applications', IEEE Internet of Things J. 12(21), Nov "
                  "2025, Table XIII",
        "caution": "figures for other ciphers are quoted from their own "
                   "papers, not re-synthesised, so tool versions differ",
    },
    "llbc_umc180_unrolled": {
        "kind": "ASIC",
        "process": "UMC L180 0.18um 1P6M (UMCL18G212T3)",
        "architecture": "fully unrolled",
        "tool": "Synopsys Design Compiler A-2007.12-SP1",
        "source": "LLBC proposal, Table XII",
    },
    "gift_stm90_roundbased": {
        "kind": "ASIC",
        "process": "STM 90nm",
        "architecture": "round-based (one round per clock)",
        "tool": "as reported by the GIFT designers",
        "source": "S. Banik et al., 'GIFT: A Small Present', CHES 2017, "
                  "implementation table",
        "caution": "the whole table was produced in one flow, so these "
                   "entries are comparable with each other -- which is "
                   "unusual and is why they are grouped separately",
    },
    "llbc_spartan6": {
        "kind": "FPGA",
        "device": "Xilinx Spartan-6",
        "architecture": "one round per clock",
        "source": "LLBC proposal, Table XI",
    },
    "llbc_artix7": {
        "kind": "FPGA",
        "device": "Xilinx Artix-7 (Nexys A7 board)",
        "architecture": "as reported",
        "source": "LLBC proposal, Table XI",
        "caution": "the LLBC rows on Spartan-6 and Artix-7 imply different "
                   "cycle counts (about 20 vs about 85 per block), so the "
                   "two are not the same implementation",
    },
    "llbc_stm32l475": {
        "kind": "software",
        "device": "STM32L475VET6 (Arm Cortex-M4)",
        "measure": "cycles for one block in ECB, assembly implementations",
        "source": "LLBC proposal, Table XV, methodology after FELICS",
    },
    "llbc_esp32s3": {
        "kind": "software",
        "device": "ESP32-S3",
        "measure": "cycles for one block",
        "source": "LLBC proposal, Table XV",
        "caution": "the ROM column of that table is around 140 kB for every "
                   "cipher and varies by under 1%, which is the whole "
                   "firmware image rather than the cipher's code size",
    },
    "llbc_sbox_nangate45": {
        "kind": "ASIC",
        "process": "NanGate 45nm",
        "architecture": "single S-box, area-optimised",
        "source": "LLBC proposal, Table VI",
    },
}

#: (cipher, environment) -> figures.  Keys are only comparable within one
#: environment; `compare()` enforces that.
BENCHMARKS = [
    # --- NanGate 45nm, fully unrolled (LLBC Table XIII) ------------------
    ("SCARF-10-240", "llbc_nangate45_unrolled",
     {"area_ge": 7370, "delay_ns": 2.26, "throughput_mbps": 4425}),
    ("LLLWBC-64-128", "llbc_nangate45_unrolled",
     {"area_ge": 8227, "delay_ns": 11.76, "throughput_mbps": 5443}),
    ("LLBC-128-128", "llbc_nangate45_unrolled",
     {"area_ge": 8485, "delay_ns": 2.79, "throughput_mbps": 45879}),
    ("PRINCE-64-128", "llbc_nangate45_unrolled",
     {"area_ge": 9874, "delay_ns": 4.06, "throughput_mbps": 15764}),
    ("PRINCEv2-64-128", "llbc_nangate45_unrolled",
     {"area_ge": 10333, "delay_ns": 4.08, "throughput_mbps": 15687}),
    ("Midori-64-128", "llbc_nangate45_unrolled",
     {"area_ge": 10676, "delay_ns": 4.94, "throughput_mbps": 12956}),
    ("QARMA5-64", "llbc_nangate45_unrolled",
     {"area_ge": 11825, "delay_ns": 4.02, "throughput_mbps": 15921}),
    ("QARMAv2-9-64", "llbc_nangate45_unrolled",
     {"area_ge": 12118, "delay_ns": 3.88, "throughput_mbps": 16495}),
    ("MANTIS5-64", "llbc_nangate45_unrolled",
     {"area_ge": 12661, "delay_ns": 4.48, "throughput_mbps": 14286}),
    ("SPEEDY-5-192", "llbc_nangate45_unrolled",
     {"area_ge": 27904, "delay_ns": 3.19}),
    ("Orthros", "llbc_nangate45_unrolled",
     {"area_ge": 31318, "delay_ns": 3.78, "throughput_mbps": 33863}),
    ("Gimli", "llbc_nangate45_unrolled",
     {"area_ge": 52039, "delay_ns": 4.54, "throughput_mbps": 84582}),

    # --- UMC 0.18um, fully unrolled (LLBC Table XII) ---------------------
    ("PRINCE-64-80", "llbc_umc180_unrolled",
     {"area_ge": 8512, "delay_ns": 13.00}),
    ("LLBC-128-128", "llbc_umc180_unrolled",
     {"area_ge": 11925, "delay_ns": 5.15, "throughput_mbps": 24854}),
    ("SKINNY-128-128", "llbc_umc180_unrolled",
     {"area_ge": 32415, "delay_ns": 97.93}),
    ("PRESENT-64-128", "llbc_umc180_unrolled", {"area_ge": 56722}),
    ("SAND-128-128", "llbc_umc180_unrolled",
     {"area_ge": 67620, "delay_ns": 25.79}),
    ("AES-128-128", "llbc_umc180_unrolled",
     {"area_ge": 71164, "delay_ns": 15.67}),

    # --- STM 90nm, round-based (GIFT, CHES 2017) -------------------------
    ("GIFT-64-128", "gift_stm90_roundbased",
     {"area_ge": 1345, "delay_ns": 1.83, "cycles": 29,
      "throughput_mbps": 1249, "power_uw": 74.8, "energy_pj": 216.9}),
    ("SIMON-64-128", "gift_stm90_roundbased",
     {"area_ge": 1458, "delay_ns": 1.83, "cycles": 45,
      "throughput_mbps": 795, "power_uw": 72.7, "energy_pj": 327.3}),
    ("SKINNY-64-128", "gift_stm90_roundbased",
     {"area_ge": 1477, "delay_ns": 1.84, "cycles": 37,
      "throughput_mbps": 966, "power_uw": 80.3, "energy_pj": 297.0}),
    ("PRESENT-64-128", "gift_stm90_roundbased",
     {"area_ge": 1560, "delay_ns": 1.63, "cycles": 33,
      "throughput_mbps": 1227, "power_uw": 71.1, "energy_pj": 234.6}),
    ("GIFT-128-128", "gift_stm90_roundbased",
     {"area_ge": 1997, "delay_ns": 1.85, "cycles": 41,
      "throughput_mbps": 1730, "power_uw": 116.6, "energy_pj": 478.1}),
    ("SIMON-128-128", "gift_stm90_roundbased",
     {"area_ge": 2064, "delay_ns": 1.87, "cycles": 69,
      "throughput_mbps": 1007, "power_uw": 105.6, "energy_pj": 728.6}),
    ("SKINNY-128-128", "gift_stm90_roundbased",
     {"area_ge": 2104, "delay_ns": 1.85, "cycles": 41,
      "throughput_mbps": 1730, "power_uw": 132.5, "energy_pj": 543.3}),

    # --- FPGA (LLBC Table XI) --------------------------------------------
    ("LLBC-128", "llbc_spartan6",
     {"luts": 833, "freq_mhz": 392, "throughput_mbps": 2572,
      "throughput_per_lut": 3.09}),
    ("ASCON-128", "llbc_spartan6",
     {"luts": 1402, "freq_mhz": 208, "throughput_mbps": 1906,
      "throughput_per_lut": 1.35}),
    ("GIFT-COFB-128", "llbc_spartan6",
     {"luts": 1960, "freq_mhz": 134, "throughput_mbps": 324,
      "throughput_per_lut": 0.16}),
    ("LLBC-128", "llbc_artix7",
     {"luts": 1063, "freq_mhz": 579, "throughput_mbps": 869,
      "throughput_per_lut": 0.82}),
    ("Elephant-160", "llbc_artix7",
     {"luts": 1717, "freq_mhz": 200, "throughput_mbps": 810,
      "throughput_per_lut": 0.47}),
    ("ASCON-128", "llbc_artix7",
     {"luts": 1790, "freq_mhz": 307, "throughput_mbps": 644,
      "throughput_per_lut": 0.36}),
    ("GIFT-COFB-128", "llbc_artix7",
     {"luts": 1932, "freq_mhz": 263, "throughput_mbps": 635,
      "throughput_per_lut": 0.33}),
    ("TinyJAMBU-128", "llbc_artix7",
     {"luts": 2044, "freq_mhz": 237, "throughput_mbps": 115,
      "throughput_per_lut": 0.06}),

    # --- software, Cortex-M4 (LLBC Table XV) -----------------------------
    ("LLBC-128", "llbc_stm32l475", {"cycles": 4725, "rom_bytes": 10800}),
    ("TinyJAMBU-128", "llbc_stm32l475",
     {"cycles": 4877, "rom_bytes": 10724}),
    ("AES-128", "llbc_stm32l475", {"cycles": 8616, "rom_bytes": 10896}),
    ("QARMAv2-64", "llbc_stm32l475", {"cycles": 8779, "rom_bytes": 11796}),
    ("ASCON-128", "llbc_stm32l475", {"cycles": 26704, "rom_bytes": 11172}),
    ("GIFT-COFB-128", "llbc_stm32l475",
     {"cycles": 43921, "rom_bytes": 10716}),
    ("LLLWBC-64", "llbc_stm32l475", {"cycles": 68982, "rom_bytes": 11280}),

    ("LLBC-128", "llbc_esp32s3", {"cycles": 5300}),
    ("TinyJAMBU-128", "llbc_esp32s3", {"cycles": 5346}),
    ("AES-128", "llbc_esp32s3", {"cycles": 7738}),
    ("ASCON-128", "llbc_esp32s3", {"cycles": 8864}),
    ("QARMAv2-64", "llbc_esp32s3", {"cycles": 42709}),
    ("GIFT-COFB-128", "llbc_esp32s3", {"cycles": 48772}),
    ("LLLWBC-64", "llbc_esp32s3", {"cycles": 88355}),

    # --- individual S-boxes (LLBC Table VI) ------------------------------
    ("LLBC-S1", "llbc_sbox_nangate45", {"area_ge": 13.67, "delay_ns": 0.12}),
    ("LLBC-S2", "llbc_sbox_nangate45", {"area_ge": 14.67, "delay_ns": 0.12}),
    ("Midori-sb0", "llbc_sbox_nangate45",
     {"area_ge": 13.3, "delay_ns": 0.24}),
    ("Midori-sb1", "llbc_sbox_nangate45",
     {"area_ge": 15.33, "delay_ns": 0.32}),
    ("PRINCE", "llbc_sbox_nangate45", {"area_ge": 16, "delay_ns": 0.36}),
    ("QARMAv2", "llbc_sbox_nangate45", {"area_ge": 23, "delay_ns": 0.61}),
    ("PRESENT", "llbc_sbox_nangate45",
     {"area_ge": 24.33, "delay_ns": 0.47}),
]

METRIC_LABELS = {
    "area_ge": ("area", "GE", False),
    "delay_ns": ("delay", "ns", False),
    "throughput_mbps": ("throughput", "Mbit/s", True),
    "throughput_per_lut": ("throughput/area", "Mbit/s per LUT", True),
    "luts": ("area", "LUTs", False),
    "freq_mhz": ("max frequency", "MHz", True),
    "cycles": ("cycles per block", "cycles", False),
    "rom_bytes": ("code size", "bytes", False),
    "power_uw": ("power", "uW", False),
    "energy_pj": ("energy per block", "pJ", False),
}


def environments(kind=None):
    return {k: v for k, v in ENVIRONMENTS.items()
            if kind is None or v["kind"] == kind}


def compare(metric="area_ge", environment=None, cipher=None):
    """
    Published figures for one metric, grouped by measurement environment.

    Grouping is not presentation: entries from different environments are not
    ranked against each other, because doing so is meaningless.  Ask for one
    environment to get one table.
    """
    label, unit, higher_better = METRIC_LABELS.get(
        metric, (metric, "", False))
    groups = defaultdict(list)
    for name, env, vals in BENCHMARKS:
        if metric not in vals:
            continue
        if environment and env != environment:
            continue
        if cipher and cipher.lower() not in name.lower():
            continue
        groups[env].append((name, vals[metric], vals))

    out = []
    for env, rows in groups.items():
        rows.sort(key=lambda r: r[1], reverse=higher_better)
        out.append({"environment": env, "info": ENVIRONMENTS[env],
                    "metric": metric, "label": label, "unit": unit,
                    "rows": rows})
    return out


def cite(environment):
    """The provenance line to put beside a quoted number."""
    e = ENVIRONMENTS[environment]
    bits = [e["source"]]
    for k in ("process", "device", "architecture", "tool", "measure"):
        if k in e:
            bits.append(f"{k}: {e[k]}")
    if "caution" in e:
        bits.append(f"caution: {e['caution']}")
    return "\n".join(bits)


def table_text(metric="area_ge", environment=None, cipher=None):
    out = []
    for g in compare(metric, environment, cipher):
        e = g["info"]
        head = f"{g['label']} ({g['unit']}) -- {g['environment']}"
        out.append(head)
        out.append("-" * len(head))
        for k in ("process", "device", "architecture", "tool", "measure"):
            if k in e:
                out.append(f"  {k}: {e[k]}")
        out.append(f"  source: {e['source']}")
        if "caution" in e:
            out.append(f"  caution: {e['caution']}")
        out.append("")
        w = max(len(n) for n, _, _ in g["rows"])
        for name, v, _ in g["rows"]:
            out.append(f"    {name:<{w}}  {v:>10,.2f}".rstrip("0").rstrip(".")
                       if isinstance(v, float)
                       else f"    {name:<{w}}  {v:>10,}")
        out.append("")
    if not out:
        return (f"no published figures for {metric!r}"
                + (f" in {environment!r}" if environment else ""))
    out.append("Figures are quoted from the papers named above and were not "
               "re-measured here.")
    out.append("Entries from different environments are not comparable; that "
               "is why they are not ranked together.")
    return "\n".join(out)


def table_latex(metric="area_ge", environment=None, cipher=None):
    groups = compare(metric, environment, cipher)
    out = []
    for g in groups:
        e = g["info"]
        env_bits = " ".join(f"{k}: {e[k]}." for k in
                            ("process", "device", "architecture", "tool")
                            if k in e)
        out += ["\\begin{table}[t]", "\\centering",
                f"\\caption{{{g['label'].capitalize()} "
                f"({g['unit']}). {env_bits} Figures from \\cite{{}}; see "
                f"the source note.}}",
                "\\begin{tabular}{lr}", "\\toprule",
                f"Cipher & {g['label'].capitalize()} ({g['unit']}) \\\\",
                "\\midrule"]
        for name, v, _ in g["rows"]:
            val = f"{v:,.2f}".rstrip("0").rstrip(".") if isinstance(v, float) \
                else f"{v:,}"
            out.append(f"{name.replace('_', '-')} & {val} \\\\")
        out += ["\\bottomrule", "\\end{tabular}",
                f"\\\\[2pt]\\footnotesize {e['source']}",
                "\\end{table}", ""]
    return "\n".join(out)


def to_json():
    return json.dumps(
        {"environments": ENVIRONMENTS,
         "benchmarks": [{"cipher": n, "environment": e, **v}
                        for n, e, v in BENCHMARKS],
         "gate_models": GATE_MODELS}, indent=2)
