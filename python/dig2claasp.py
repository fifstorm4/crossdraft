"""
dig2claasp -- turn a Digital circuit into a CLAASP cipher.

    circuit.dig --[DigNetlist.java]--> circuit.json --[this file]--> CLAASP

    # outside Sage, no CLAASP needed: check the translation is faithful
    from dig2claasp import Netlist, evaluate
    nl = Netlist("subcell.json")
    evaluate(nl, {"x": 0x0123456789ABCDEF})

    # inside Sage
    sage: load("dig2claasp.py")
    sage: c = build_cipher("round.json")

The Java half exists because .dig stores wires as coordinates, not as a
netlist; it calls Digital's own NetList to resolve connectivity.  Everything
here is pure Python over the resulting JSON and knows nothing about geometry.


THE EVALUATOR IS THE POINT
--------------------------
evaluate() runs the netlist directly, without CLAASP, so the translation can
be checked against Digital's own simulator on the same circuit:

    java -cp Digital.jar CLI test -circ circuit.dig    # Digital's answer
    evaluate(nl, inputs)                               # ours

Only once those agree is it worth emitting a CLAASP object.  A mistranslated
CLAASP model is invisible: it still produces plausible differential trails,
with nothing to compare them against.


SUPPORTED SUBSET
----------------
Digital has around a hundred component types and almost none mean anything to
a differential model.  Anything outside this table is rejected by name rather
than silently mistranslated.

    In Out          circuit boundary        plaintext / key / cipher_output
    XOr             bitwise over the bus    add_XOR_component
    And Or Not      bitwise                 add_AND / add_OR / add_NOT
    NAnd NOr        bitwise                 the above followed by a NOT
    ROM             lookup table            add_SBOX_component
    Splitter        slicing and regrouping  re-slicing, or add_rotate
    Const           constant                add_constant_component
    Tunnel Text     annotation, no logic    --

Rejected loudly: flip-flops, registers, RAM, counters, clocks.  A cipher for
CLAASP has to be an unrolled DAG, one instance per round, because there is no
notion of time in a differential model.


TEST DATA NUMBER FORMAT
-----------------------
Measured against Digital's CLI, not inferred: decimal and 0x-prefixed hex are
accepted; bare hex ("C", "B") is rejected with "Error parsing the test data",
even though the GUI editor appears to take it.
"""

import json
import os
import re
from collections import defaultdict, deque

# Re-exported so callers that already import from here keep working.
from javacp import classpath          # noqa: F401


SUPPORTED = {
    "In", "Out", "XOr", "And", "Or", "Not", "NAnd", "NOr",
    "ROM", "Splitter", "Const", "Tunnel", "Testcase", "Text", "Rectangle",
}

SEQUENTIAL = {
    "D_FF", "JK_FF", "T_FF", "RS_FF", "Register", "Counter", "Clock",
    "RAMDualPort", "RAMSinglePort", "RAMSinglePortSel", "Monoflop",
    "D_FF_AS", "JK_FF_AS", "BlockRAMDualPort", "RegisterFile",
}

PASSIVE = {"Tunnel", "Testcase", "Text", "Rectangle"}


# --------------------------------------------------------------------------


def _pin_key(item):
    """
    Order pins the way Digital numbers them.

    Splitter ports are named after the bit range they carry -- "0", "3,4",
    "8-11", "0-63" -- and their order decides which bits go where.  Sorting
    those as strings puts "10" before "2" and silently transposes every word
    that passes through a splitter with more than ten ports, which is every
    64-bit bit-permutation.  Sort on the first bit index instead.

    Gate pins ("In_1", "In_2") get the same treatment on their trailing
    number; anything else falls back to its name.
    """
    name = item[0]

    m = re.fullmatch(r"(\d+)(?:[-,](\d+))?", name)
    if m:                      # splitter port: leading bit index
        return ("", int(m.group(1)))

    m = re.fullmatch(r"([A-Za-z_]+?)_?(\d+)", name)
    if m:                      # In_1, out_2, ...
        return (m.group(1).lower(), int(m.group(2)))

    return (name.lower(), -1)


def flatten(src, base_dir=None, digital_jar=None, bridge_jar=None,
            java="java", _depth=0):
    """
    Inline every `*.dig` used as a component, recursively.

    Digital lets a circuit be dropped into another as a single box, which is
    how a schematic stays readable: an S-box layer or a MixWord becomes one
    symbol instead of forty.  The netlist that comes back names those boxes by
    filename and says nothing about what is inside, so the translator has to
    open them and splice them in.

    Splicing means renaming.  Every component and net inside an instance gets
    a prefix, so two copies of the same sub-circuit stay distinct, and the
    instance's own pins are stitched to the parent's nets by matching the
    sub-circuit's In/Out labels against the box's pin names -- which is what
    Digital does too, and why a sub-circuit's ports have to be labelled.

    Returns a plain dict in the same shape DigNetlist emits, so everything
    downstream is unchanged.
    """
    if _depth > 16:
        raise RecursionError(
            "sub-circuits nested more than 16 deep; is one including itself?")

    raw = src if isinstance(src, dict) else json.load(open(src))
    if base_dir is None and not isinstance(src, dict):
        base_dir = os.path.dirname(os.path.abspath(src))

    subs = [c for c in raw["components"] if c["type"].endswith(".dig")]
    if not subs:
        return raw

    if not (digital_jar and bridge_jar):
        raise ValueError(
            f"{raw.get('circuit')} uses sub-circuits "
            f"({', '.join(sorted({c['type'] for c in subs}))}); flatten() "
            f"needs digital_jar and bridge_jar to extract them")

    comps = [c for c in raw["components"] if not c["type"].endswith(".dig")]
    nets = {n["id"]: {"id": n["id"], "labels": list(n["labels"]),
                      "pins": list(n["pins"])} for n in raw["nets"]}
    loose = list(raw.get("unconnected", []))

    for inst in subs:
        pfx = f"{inst['id']}$"
        path = os.path.join(base_dir or ".", inst["type"])
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"{raw.get('circuit')} uses {inst['type']}, which is not "
                f"next to it in {base_dir}")

        js = _extract_netlist(path, digital_jar, bridge_jar, java)
        inner = flatten(js, os.path.dirname(os.path.abspath(path)),
                        digital_jar, bridge_jar, java, _depth + 1)

        # Which outer net does each of the instance's pins sit on?
        outer = {}
        for nid, net in nets.items():
            for pin in list(net["pins"]):
                if pin["component"] == inst["id"]:
                    outer[pin["pin"]] = nid
                    net["pins"].remove(pin)

        inner_nets = {n["id"]: n for n in inner["nets"]}
        boundary = {}      # inner net id -> outer net id
        for c in inner["components"]:
            if c["type"] not in ("In", "Out"):
                continue
            label = c["attrs"].get("Label")
            if label is None:
                raise ValueError(
                    f"{inst['type']} has an unlabelled {c['type']}; a "
                    f"sub-circuit's ports must be labelled, because the label "
                    f"is what names the pin on the box")
            if label not in outer:
                continue          # port left unconnected by the parent
            for n in inner["nets"]:
                if any(p["component"] == c["id"] for p in n["pins"]):
                    boundary[n["id"]] = outer[label]

        for c in inner["components"]:
            if c["type"] in ("In", "Out") and c["attrs"].get("Label") in outer:
                continue          # replaced by the parent's net
            comps.append({"id": pfx + c["id"], "type": c["type"],
                          "attrs": c["attrs"]})

        for n in inner["nets"]:
            pins = [p for p in n["pins"]
                    if not (inner_nets and _is_boundary_pin(p, inner, outer))]
            pins = [{"component": pfx + p["component"], "pin": p["pin"],
                     "dir": p["dir"]} for p in pins]
            if not pins:
                continue
            target = boundary.get(n["id"])
            if target is not None:
                nets[target]["pins"].extend(pins)
            else:
                nid = pfx + n["id"]
                nets[nid] = {"id": nid,
                             "labels": [pfx + x for x in n["labels"]],
                             "pins": pins}

        for u in inner.get("unconnected", []):
            loose.append({**u, "component": pfx + u["component"]})

    return {"circuit": raw.get("circuit", "?"),
            "components": comps,
            "nets": list(nets.values()),
            "unconnected": loose}


def _is_boundary_pin(pin, inner, outer):
    """True for a pin belonging to an In/Out that the parent has taken over."""
    for c in inner["components"]:
        if c["id"] == pin["component"] and c["type"] in ("In", "Out"):
            return c["attrs"].get("Label") in outer
    return False


def _extract_netlist(dig_path, digital_jar, bridge_jar, java="java"):
    """Run DigNetlist on a .dig and return the parsed JSON."""
    import subprocess
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        out = os.path.join(tmp, "n.json")
        r = subprocess.run(
            [java, "-cp", classpath(digital_jar, bridge_jar),
             "digbridge.DigNetlist", dig_path, out],
            capture_output=True, text=True)
        if r.returncode:
            raise RuntimeError(
                f"extracting {os.path.basename(dig_path)} failed:\n"
                f"{r.stderr}")
        return json.load(open(out))


class Netlist:
    """
    The JSON emitted by DigNetlist, indexed for traversal.

    Pass digital_jar/bridge_jar to inline any sub-circuits on the way in; a
    circuit that uses them is otherwise rejected, because a box whose contents
    are unknown cannot be translated.
    """

    def __init__(self, src, digital_jar=None, bridge_jar=None, java="java"):
        raw = src if isinstance(src, dict) else json.load(open(src))
        if any(c["type"].endswith(".dig") for c in raw["components"]):
            raw = flatten(src, None, digital_jar, bridge_jar, java)
        self.name = raw.get("circuit", "?")
        self.components = {c["id"]: c for c in raw["components"]}
        self.nets = {n["id"]: n for n in raw["nets"]}
        self.unconnected = raw.get("unconnected", [])

        self.driver_of = {}
        self._ins = defaultdict(list)
        self._outs = defaultdict(list)
        for nid, net in self.nets.items():
            for p in net["pins"]:
                if p["dir"] == "output":
                    if nid in self.driver_of:
                        raise ValueError(
                            f"net {nid} is driven by both "
                            f"{self.driver_of[nid]} and "
                            f"{(p['component'], p['pin'])}")
                    self.driver_of[nid] = (p["component"], p["pin"])
                    self._outs[p["component"]].append((p["pin"], nid))
                else:
                    self._ins[p["component"]].append((p["pin"], nid))
        for cid in self.components:
            self._ins[cid].sort(key=_pin_key)
            self._outs[cid].sort(key=_pin_key)

    def inputs_of(self, cid):
        return self._ins[cid]

    def outputs_of(self, cid):
        return self._outs[cid]

    def by_type(self, t):
        return [c for c in self.components.values() if c["type"] == t]

    def labelled(self, t):
        return {c["attrs"].get("Label"): c for c in self.by_type(t)}


# --------------------------------------------------------------------------
# Attributes
# --------------------------------------------------------------------------

def bits_of(comp, default=1):
    for k in ("Bits", "bits"):
        if k in comp["attrs"]:
            return int(comp["attrs"][k])
    return default


def const_value(comp):
    v = str(comp["attrs"].get("Value", "0"))
    return int(v, 16) if v.lower().startswith("0x") else int(v)


def sbox_table(comp):
    raw = str(comp["attrs"].get("Data", ""))
    out = []
    for t in re.split(r"[,\s]+", raw.strip()):
        if t:
            out.append(int(t, 16) if t.lower().startswith("0x") else int(t))
    return out


def parse_splitting(spec, total_bits):
    """
    Digital's splitter notation:

        "4,2,2"     ports of 4, 2 and 2 bits, taken in order
        "4*16"      sixteen ports of 4 bits
        "4-7,0-3"   explicit ranges in any order -- this is what lets a
                    splitter pair express a rotation

    Returns one list of bit indices per port.
    """
    spec = (spec or "").strip()
    if not spec:
        return [list(range(total_bits))]
    ports, cursor = [], 0
    for part in spec.split(","):
        part = part.strip()
        m = re.fullmatch(r"(\d+)\s*\*\s*(\d+)", part)
        if m:
            w, n = int(m.group(1)), int(m.group(2))
            for _ in range(n):
                ports.append(list(range(cursor, cursor + w)))
                cursor += w
            continue
        m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", part)
        if m:
            lo, hi = int(m.group(1)), int(m.group(2))
            ports.append(list(range(lo, hi + 1)))
            cursor = max(cursor, hi + 1)
            continue
        if re.fullmatch(r"\d+", part):
            w = int(part)
            ports.append(list(range(cursor, cursor + w)))
            cursor += w
            continue
        raise ValueError(f"cannot parse splitter spec {part!r}")
    return ports



def port_index(spec, pin_name):
    """
    Which port of a splitter spec a pin name refers to.

    Digital names a splitter port after the bit range it carries -- "0-3",
    "4-11", "7" -- so the name determines the port outright.  Matching by
    position instead works only while every port is wired: leave one end of a
    slice dangling, as every rotation and every wide register does, and the
    remaining names shift down onto the wrong bits.  Silently, and only in
    the value.
    """
    for i, positions in enumerate(parse_splitting(spec, 0)):
        lo, hi = positions[0], positions[-1]
        if pin_name == (str(lo) if lo == hi
                        else f"{lo},{hi}" if hi == lo + 1
                        else f"{lo}-{hi}"):
            return i
    return None


def splitter_ports(comp):
    """(input port bit-lists, output port bit-lists, total width)."""
    a = comp["attrs"]
    ins = parse_splitting(a.get("Input Splitting"), 0)
    outs = parse_splitting(a.get("Output Splitting"), 0)
    total = max(max(p) for p in ins + outs) + 1
    return ins, outs, total


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def check(nl, allow_unconnected=False):
    problems = []
    for c in nl.components.values():
        t = c["type"]
        if t in SUPPORTED or t.endswith(".dig"):
            continue
        why = ("sequential -- draw the rounds unrolled, one instance per round"
               if t in SEQUENTIAL else "not in the supported subset")
        problems.append(f"    {t}: {why}")
    if problems:
        raise NotImplementedError(
            f"circuit '{nl.name}' uses components this translator does not "
            "model:\n" + "\n".join(sorted(set(problems))))

    # A splitter output nobody uses is normal: cutting bits [5,20) out of a
    # word necessarily leaves the two ends dangling, and slicing is how every
    # rotation and every wide register is built.  A dangling pin anywhere
    # else is the most common circuit mistake and is invisible in the .dig
    # file, so it still stops the translation.
    loose = [u for u in nl.unconnected
             if not (nl.components[u["component"]]["type"] == "Splitter"
                     and u["dir"] == "output")]
    if loose and not allow_unconnected:
        detail = ", ".join(f"{u['component']}.{u['pin']}" for u in loose[:8])
        raise ValueError(
            f"{len(loose)} pin(s) are not wired: {detail}. An unwired pin is "
            "invisible in the .dig file and is the most common circuit "
            "mistake; fix it before translating. (Unused splitter *outputs* "
            "are allowed -- slicing a word always leaves ends over.)")
    return True


def topo_order(nl):
    indeg = {c: 0 for c in nl.components}
    succ = defaultdict(list)
    for cid in nl.components:
        for _, nid in nl.inputs_of(cid):
            drv = nl.driver_of.get(nid)
            if drv:
                succ[drv[0]].append(cid)
                indeg[cid] += 1
    q = deque(c for c, d in indeg.items() if d == 0)
    order = []
    while q:
        c = q.popleft()
        order.append(c)
        for s in succ[c]:
            indeg[s] -= 1
            if indeg[s] == 0:
                q.append(s)
    if len(order) != len(nl.components):
        stuck = [c for c in nl.components if c not in set(order)]
        raise ValueError(f"combinational loop involving {stuck[:5]}")
    return order


# --------------------------------------------------------------------------
# Evaluator -- runs the netlist without CLAASP, for cross-checking
# --------------------------------------------------------------------------

def evaluate(nl, inputs, trace=False):
    """
    Evaluate the circuit on integer inputs keyed by In label; returns
    {out label: int}.  Compare with Digital's own simulator on the same
    vectors: agreement is what licences the CLAASP translation.
    """
    check(nl)
    order = topo_order(nl)
    val, width = {}, {}

    for label, comp in nl.labelled("In").items():
        if label not in inputs:
            raise KeyError(f"no value supplied for input {label!r}")
        outs = nl.outputs_of(comp["id"])
        if outs:
            b = bits_of(comp, 1)
            val[outs[0][1]] = inputs[label] & ((1 << b) - 1)
            width[outs[0][1]] = b

    for cid in order:
        comp = nl.components[cid]
        t = comp["type"]
        if t in PASSIVE or t in ("In", "Out"):
            continue

        src, missing = [], False
        for _, nid in nl.inputs_of(cid):
            if nid not in val:
                missing = True
                break
            src.append((val[nid], width.get(nid, 1)))
        if missing and t != "Const":
            continue

        if t == "Const":
            b = bits_of(comp, 1)
            res = [(const_value(comp) & ((1 << b) - 1), b)]

        elif t in ("XOr", "And", "Or", "NAnd", "NOr"):
            b = bits_of(comp, max((w for _, w in src), default=1))
            acc = src[0][0]
            for v, _ in src[1:]:
                if t == "XOr":
                    acc ^= v
                elif t in ("And", "NAnd"):
                    acc &= v
                else:
                    acc |= v
            if t in ("NAnd", "NOr"):
                acc = ~acc
            res = [(acc & ((1 << b) - 1), b)]

        elif t == "Not":
            b = bits_of(comp, src[0][1])
            res = [((~src[0][0]) & ((1 << b) - 1), b)]

        elif t == "ROM":
            table = sbox_table(comp)
            db = bits_of(comp, 4)
            addr = src[0][0] if src else 0
            res = [(table[addr % len(table)] & ((1 << db) - 1), db)]

        elif t == "Splitter":
            ins_spec, outs_spec, _ = splitter_ports(comp)
            in_spec = str(comp["attrs"].get("Input Splitting", ""))
            out_spec = str(comp["attrs"].get("Output Splitting", ""))
            bundle = 0
            for (pin, _), (v, _) in zip(nl.inputs_of(cid), src):
                idx = port_index(in_spec, pin)
                if idx is None:
                    continue
                for k, bitpos in enumerate(ins_spec[idx]):
                    if (v >> k) & 1:
                        bundle |= 1 << bitpos
            res = []
            for pin, _ in nl.outputs_of(cid):
                idx = port_index(out_spec, pin)
                positions = outs_spec[idx] if idx is not None else []
                o = 0
                for k, bitpos in enumerate(positions):
                    if (bundle >> bitpos) & 1:
                        o |= 1 << k
                res.append((o, len(positions)))

        else:
            raise NotImplementedError(f"evaluator has no rule for {t!r}")

        for (_, nid), (v, w) in zip(nl.outputs_of(cid), res):
            val[nid] = v
            width[nid] = w
        if trace:
            print(f"  {cid:4s} {t:9s} -> "
                  + ", ".join(f"0x{v:X}" for v, _ in res))

    result = {}
    for label, comp in nl.labelled("Out").items():
        i = nl.inputs_of(comp["id"])
        if i and i[0][1] in val:
            result[label] = val[i[0][1]] & ((1 << bits_of(comp, 1)) - 1)
    return result



# --------------------------------------------------------------------------
# Iteration -- draw one round, run N
# --------------------------------------------------------------------------

class RoundSpec:
    """
    How a one-round circuit loops, read off the schematic itself.

    Almost every block cipher is the same round applied N times, so drawing
    twenty of them is wasted work and twenty chances to mis-wire one.  Draw
    one; the round count belongs to the analysis, not to the picture.

    The loop is declared by naming, so the schematic still says what it does
    without a separate config file:

        In "L" paired with Out "L'"   ->  L is state, fed to the next round
        In "rk" with no matching Out  ->  rk is a per-round argument

    Either "X'" or "X_next" is accepted as the partner of "X".
    """

    def __init__(self, nl):
        self.nl = nl
        ins = {k: v for k, v in nl.labelled("In").items() if k}
        outs = {k: v for k, v in nl.labelled("Out").items() if k}

        self.state, self.state_out = [], {}
        for name in ins:
            for suffix in ("'", "_next"):
                if name + suffix in outs:
                    self.state.append(name)
                    self.state_out[name] = name + suffix
                    break
        self.params = [k for k in ins if k not in self.state_out]
        self.extra_out = [k for k in outs
                          if k not in self.state_out.values()]

        if not self.state:
            raise ValueError(
                "no state variable found: a round circuit needs an In 'X' "
                "paired with an Out \"X'\" (or 'X_next'). "
                f"inputs={sorted(ins)} outputs={sorted(outs)}")

        self.bits = {n: bits_of(ins[n], 64) for n in ins}

    def __repr__(self):
        return (f"<RoundSpec state={self.state} params={self.params}"
                + (f" extra_out={self.extra_out}>" if self.extra_out else ">"))


def iterate(nl, rounds, state, params=None, spec=None, trace=False):
    """
    Run a one-round netlist `rounds` times, threading the state variables.

    params(i) -> {name: value} supplies the per-round arguments: round keys,
    round constants, anything that differs between rounds.

    Returns the final state dict.  Use this to check a full cipher against the
    test vectors in its specification without ever drawing more than one
    round -- which is also the only way to check twenty rounds at all, since
    Digital can only simulate what is on the canvas.
    """
    spec = spec or RoundSpec(nl)
    cur = dict(state)
    for i in range(rounds):
        args = dict(cur)
        if params:
            args.update(params(i))
        missing = [p for p in spec.params if p not in args]
        if missing:
            raise KeyError(f"round {i}: no value for {missing}")
        out = evaluate(nl, {k: args[k] for k in spec.bits if k in args})
        nxt = {n: out[spec.state_out[n]] for n in spec.state}
        if trace:
            shown = ", ".join(f"{n}=0x{nxt[n]:X}" for n in spec.state)
            print(f"  round {i:2d}: {shown}")
        cur = nxt
    return cur


# --------------------------------------------------------------------------
# Rotation recognition
# --------------------------------------------------------------------------

def find_rotations(nl):
    """
    Digital has no rotate primitive: a constant rotation is drawn as one
    splitter that cuts the word and a second that rejoins it swapped.
    Translating that literally emits 64 individual bit assignments per
    rotation, which bloats the SAT model badly over twenty rounds.

    Bit indices restart inside each splitter, so the specs cannot be compared
    directly -- A's high port "61-63" arrives at B as its own "0-2".  What
    identifies a rotation is the port widths being reversed AND the wires
    crossing; the same widths in the same order is a pass-through.

    Returns {splitter_a_id: (splitter_b_id, amount)}.
    """
    found = {}
    for a in nl.by_type("Splitter"):
        a_out = nl.outputs_of(a["id"])
        _, outs_a, _ = splitter_ports(a)
        if len(a_out) != 2 or len(outs_a) != 2:
            continue

        # Tunnels sit on the net as extra pins.  They carry no logic, so a
        # rotation drawn with tunnel connections would otherwise look like it
        # fans out to three components and be skipped.
        targets = set()
        for _, nid in a_out:
            for p in nl.nets[nid]["pins"]:
                if p["dir"] != "input":
                    continue
                if nl.components[p["component"]]["type"] in PASSIVE:
                    continue
                targets.add(p["component"])
        if len(targets) != 1:
            continue
        b_id = targets.pop()
        b = nl.components.get(b_id)
        if b is None or b["type"] != "Splitter":
            continue

        ins_b, _, _ = splitter_ports(b)
        wa = [len(p) for p in outs_a]
        if [len(p) for p in ins_b] != wa[::-1]:
            continue

        b_in = nl.inputs_of(b_id)
        if len(b_in) != 2:
            continue
        if not (a_out[0][1] == b_in[1][1] and a_out[1][1] == b_in[0][1]):
            continue          # not crossed: identity, not a rotation

        found[a["id"]] = (b_id, wa[1])
    return found


# --------------------------------------------------------------------------
# CLAASP emission
# --------------------------------------------------------------------------

def build_cipher(round_json, rounds=1, params=None, key_json=None,
                 key_params=None, key_map=None, key_extra=None,
                 final_key=None, family_name=None,
                 block_bits=None, key_bits=128):
    """
    Emit an N-round CLAASP cipher from a ONE-ROUND netlist.

    A block cipher is the same round applied N times, so the schematic holds
    one round and the round count is an argument here.  Drawing twenty rounds
    would be twenty chances to mis-wire one, and Digital could not simulate
    the result any better than it simulates one.

    The loop is read off the schematic by naming (see RoundSpec): an In "X"
    paired with an Out "X'" is state carried to the next round; an In without
    a partner is a per-round argument.

        round_json   the data-path round: state + round keys + constants
        rounds       how many times to apply it
        params(i)    -> {name: int} for the per-round arguments that are
                     constants; anything not returned here must come from the
                     key schedule
        key_json     optional one-step key-schedule netlist, iterated in step
                     with the data path
        key_params(i) -> {name: int} for the key schedule's own constants
        key_extra    {round input: key-schedule output} for a schedule that
                     emits its round key as an output rather than carrying it
                     as state, which is what PRESENT does
        final_key    key-schedule output to xor into the ciphertext after the
                     last round, for ciphers that whiten at the end
        key_map      {round input: key-schedule state} -- the round calls its
                     subkeys "rk_lo"/"rk_hi" while the schedule calls its
                     registers "k0"/"k1", and only the designer knows which is
                     which, so the correspondence is stated rather than
                     guessed from names

    Run cross_check() and iterate() first.  A CLAASP model that disagrees with
    Digital still produces trails, and they are wrong in ways nothing else
    catches.
    """
    from claasp.cipher import Cipher
    from claasp.name_mappings import (BLOCK_CIPHER, INPUT_PLAINTEXT,
                                      INPUT_KEY)

    nl = Netlist(round_json)
    check(nl)
    spec = RoundSpec(nl)
    order = topo_order(nl)
    rotations = find_rotations(nl)
    rot_second = {b for b, _ in rotations.values()}

    knl = kspec = korder = None
    if key_json:
        knl = Netlist(key_json)
        check(knl)
        kspec = RoundSpec(knl)
        korder = topo_order(knl)

    state_bits = {n: spec.bits[n] for n in spec.state}
    total_block = block_bits or sum(state_bits[n] for n in spec.state)

    class DigCipher(Cipher):
        def __init__(self):
            super().__init__(
                family_name=family_name or nl.name.replace(".dig", ""),
                cipher_type=BLOCK_CIPHER,
                cipher_inputs=[INPUT_PLAINTEXT, INPUT_KEY],
                cipher_inputs_bit_size=[total_block, key_bits],
                cipher_output_bit_size=total_block,
            )

            # Slice the plaintext across the state variables, in the order
            # they appear on the schematic.
            cur, off = {}, 0
            for n in spec.state:
                w = state_bits[n]
                cur[n] = ([INPUT_PLAINTEXT], [list(range(off, off + w))])
                off += w

            kcur = {}
            if kspec:
                off = 0
                for n in kspec.state:
                    w = kspec.bits[n]
                    kcur[n] = ([INPUT_KEY], [list(range(off, off + w))])
                    off += w

            for r in range(rounds):
                self.add_round()

                supplied = dict(params(r)) if params else {}
                knext = None
                if kspec:
                    # Advance the schedule first and take its extra outputs
                    # from that same step: PRESENT reads the round key off
                    # the register *before* updating it, so the key the data
                    # path wants and the state it moves to come out together.
                    ksup = dict(key_params(r)) if key_params else {}
                    krots = find_rotations(knl)
                    knext, kextra = self._apply(
                        knl, korder, kspec, krots,
                        {b for b, _ in krots.values()}, kcur, ksup, r)
                    for round_in, sched_out in (key_extra or {}).items():
                        if sched_out not in kextra:
                            raise KeyError(
                                f"key_extra sends {round_in!r} to "
                                f"{sched_out!r}, which the key schedule does "
                                f"not output ({kspec.extra_out})")
                        supplied[round_in] = kextra[sched_out]
                    # Wire the schedule's registers to the round's subkey
                    # inputs.  Same-named signals pair up automatically; the
                    # rest need key_map, because "rk_hi" could be either
                    # register and nothing in the netlist says which.
                    for n in kspec.state:
                        if n in spec.params and n not in supplied:
                            supplied[n] = kcur[n]
                    for round_in, sched_state in (key_map or {}).items():
                        if sched_state not in kcur:
                            raise KeyError(
                                f"key_map sends {round_in!r} to "
                                f"{sched_state!r}, which is not a state of "
                                f"the key schedule ({kspec.state})")
                        supplied[round_in] = kcur[sched_state]

                cur, _ = self._apply(nl, order, spec, rotations, rot_second,
                                     cur, supplied, r)
                if knext is not None:
                    kcur = knext

                self.add_round_output_component(
                    sum((cur[n][0] for n in spec.state), []),
                    sum((cur[n][1] for n in spec.state), []),
                    total_block)

            ids = sum((cur[n][0] for n in spec.state), [])
            pos = sum((cur[n][1] for n in spec.state), [])
            if final_key and kspec:
                # One more step of the schedule supplies the whitening key.
                ksup = dict(key_params(rounds)) if key_params else {}
                krots = find_rotations(knl)
                _, kextra = self._apply(knl, korder, kspec, krots,
                                        {b for b, _ in krots.values()},
                                        kcur, ksup, rounds)
                wk = kextra[final_key]
                cid = self.add_XOR_component(ids + wk[0], pos + wk[1],
                                             total_block).id
                ids, pos = [cid], [list(range(total_block))]
            self.add_cipher_output_component(ids, pos, total_block)

        # ------------------------------------------------------------------

        def _apply(self, netlist_, order_, spec_, rots, rot2, state, extra,
                   round_index):
            """Emit one instance of a round netlist and return its new state."""
            op = {}
            ins = netlist_.labelled("In")
            for name, comp in ins.items():
                if not name:
                    continue
                outs = netlist_.outputs_of(comp["id"])
                if not outs:
                    continue
                nid = outs[0][1]
                if name in state:
                    op[nid] = state[name]
                elif name in extra:
                    v = extra[name]
                    if isinstance(v, tuple):
                        op[nid] = v
                    else:
                        w = spec_.bits[name]
                        cid = self.add_constant_component(w, v).id
                        op[nid] = ([cid], [list(range(w))])
                else:
                    raise KeyError(
                        f"round {round_index}: input {name!r} is neither "
                        f"state nor supplied; params must provide it")

            for cid in order_:
                comp = netlist_.components[cid]
                t = comp["type"]
                if t in PASSIVE or t in ("In", "Out") or cid in rot2:
                    continue
                src = [op[nid] for _, nid in netlist_.inputs_of(cid)
                       if nid in op]
                if not src and t != "Const":
                    continue

                if cid in rots:
                    b_id, amount = rots[cid]
                    # Width of the rotated word, taken from the splitter's
                    # own ports.  A key schedule rotating 16-bit words inside
                    # a 64-bit register would otherwise be emitted as a
                    # 64-bit rotation and silently produce the wrong answer.
                    size = sum(len(p) for p in splitter_ports(comp)[0])
                    res = [self._rot(src[0], amount, size)]
                    targets = netlist_.outputs_of(b_id)
                elif t == "XOr":
                    size = bits_of(comp, max(sum(len(p) for p in o[1])
                                             for o in src))
                    res, targets = [self._xor(src, size)], \
                        netlist_.outputs_of(cid)
                elif t == "ROM":
                    res, targets = [self._sbox(src[0], sbox_table(comp),
                                               bits_of(comp, 4))], \
                        netlist_.outputs_of(cid)
                elif t == "Const":
                    res, targets = [self._const(comp)], \
                        netlist_.outputs_of(cid)
                elif t == "Splitter":
                    res, targets = self._split(src, comp, netlist_, cid), \
                        netlist_.outputs_of(cid)
                elif t in ("And", "Or", "Not", "NAnd", "NOr"):
                    res, targets = [self._gate(t, src, bits_of(comp, 1))], \
                        netlist_.outputs_of(cid)
                else:
                    raise NotImplementedError(f"no CLAASP rule for {t!r}")

                for (_, nid), r in zip(targets, res):
                    op[nid] = r

            outs = netlist_.labelled("Out")
            new = {}
            for n in spec_.state:
                comp = outs[spec_.state_out[n]]
                i = netlist_.inputs_of(comp["id"])
                if not i or i[0][1] not in op:
                    raise ValueError(
                        f"output {spec_.state_out[n]!r} is not driven")
                new[n] = op[i[0][1]]

            # Outputs that are not state: a key schedule's round key is
            # produced each step and consumed by the data path, but is not
            # carried forward, so it belongs here rather than in the loop.
            extra = {}
            for n in spec_.extra_out:
                i = netlist_.inputs_of(outs[n]["id"])
                if i and i[0][1] in op:
                    extra[n] = op[i[0][1]]
            return new, extra

        def _xor(self, operands, size):
            ids, pos = [], []
            for o in operands:
                ids += o[0]
                pos += o[1]
            return ([self.add_XOR_component(ids, pos, size).id],
                    [list(range(size))])

        def _gate(self, t, operands, size):
            ids, pos = [], []
            for o in operands:
                ids += o[0]
                pos += o[1]
            if t in ("And", "NAnd"):
                cid = self.add_AND_component(ids, pos, size).id
            elif t in ("Or", "NOr"):
                cid = self.add_OR_component(ids, pos, size).id
            else:
                cid = self.add_NOT_component(ids, pos, size).id
            if t in ("NAnd", "NOr"):
                cid = self.add_NOT_component([cid], [list(range(size))],
                                             size).id
            return ([cid], [list(range(size))])

        def _sbox(self, operand, table, out_w):
            width = max(1, (len(table) - 1).bit_length())
            cid = self.add_SBOX_component(operand[0], operand[1],
                                          width, table).id
            return ([cid], [list(range(out_w))])

        def _const(self, comp):
            size = bits_of(comp, 1)
            cid = self.add_constant_component(size, const_value(comp)).id
            return ([cid], [list(range(size))])

        def _rot(self, operand, amount, size):
            # CLAASP takes a negative parameter for rotate-left, matching the
            # <<< of the usual cipher specifications.
            cid = self.add_rotate_component(operand[0], operand[1], size,
                                            -(amount % size)).id
            return ([cid], [list(range(size))])

        def _split(self, operands, comp, netlist_=None, cid=None):
            """
            A splitter is pure rewiring: no component, just re-slicing.

            The two sides number bits in opposite directions and the mismatch
            is silent.  Digital's splitter bundle counts from the LSB -- port
            bit k carries bundle bit positions[k] -- while a CLAASP operand
            lists its bit positions MSB first.  Feeding one straight into the
            other transposes every word: the data path still evaluates
            correctly because its splitters are symmetric, but a key schedule
            that slices a 64-bit register into 16-bit words comes out
            byte-reversed and only the final answer disagrees.

            So each port is reversed on the way in and on the way out.
            """
            ins_spec, outs_spec, _ = splitter_ports(comp)
            in_spec = str(comp["attrs"].get("Input Splitting", ""))
            out_spec = str(comp["attrs"].get("Output Splitting", ""))

            in_ports = ([port_index(in_spec, p) for p, _ in
                         netlist_.inputs_of(cid)] if netlist_ is not None
                        else list(range(len(ins_spec))))
            out_ports = ([port_index(out_spec, p) for p, _ in
                          netlist_.outputs_of(cid)] if netlist_ is not None
                         else list(range(len(outs_spec))))

            flat = {}
            for operand, idx in zip(operands, in_ports):
                positions = ins_spec[idx] if idx is not None else []
                pairs = [(cid, b) for cid, bits in zip(operand[0], operand[1])
                         for b in bits]
                # operand is MSB-first; the bundle is LSB-first.
                pairs = pairs[::-1]
                for k, bitpos in enumerate(positions):
                    if k < len(pairs):
                        flat[bitpos] = pairs[k]

            res = []
            for idx in out_ports:
                positions = outs_spec[idx] if idx is not None else []
                ids, pos = [], []
                for bitpos in reversed(positions):      # back to MSB-first
                    cid, b = flat[bitpos]
                    if ids and ids[-1] == cid and pos[-1][-1] == b - 1:
                        pos[-1].append(b)
                    else:
                        ids.append(cid)
                        pos.append([b])
                res.append((ids, pos))
            return res

    return DigCipher()


# --------------------------------------------------------------------------
# Cross-check against Digital itself
# --------------------------------------------------------------------------

def cross_check(dig_path, json_path, digital_jar, vectors, java="java",
                verbose=True):
    """
    Run the same vectors through Digital's simulator and through evaluate().

    vectors: list of ({in label: int}, {out label: int}).

    This is what makes the pipeline trustworthy.  Run it every time a
    component type is added: a bridge that drops or mis-wires something
    produces a CLAASP model that looks fine and analyses the wrong cipher.
    """
    import os
    import subprocess
    import tempfile

    nl = Netlist(json_path)

    ours_ok = True
    for inputs, expected in vectors:
        got = evaluate(nl, inputs)
        for k, v in expected.items():
            if got.get(k) != v:
                if verbose:
                    print(f"  MISMATCH {inputs} -> {k}: "
                          f"ours=0x{got.get(k, 0):X} want=0x{v:X}")
                ours_ok = False

    in_labels = sorted(nl.labelled("In"))
    out_labels = sorted(nl.labelled("Out"))
    lines = [" ".join(in_labels + out_labels)]
    for inputs, expected in vectors:
        row = [inputs[k] for k in in_labels] + [expected[k]
                                                for k in out_labels]
        lines.append(" ".join(f"0x{v:X}" for v in row))

    with tempfile.TemporaryDirectory() as tmp:
        tests = os.path.join(tmp, "tests.dig")
        src = open(dig_path).read()
        block = ('    <visualElement><elementName>Testcase</elementName>'
                 '<elementAttributes><entry><string>Testdata</string>'
                 '<testData><dataString>' + "\n".join(lines) +
                 '</dataString></testData></entry></elementAttributes>'
                 '<pos x="0" y="0"/></visualElement>\n  </visualElements>')
        open(tests, "w").write(
            src.replace("  </visualElements>", block))
        res = subprocess.run(
            [java, "-cp", digital_jar, "CLI", "test",
             "-circ", dig_path, "-tests", tests],
            capture_output=True, text=True)
        digital_ok = "passed" in res.stdout

    if verbose:
        print(f"  python evaluator : {'OK' if ours_ok else 'FAIL'}")
        print(f"  Digital simulator: {'OK' if digital_ok else 'FAIL'}")
        if not digital_ok:
            print("   ", res.stdout.strip().replace("\n", "\n    "))
    return ours_ok and digital_ok
