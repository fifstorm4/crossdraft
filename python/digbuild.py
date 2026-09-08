"""
digbuild -- write Digital .dig circuits from Python.

    from digbuild import Circuit
    c = Circuit()
    x = c.add("In",  Label="x", Bits=64)
    r = c.add("ROM", Bits=4, AddrBits=4, Data=[12, 5, 6, ...])
    c.connect((x, "out"), (r, "A"))
    c.write("sbox.dig", digital_jar="Digital.jar", bridge_jar="digbridge.jar")

WHY WIRING NEEDS A ROUND TRIP
-----------------------------
A .dig file records wires as bare coordinate pairs, so writing one means
knowing exactly where every pin sits.  Pin positions depend on the component
type, its rotation, its bit width and its input count, via shape rules that
live inside Digital.

Rather than reimplement those rules, write() does two passes: it emits the
components alone, asks Digital where the pins landed (DigNetlist --pins), and
only then emits the wires.  The geometry is never guessed, and the builder
cannot drift out of sync when Digital changes a shape.

The cost is that write() shells out to java twice.  That is fine for building
circuits; it would not be fine in a tight loop.


TEST DATA NUMBER FORMAT
-----------------------
Measured against Digital's own CLI, not inferred:

    decimal        accepted
    0x-prefixed    accepted
    bare hex       REJECTED -- "Error parsing the test data"

Bare hex looks like it works in the GUI editor but does not survive to the
command line, so testcase() always emits the 0x form.
"""

import json
import os
import re
import subprocess

import tempfile
from xml.sax.saxutils import escape

from javacp import classpath


class Component:
    __slots__ = ("index", "type", "attrs", "x", "y")

    def __init__(self, index, type_name, x, y, attrs):
        self.index = index
        self.type = type_name
        self.x = x
        self.y = y
        self.attrs = attrs

    @property
    def id(self):
        return f"c{self.index}"

    def __repr__(self):
        return f"<{self.type} {self.id} at ({self.x},{self.y})>"


# Attribute name -> XML element used for its value.  Digital's reader is
# strict about these: an int written as <string> is silently ignored.
_XML_TYPE = {
    "Bits": "int",
    "AddrBits": "int",
    "Inputs": "int",
    "Value": "long",
    "Label": "string",
    "NetName": "string",
    "Input Splitting": "string",
    "Output Splitting": "string",
    "rotation": "rotation",
    "intFormat": "intFormat",
    "Description": "string",
}


class Circuit:
    """A .dig circuit under construction."""

    def __init__(self, grid=20):
        self.components = []
        self.links = []          # ((comp, pin), (comp, pin))
        self.grid = grid
        self._x = 100
        self._y = 100

    # ---------------------------------------------------------------- build

    def add(self, type_name, x=None, y=None, **attrs):
        if x is None or y is None:
            x, y = self._x, self._y
            self._y += 80
            if self._y > 1200:
                self._y = 100
                self._x += 200
        x = self._snap(x)
        y = self._snap(y)
        if "Value" in attrs:
            attrs = dict(attrs)
            attrs["Value"] = self._signed64(int(attrs["Value"]),
                                            int(attrs.get("Bits", 64) or 64))
        c = Component(len(self.components), type_name, x, y, attrs)
        self.components.append(c)
        return c

    def connect(self, a, b):
        """Connect (component, pin) to (component, pin)."""
        self.links.append((a, b))

    def testcase(self, header, rows, x=None, y=None, label="t"):
        """
        header: list of signal names, e.g. ["x", "y"]
        rows:   list of int lists, one per test line

        Values are emitted as 0x hex because bare hex is rejected by the
        command-line test runner.
        """
        lines = [" ".join(header)]
        for r in rows:
            lines.append(" ".join(f"0x{v:X}" for v in r))
        return self.add("Testcase", x=x, y=y, Label=label,
                        Testdata="\n".join(lines))

    @staticmethod
    def split_pin(spec, index):
        """
        Name of a Splitter port.  Digital names each port after the bit range
        it carries -- "3", "3,4" or "3-63" -- not "in_0"/"out_2", so a builder
        has to derive the name from the splitting spec rather than guess it.

            split_pin("4*16", 2)  -> "8-11"
            split_pin("64", 0)    -> "0-63"
            split_pin("61,3", 1)  -> "61-63"
        """
        ports, cursor = [], 0
        for part in str(spec).split(","):
            part = part.strip()
            m = re.fullmatch(r"(\d+)\s*\*\s*(\d+)", part)
            if m:
                w, n = int(m.group(1)), int(m.group(2))
                for _ in range(n):
                    ports.append((cursor, w))
                    cursor += w
                continue
            m = re.fullmatch(r"(\d+)\s*-\s*(\d+)", part)
            if m:
                lo, hi = int(m.group(1)), int(m.group(2))
                ports.append((lo, hi - lo + 1))
                cursor = max(cursor, hi + 1)
                continue
            w = int(part)
            ports.append((cursor, w))
            cursor += w
        pos, bits = ports[index]
        if bits == 1:
            return str(pos)
        if bits == 2:
            return f"{pos},{pos + 1}"
        return f"{pos}-{pos + bits - 1}"

    def _snap(self, v):
        return int(round(v / self.grid) * self.grid)

    # ----------------------------------------------------------- emit + wire

    def _xml(self, wires=()):
        out = ['<?xml version="1.0" encoding="utf-8"?>', "<circuit>",
               "  <version>1</version>", "  <visualElements>"]
        for c in self.components:
            out.append("    <visualElement>")
            out.append(f"      <elementName>{escape(c.type)}</elementName>")
            out.append("      <elementAttributes>")
            for k, v in c.attrs.items():
                out.append(self._attr_xml(k, v))
            out.append("      </elementAttributes>")
            out.append(f'      <pos x="{c.x}" y="{c.y}"/>')
            out.append("    </visualElement>")
        out.append("  </visualElements>")
        out.append("  <wires>")
        for (x1, y1), (x2, y2) in wires:
            out.append(f'    <wire><p1 x="{x1}" y="{y1}"/>'
                       f'<p2 x="{x2}" y="{y2}"/></wire>')
        out.append("  </wires>")
        out.append("</circuit>")
        return "\n".join(out) + "\n"

    @staticmethod
    def _signed64(value, bits):
        """
        Digital stores a constant as a Java long, which is signed.

        A 64-bit value with its top bit set is larger than Long.MAX_VALUE, and
        XStream refuses the file outright -- the circuit does not load at all,
        with a NumberFormatException naming a number the user never typed.
        Writing the two's-complement form gives Digital the same 64 bits.
        """
        if bits >= 64 and value >= (1 << 63):
            return value - (1 << 64)
        return value

    @staticmethod
    def _attr_xml(key, value):
        if key == "Data":
            # A ROM table.  Digital stores it as <data> with comma-separated
            # values; the reader accepts decimal or hex digits.
            body = ",".join(f"{v:x}" for v in value)
            return (f"        <entry><string>Data</string>"
                    f"<data>{body}</data></entry>")
        if key == "Testdata":
            return ("        <entry><string>Testdata</string><testData>"
                    f"<dataString>{escape(str(value))}</dataString>"
                    "</testData></entry>")
        if key == "Value":
            return (f"        <entry><string>Value</string>"
                    f"<long>{value}</long></entry>")
        kind = _XML_TYPE.get(key, "string")
        if kind == "rotation":
            return (f"        <entry><string>{key}</string>"
                    f'<rotation rotation="{value}"/></entry>')
        if kind == "intFormat":
            return (f"        <entry><string>{key}</string>"
                    f"<intFormat>{value}</intFormat></entry>")
        return (f"        <entry><string>{escape(key)}</string>"
                f"<{kind}>{escape(str(value))}</{kind}></entry>")

    def _query_pins(self, xml_text, digital_jar, bridge_jar, java,
                    near=None):
        """
        Ask Digital where the pins ended up.

        The staging file is written beside the real output, not in a temp
        directory, because Digital resolves a sub-circuit component by looking
        for its .dig next to the circuit using it.  Staged somewhere else, a
        sub-circuit box comes back with no pins at all and the failure reads
        as "no pin 'x' on subcell.dig".
        """
        base = os.path.dirname(os.path.abspath(near)) if near else None
        with tempfile.TemporaryDirectory() as tmp:
            stage = os.path.join(base or tmp, ".digbuild_stage.dig")
            with open(stage, "w") as fh:
                fh.write(xml_text)
            res = subprocess.run(
                [java, "-cp", classpath(digital_jar, bridge_jar),
                 "digbridge.DigNetlist", "--pins", stage],
                capture_output=True, text=True)
            try:
                if res.returncode != 0:
                    raise RuntimeError(f"pin query failed:\n{res.stderr}")
                return json.loads(res.stdout)
            finally:
                if base and os.path.exists(stage):
                    os.remove(stage)

    def write(self, path, digital_jar, bridge_jar, java="java",
              wires=True):
        """
        Emit the circuit, resolving pin coordinates through Digital itself.

        Connections are drawn as wires by default, because the point of
        producing a .dig is that somebody can open it and read it. Pass
        wires=False to fall back on named tunnels, which is smaller on the
        canvas but shows no lines at all.

        Digital joins two wires only where an END POINT is shared. Crossings
        stay independent, so do overlapping collinear runs, and so does an
        endpoint landing partway along another wire. That is a far narrower
        rule than it looks, and it is what makes routing tractable: paths may
        cross each other freely, and the only thing to avoid is two different
        nets sharing a corner or a corner landing on a pin.

        Two passes, because the second needs what the first produced: emit
        the components alone and ask Digital where the pins landed, then emit
        the same components plus the wires between them.
        """
        pins = self._query_pins(self._xml(), digital_jar, bridge_jar, java,
                                near=path)
        index = {(p["component"], p["pin"]): (p["x"], p["y"]) for p in pins}
        direction = {(p["component"], p["pin"]): p["dir"] for p in pins}

        for (ca, pa), (cb, pb) in self.links:
            for comp, pin in ((ca, pa), (cb, pb)):
                if (comp.id, pin) not in index:
                    avail = sorted(k[1] for k in index if k[0] == comp.id)
                    raise KeyError(
                        f"no pin {pin!r} on {comp.type} ({comp.id}); "
                        f"available: {avail}")

        # Overlapping components put two pins on one point, which the
        # shared-endpoint rule then reads as one net. Builder's layout cannot
        # produce that; a hand-assembled circuit can, and the error would
        # otherwise surface far away as "net driven twice".
        placed = {}
        for c in self.components:
            if c.type in ("Text", "Rectangle", "Testcase"):
                continue
            if (c.x, c.y) in placed:
                other = placed[(c.x, c.y)]
                raise ValueError(
                    f"{c.type} ({c.id}) and {other.type} ({other.id}) are "
                    f"both at {(c.x, c.y)}. Overlapping components short "
                    f"their nets together; move one.")
            placed[(c.x, c.y)] = c

        nets = self._nets()

        if wires:
            segments = self._route_nets(nets, index, direction, pins)
            with open(path, "w") as fh:
                fh.write(self._xml(segments))
            return path

        return self._write_with_tunnels(path, nets, index, direction,
                                        digital_jar, bridge_jar, java)

    def _nets(self):
        """
        Group links into nets.

        A signal that fans out -- one constant feeding sixteen S-box select
        pins -- is a single net with seventeen pins, not sixteen links, and
        every branch has to leave from the same driver.
        """
        parent = {}

        def find(k):
            parent.setdefault(k, k)
            while parent[k] != k:
                parent[k] = parent[parent[k]]
                k = parent[k]
            return k

        for (ca, pa), (cb, pb) in self.links:
            ra, rb = find((ca.id, pa)), find((cb.id, pb))
            if ra != rb:
                parent[ra] = rb

        nets = {}
        for endpoint in sorted(parent):
            nets.setdefault(find(endpoint), []).append(endpoint)
        return list(nets.values())

    def _route_nets(self, nets, index, direction, pins):
        """
        Draw every net as Manhattan paths over a channel of its own.

        Each net gets one vertical x that no pin sits on and no other net
        uses. A branch then runs horizontally from the driver to that
        channel, vertically along it, and horizontally into the sink. The two
        corners are the only endpoints a branch introduces, and since the
        channel is unique to the net, no two nets can share one.

        Branches of the same net do share their corners, which is correct --
        they are the same signal.
        """
        pin_xs = {p["x"] for p in pins}
        used = set()
        segments = []

        def channel(lo, hi):
            """A free vertical line, preferably between the two pins."""
            mid = self._snap((lo + hi) // 2)
            for step in range(0, 400, self.grid):
                for cand in ((mid + step), (mid - step)):
                    if cand not in pin_xs and cand not in used:
                        used.add(cand)
                        return cand
            cand = max(pin_xs) + self.grid
            while cand in used:
                cand += self.grid
            used.add(cand)
            return cand

        for endpoints in nets:
            drivers = [e for e in endpoints
                       if direction.get(e) == "output"] or endpoints[:1]
            src = index[drivers[0]]
            sinks = [index[e] for e in endpoints if e != drivers[0]]
            if not sinks:
                continue

            lo = min([src[0]] + [s[0] for s in sinks])
            hi = max([src[0]] + [s[0] for s in sinks])
            cx = channel(lo, hi)

            for dst in sinks:
                if src[1] == dst[1] and src[0] == dst[0]:
                    continue
                if src[0] == dst[0] or src[1] == dst[1]:
                    segments.append((src, dst))
                    continue
                a, b = (cx, src[1]), (cx, dst[1])
                segments.append((src, a))
                segments.append((a, b))
                segments.append((b, dst))
        return segments

    def _write_with_tunnels(self, path, nets, index, direction,
                            digital_jar, bridge_jar, java):
        """
        The older scheme: connect by name instead of by line.

        Kept because it is immune to routing mistakes -- a tunnel cannot
        short against anything -- so it is somewhere to fall back to if a
        drawn circuit ever comes out wrong.
        """
        names = {}
        n_components = len(self.components)
        stubs = []
        for i, endpoints in enumerate(nets):
            for endpoint in endpoints:
                px, py = index[endpoint]
                dx = self.grid if direction[endpoint] == "output" \
                    else -self.grid
                t = self.add("Tunnel", x=px + dx, y=py, NetName=f"n{i}")
                stubs.append(((px, py), t))
                names[endpoint] = f"n{i}"

        seen = {}
        for _, t in stubs:
            if (t.x, t.y) in seen:
                raise ValueError(
                    f"two tunnels would sit at {(t.x, t.y)}; move the "
                    f"components further apart (grid={self.grid})")
            seen[(t.x, t.y)] = t

        pins2 = self._query_pins(self._xml(), digital_jar, bridge_jar, java,
                                 near=path)
        index2 = {(p["component"], p["pin"]): (p["x"], p["y"])
                  for p in pins2}

        wires = []
        for (px, py), tunnel in stubs:
            tp = [v for k, v in index2.items() if k[0] == tunnel.id]
            if not tp:
                raise RuntimeError(f"tunnel {tunnel.id} exposes no pin")
            wires.append(((px, py), tp[0]))

        with open(path, "w") as fh:
            fh.write(self._xml(wires))

        del self.components[n_components:]
        return path

    @staticmethod
    def _signed64(value, bits):
        """
        Digital stores a constant as a Java long, which is signed.

        A 64-bit value with its top bit set is larger than Long.MAX_VALUE, and
        XStream refuses the file outright -- the circuit does not load at all,
        with a NumberFormatException naming a number the user never typed.
        Writing the two's-complement form gives Digital the same 64 bits.
        """
        if bits >= 64 and value >= (1 << 63):
            return value - (1 << 64)
        return value

    @staticmethod
    def _attr_xml(key, value):
        if key == "Data":
            # A ROM table.  Digital stores it as <data> with comma-separated
            # values; the reader accepts decimal or hex digits.
            body = ",".join(f"{v:x}" for v in value)
            return (f"        <entry><string>Data</string>"
                    f"<data>{body}</data></entry>")
        if key == "Testdata":
            return ("        <entry><string>Testdata</string><testData>"
                    f"<dataString>{escape(str(value))}</dataString>"
                    "</testData></entry>")
        if key == "Value":
            return (f"        <entry><string>Value</string>"
                    f"<long>{value}</long></entry>")
        kind = _XML_TYPE.get(key, "string")
        if kind == "rotation":
            return (f"        <entry><string>{key}</string>"
                    f'<rotation rotation="{value}"/></entry>')
        if kind == "intFormat":
            return (f"        <entry><string>{key}</string>"
                    f"<intFormat>{value}</intFormat></entry>")
        return (f"        <entry><string>{escape(key)}</string>"
                f"<{kind}>{escape(str(value))}</{kind}></entry>")

    def _query_pins(self, xml_text, digital_jar, bridge_jar, java,
                    near=None):
        """
        Ask Digital where the pins ended up.

        The staging file is written beside the real output, not in a temp
        directory, because Digital resolves a sub-circuit component by looking
        for its .dig next to the circuit using it.  Staged somewhere else, a
        sub-circuit box comes back with no pins at all and the failure reads
        as "no pin 'x' on subcell.dig".
        """
        base = os.path.dirname(os.path.abspath(near)) if near else None
        with tempfile.TemporaryDirectory() as tmp:
            stage = os.path.join(base or tmp, ".digbuild_stage.dig")
            with open(stage, "w") as fh:
                fh.write(xml_text)
            res = subprocess.run(
                [java, "-cp", classpath(digital_jar, bridge_jar),
                 "digbridge.DigNetlist", "--pins", stage],
                capture_output=True, text=True)
            try:
                if res.returncode != 0:
                    raise RuntimeError(f"pin query failed:\n{res.stderr}")
                return json.loads(res.stdout)
            finally:
                if base and os.path.exists(stage):
                    os.remove(stage)
