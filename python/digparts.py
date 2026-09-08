"""
digparts -- cipher building blocks for Digital circuits.

Ciphers are built from a small number of shapes that recur everywhere: an
S-box layer, a rotation, a wide XOR, a Feistel swap.  Hand-placing the
splitters and coordinates for each one is where the mistakes come from, so
this wraps them.

    from digparts import Builder

    b = Builder()
    L  = b.inp("L", 64)
    R  = b.inp("R", 64)
    rk = b.inp("rk", 64)

    t  = b.xor(L, rk)
    s  = b.sbox_layer(b.rotl(t, 3), PRESENT_SBOX)
    b.out("L'", b.xor(R, s))
    b.out("R'", L)

    b.write("round.dig")

Every helper returns an opaque port that other helpers accept, so a cipher
reads as the equations in its specification rather than as wiring.  Layout is
automatic: components are placed in columns as they are created and connected
through tunnels, which join by name and therefore cannot short against a wire
that happens to pass through.


WHAT THE HELPERS EMIT
---------------------
    rotl(x, n)          two splitters, cut and rejoined swapped.  Digital has
                        no rotate primitive; dig2claasp recognises the pair
                        and emits one CLAASP rotate rather than 64 bit
                        assignments.
    sbox_layer(x, tbl)  a splitter, one ROM per cell, a merger.  Every ROM
                        needs its select pin held high, which the Builder
                        wires from a single shared constant.
    words / join        splitter and merger for slicing a register into
                        equal-width words, as key schedules do.

LOOP CONVENTION
---------------
A one-round circuit declares its loop by naming (see dig2claasp.RoundSpec):
an In "X" paired with an Out "X'" is state carried to the next round; an In
without a partner is a per-round argument.  Draw one round; the round count
belongs to the analysis.
"""

from digbuild import Circuit

SP = Circuit.split_pin


class Port:
    """A signal: the component and pin it comes from, plus its width."""

    __slots__ = ("comp", "pin", "bits")

    def __init__(self, comp, pin, bits):
        self.comp, self.pin, self.bits = comp, pin, bits

    def as_link(self):
        return (self.comp, self.pin)

    def __repr__(self):
        return f"<Port {self.comp.type}.{self.pin} {self.bits}b>"


class Wide:
    """
    A register wider than one Digital bus, carried as several ports.

    Digital's buses top out at 64 bits, but key registers do not: PRESENT-80
    rotates an 80-bit register by 61, SKINNY carries a 384-bit tweakey, and a
    256-bit key is ordinary.  Splitting by hand is where the mistakes are, so
    the pieces are kept together and the helpers below do the arithmetic.

    Words are held least significant first, matching how Digital numbers a
    splitter's ports, and `bits` is the width of the whole register.  Slicing
    and rotation are stated on the whole register; which word a bit lands in
    is not the caller's problem.
    """

    __slots__ = ("words", "bits")

    def __init__(self, words, bits):
        self.words = list(words)          # Ports, least significant first
        self.bits = bits

    @property
    def offsets(self):
        """Absolute bit offset of each word."""
        out, off = [], 0
        for w in self.words:
            out.append(off)
            off += w.bits
        return out

    def __repr__(self):
        return (f"<Wide {self.bits}b = "
                + " | ".join(str(w.bits) for w in reversed(self.words)) + ">")


class Builder:
    """
    A circuit under construction, with automatic placement.

    Components are laid out left to right in the order they are created, with
    a fresh column for each, so nothing overlaps and the tunnels the writer
    inserts have room.  Pass explicit x/y only if a hand-tuned picture matters.
    """

    #: How the helpers read a bit index.
    #:
    #: Specifications disagree about which end of a word is bit 0.  PRESENT
    #: numbers from the LSB -- its pLayer is stated as "input bit i moves to
    #: output bit 16i mod 63", counting up from the least significant end.
    #: Others index from the MSB, so that bit 0 is the leftmost digit when the
    #: value is written out.  Reading one convention as the other produces a
    #: working circuit computing the mirror-image function, which no test on a
    #: single layer will reveal.
    #:
    #: "lsb" is Digital's own convention and the default.  Set bit_order="msb"
    #: to write rotations and permutations the other way round; every helper
    #: converts, so a cipher's source can match its paper.
    BIT_ORDERS = ("lsb", "msb")

    def __init__(self, col_width=340, row_height=90, top=100,
                 bit_order="lsb"):
        if bit_order not in self.BIT_ORDERS:
            raise ValueError(
                f"bit_order must be one of {self.BIT_ORDERS}, got "
                f"{bit_order!r}")
        self.c = Circuit()
        self.bit_order = bit_order
        self.col_width = col_width
        self.row_height = row_height
        self.top = top
        self._x = 100
        self._one = None
        self._zero = None
        self._taken = set()

    # ------------------------------------------------------------ placement

    def _add(self, type_name, x, y, **attrs):
        """
        Place a component, moving it down until the spot is free.

        Two components on the same coordinate is not a cosmetic problem.  The
        writer routes every pin through a tunnel placed one grid step away,
        so overlapping components put two tunnels on the same point, Digital
        merges their nets, and the result is reported as "net driven twice" --
        far from the cause, and only in circuits that happen to use two of
        whatever collided.  Two constants did exactly this.

        Tracking the occupied cells here means the layout cannot produce that
        state at all, rather than detecting it afterwards.
        """
        step = max(self.row_height, 60)
        while (x, y) in self._taken:
            y += step
        self._taken.add((x, y))
        return self.c.add(type_name, x=x, y=y, **attrs)

    # --------------------------------------------------------- bit ordering

    def _bit(self, index, width):
        """Translate a bit index from the builder's convention to Digital's."""
        return index if self.bit_order == "lsb" else width - 1 - index

    def _amount(self, amount, width):
        """
        Translate a rotation amount.

        A left rotation counting from the LSB is a right rotation of the same
        size counting from the MSB: the bits move the same way, the labels
        run the other way.
        """
        amount %= width
        return amount if self.bit_order == "lsb" else (width - amount) % width

    # ------------------------------------------------------------ placement

    def _col(self, width=None):
        self._x += width or self.col_width
        return self._x

    @property
    def one(self):
        """
        A shared constant 1, for the select pin every ROM needs held high.

        Shared on purpose: one component feeding every S-box, rather than one
        per S-box, which keeps the drawing readable and the netlist small.
        """
        if self._one is None:
            self._one = self._add("Const", 100, self.top - 200,
                                   Value=1, Bits=1)
        return self._one

    # -------------------------------------------------------------- signals

    def inp(self, label, bits, y=None):
        n = len([1 for c in self.c.components if c.type == "In"])
        comp = self._add("In", 100,
                         y if y is not None else self.top + n * self.row_height,
                         Label=label, Bits=bits)
        return Port(comp, "out", bits)

    def out(self, label, port, y=None):
        n = len([1 for c in self.c.components if c.type == "Out"])
        comp = self._add("Out", self._x + self.col_width,
                         y if y is not None else self.top + n * self.row_height,
                         Label=label, Bits=port.bits)
        self.c.connect(port.as_link(), (comp, "in"))
        return comp

    def const(self, value, bits, y=None):
        """
        A constant.

        Each one gets its own row.  Stacking them on a fixed coordinate puts
        two Const components in the same place, and the writer then routes
        both through a tunnel at the same point -- so Digital merges the two
        nets and reads the result as one net with two drivers. The error
        surfaces as "net driven twice" with no hint that the cause is a
        duplicated position, and only appears once a circuit happens to use
        two constants.
        """
        n = sum(1 for c in self.c.components if c.type == "Const")
        comp = self._add(
            "Const", 100,
            y if y is not None else self.top - 300 - n * self.row_height,
            Value=value, Bits=bits)
        return Port(comp, "out", bits)

    # ------------------------------------------------------------ operators

    def xor(self, *ports, y=None):
        if not ports:
            raise ValueError("xor needs at least one input")
        bits = ports[0].bits
        for p in ports:
            if p.bits != bits:
                raise ValueError(
                    f"xor operands differ in width: {bits} vs {p.bits}")
        g = self._add("XOr", self._col(), y if y is not None else self.top,
                      Bits=bits, Inputs=len(ports))
        for i, p in enumerate(ports):
            self.c.connect(p.as_link(), (g, f"In_{i+1}"))
        return Port(g, "out", bits)

    def gate(self, kind, *ports, y=None):
        """kind: And, Or, NAnd, NOr."""
        bits = ports[0].bits
        g = self._add(kind, self._col(), y if y is not None else self.top,
                      Bits=bits, Inputs=len(ports))
        for i, p in enumerate(ports):
            self.c.connect(p.as_link(), (g, f"In_{i+1}"))
        return Port(g, "out", bits)

    def not_(self, port, y=None):
        g = self._add("Not", self._col(), y if y is not None else self.top,
                      Bits=port.bits)
        self.c.connect(port.as_link(), (g, "in"))
        return Port(g, "out", port.bits)

    def modadd(self, a, b, y=None):
        """
        Addition modulo 2^n -- the A in ARX.

        Digital's Add carries a `c_i` input and a `c_o` output. The carry in
        has to be tied low or the sum is undefined, and the carry out is
        discarded, which is exactly what addition modulo 2^n means: the
        overflow is thrown away rather than widening the word.

        Without this, Speck, LEA, HIGHT, Chaskey and every other ARX design
        cannot be drawn at all.
        """
        if a.bits != b.bits:
            raise ValueError(
                f"modadd operands differ in width: {a.bits} vs {b.bits}")
        g = self._add("Add", self._col(), y if y is not None else self.top,
                      Bits=a.bits)
        self.c.connect(a.as_link(), (g, "a"))
        self.c.connect(b.as_link(), (g, "b"))
        self.c.connect((self.zero, "out"), (g, "c_i"))
        return Port(g, "s", a.bits)

    @property
    def zero(self):
        """
        A shared constant 0, for the carry input every Add needs tied low.

        Shared for the same reason `one` is: one component feeding every
        adder keeps the drawing and the netlist small.
        """
        if self._zero is None:
            self._zero = self._add("Const", 100, self.top - 250,
                                   Value=0, Bits=1)
        return self._zero

    def rotl(self, port, amount, y=None):
        """
        Rotate left by a constant: cut the word in two and rejoin it swapped.

        Digital has no rotate component.  dig2claasp.find_rotations recognises
        this exact pair -- reversed port widths, wires crossed -- and emits one
        CLAASP rotate instead of a per-bit rewiring, which matters a great deal
        for SAT model size over twenty rounds.
        """
        n = port.bits
        amount = self._amount(amount, n)
        if amount == 0:
            return port
        a_spec, b_spec = f"{n-amount},{amount}", f"{amount},{n-amount}"
        y = y if y is not None else self.top
        x = self._col(self.col_width)
        a = self._add("Splitter", x, y,
                       **{"Input Splitting": str(n),
                          "Output Splitting": a_spec})
        b = self._add("Splitter", x + 200, y,
                       **{"Input Splitting": b_spec,
                          "Output Splitting": str(n)})
        self.c.connect(port.as_link(), (a, SP(str(n), 0)))
        self.c.connect((a, SP(a_spec, 0)), (b, SP(b_spec, 1)))
        self.c.connect((a, SP(a_spec, 1)), (b, SP(b_spec, 0)))
        self._col(200)
        return Port(b, SP(str(n), 0), n)

    def rotr(self, port, amount, y=None):
        return self.rotl(port, port.bits - (amount % port.bits), y=y)

    # ----------------------------------------------------------- structures

    def words(self, port, word_bits, y=None):
        """Slice a register into equal-width words; returns a list of Ports."""
        n = port.bits
        if n % word_bits:
            raise ValueError(f"{n} bits is not a multiple of {word_bits}")
        count = n // word_bits
        spec = f"{word_bits}*{count}"
        y = y if y is not None else self.top
        sp = self._add("Splitter", self._col(), y,
                        **{"Input Splitting": str(n),
                           "Output Splitting": spec})
        self.c.connect(port.as_link(), (sp, SP(str(n), 0)))
        ports = [Port(sp, SP(spec, i), word_bits) for i in range(count)]
        # Digital hands back the least significant word first.  Under "msb"
        # the caller expects words[0] to be the leading one, as a
        # specification writes w0 || w1 || w2 || w3.
        return ports if self.bit_order == "lsb" else ports[::-1]

    def join(self, ports, y=None):
        """Concatenate equal-width words back into one register."""
        word_bits = ports[0].bits
        count = len(ports)
        n = word_bits * count
        spec = f"{word_bits}*{count}"
        y = y if y is not None else self.top
        mg = self._add("Splitter", self._col(), y,
                        **{"Input Splitting": spec,
                           "Output Splitting": str(n)})
        order = ports if self.bit_order == "lsb" else list(ports)[::-1]
        for i, p in enumerate(order):
            if p.bits != word_bits:
                raise ValueError("join needs equal-width words")
            self.c.connect(p.as_link(), (mg, SP(spec, i)))
        return Port(mg, SP(str(n), 0), n)

    def sbox_layer(self, port, table, tag="S", y=None):
        """
        Apply one lookup table to every cell of the word.

        Each ROM's select pin has to be held high or its output floats and the
        whole layer silently reads as high-Z; the Builder wires them all from
        one shared constant so that cannot be forgotten.
        """
        cell = max(1, (len(table) - 1).bit_length())
        n = port.bits
        if n % cell:
            raise ValueError(
                f"a {len(table)}-entry table works on {cell}-bit cells, "
                f"which does not divide {n} bits")
        count = n // cell
        y = y if y is not None else self.top

        if count == 1:
            # One cell: the splitter and merger would each be a width-n port
            # in and the same width-n port out, which Digital treats as plain
            # wire. Both ends land on one net, the ROM drives it too, and the
            # result is reported as "net driven twice". Wire the ROM directly.
            rom = self._add("ROM", self._col(), y, Label=f"{tag}0",
                            Bits=cell, AddrBits=cell, Data=list(table))
            self.c.connect(port.as_link(), (rom, "A"))
            self.c.connect((self.one, "out"), (rom, "sel"))
            return Port(rom, "D", n)

        spec = f"{cell}*{count}"
        x = self._col()
        sp = self._add("Splitter", x, y,
                        **{"Input Splitting": str(n),
                           "Output Splitting": spec})
        mg = self._add("Splitter", x + 400, y,
                        **{"Input Splitting": spec,
                           "Output Splitting": str(n)})
        self.c.connect(port.as_link(), (sp, SP(str(n), 0)))
        for i in range(count):
            rom = self._add("ROM", x + 200, y + i * 80,
                             Label=f"{tag}{i}", Bits=cell, AddrBits=cell,
                             Data=list(table))
            self.c.connect((sp, SP(spec, i)), (rom, "A"))
            self.c.connect((self.one, "out"), (rom, "sel"))
            self.c.connect((rom, "D"), (mg, SP(spec, i)))
        self._col(400)
        return Port(mg, SP(str(n), 0), n)

    def permute(self, port, mapping, y=None):
        """
        Arbitrary bit permutation: output bit j takes input bit mapping[j].

        Emitted as a splitter to single bits and a merger, so a 64-bit
        permutation costs 64 wires.  Unavoidable -- Digital's splitter ranges
        cannot express a non-contiguous reordering -- and the reason a cipher
        whose diffusion is rotations rather than a bit permutation is far
        cheaper to draw and to solve.
        """
        n = port.bits
        if sorted(mapping) != list(range(n)):
            raise ValueError("mapping must be a permutation of 0..n-1")
        # Restate the mapping in Digital's LSB-first indexing.  Under "msb"
        # both the position being filled and the bit filling it are mirrored.
        if self.bit_order == "msb":
            mapping = [self._bit(mapping[self._bit(j, n)], n)
                       for j in range(n)]
        spec = f"1*{n}"
        y = y if y is not None else self.top
        x = self._col()
        sp = self._add("Splitter", x, y,
                        **{"Input Splitting": str(n),
                           "Output Splitting": spec})
        mg = self._add("Splitter", x + 300, y,
                        **{"Input Splitting": spec,
                           "Output Splitting": str(n)})
        self.c.connect(port.as_link(), (sp, SP(str(n), 0)))
        # mapping is stated the way specifications state a permutation:
        # output bit j takes input bit mapping[j].  So the wire runs from the
        # splitter port carrying input bit mapping[j] to the merger port that
        # becomes output bit j.  Getting this backwards still produces a valid
        # permutation -- the inverse one -- and nothing downstream notices.
        for j in range(n):
            self.c.connect((sp, SP(spec, mapping[j])), (mg, SP(spec, j)))
        self._col(300)
        return Port(mg, SP(str(n), 0), n)

    # ----------------------------------------------------- wide registers

    def wide_in(self, label, bits, word=64, y=None):
        """
        An input wider than one bus, as `label_0` (least significant) upward.

        Digital cannot carry more than 64 bits on a wire, so an 80-bit key
        arrives as two ports.  The loop convention still applies per port:
        pair `k_0` with `k_0'` and the round machinery threads both.
        """
        widths = []
        left = bits
        while left > 0:
            widths.append(min(word, left))
            left -= widths[-1]
        return Wide([self.inp(f"{label}_{i}", w, y=y)
                     for i, w in enumerate(widths)], bits)

    def wide_out(self, label, wide):
        """
        Emit the words of a wide register as outputs.

        A trailing prime or _next stays at the end of each word's name, so
        wide_in("k", 80) and wide_out("k'", ...) give k_0 / k_0' rather than
        k_0 / k'_0.  RoundSpec pairs state by that suffix, and putting it in
        the middle leaves the loop undeclared.
        """
        for suffix in ("'", "_next"):
            if label.endswith(suffix):
                base = label[: -len(suffix)]
                for i, w in enumerate(wide.words):
                    self.out(f"{base}_{i}{suffix}", w)
                return
        for i, w in enumerate(wide.words):
            self.out(f"{label}_{i}", w)

    def wide_slice(self, wide, lo, hi, y=None):
        """
        Bits [lo, hi) of the register, as one Port.

        The range may straddle a word boundary; the pieces are cut out and
        rejoined.  It may not exceed 64 bits, since the result is a bus.
        """
        if not 0 <= lo < hi <= wide.bits:
            raise ValueError(f"[{lo},{hi}) is not inside {wide.bits} bits")
        if hi - lo > 64:
            raise ValueError(
                f"a slice is a single bus and cannot exceed 64 bits; "
                f"[{lo},{hi}) is {hi - lo}")
        pieces = []
        for w, off in zip(wide.words, wide.offsets):
            a, b = max(lo, off), min(hi, off + w.bits)
            if a < b:
                pieces.append(self._cut(w, a - off, b - off, y=y))
        return pieces[0] if len(pieces) == 1 else self.join_bits(pieces, y=y)

    def wide_splice(self, wide, lo, port, y=None):
        """A copy of the register with bits [lo, lo+port.bits) replaced."""
        hi = lo + port.bits
        if hi > wide.bits:
            raise ValueError(f"[{lo},{hi}) runs past {wide.bits} bits")
        new, used = [], 0
        for w, off in zip(wide.words, wide.offsets):
            a, b = max(lo, off), min(hi, off + w.bits)
            if a >= b:
                new.append(w)
                continue
            parts = []
            if a > off:
                parts.append(self._cut(w, 0, a - off, y=y))
            parts.append(self._cut(port, used, used + (b - a), y=y)
                         if (b - a) != port.bits else port)
            used += b - a
            if b < off + w.bits:
                parts.append(self._cut(w, b - off, w.bits, y=y))
            new.append(parts[0] if len(parts) == 1
                       else self.join_bits(parts, y=y))
        return Wide(new, wide.bits)

    def wide_rotl(self, wide, amount, y=None):
        """
        Rotate the whole register left, across word boundaries.

        PRESENT-80's key schedule turns on an 80-bit rotation by 61, which no
        single Digital component can express.  Each output word is assembled
        from the one or two input runs that land in it.
        """
        n = wide.bits
        amount %= n
        if amount == 0:
            return wide
        out = []
        for off, w in zip(wide.offsets, wide.words):
            pieces, pos = [], 0
            while pos < w.bits:
                src = (off + pos - amount) % n
                # How far can we go before the source crosses a boundary?
                run = w.bits - pos
                for s_off, s_w in zip(wide.offsets, wide.words):
                    if s_off <= src < s_off + s_w.bits:
                        run = min(run, s_off + s_w.bits - src)
                        break
                run = min(run, n - src)
                pieces.append(self.wide_slice(wide, src, src + run, y=y))
                pos += run
            out.append(pieces[0] if len(pieces) == 1
                       else self.join_bits(pieces, y=y))
        return Wide(out, n)

    def wide_rotr(self, wide, amount, y=None):
        return self.wide_rotl(wide, wide.bits - (amount % wide.bits), y=y)

    def wide_xor(self, a, b, y=None):
        if a.bits != b.bits:
            raise ValueError("wide_xor operands differ in width")
        return Wide([self.xor(x, z, y=y) for x, z in zip(a.words, b.words)],
                    a.bits)

    def wide_const(self, value, bits, word=64, y=None):
        widths, left = [], bits
        while left > 0:
            widths.append(min(word, left))
            left -= widths[-1]
        out, off = [], 0
        for w in widths:
            out.append(self.const((value >> off) & ((1 << w) - 1), w, y=y))
            off += w
        return Wide(out, bits)

    def join_bits(self, ports, y=None):
        """
        Concatenate ports of any widths, least significant first.

        A single port is returned unchanged rather than wrapped in a splitter.
        A one-port merger would connect that port's pin twice -- once to the
        merger, once wherever it already went -- and Digital reads two drivers
        on a net as an error, which surfaces far from the cause.
        """
        if len(ports) == 1:
            return ports[0]
        total = sum(p.bits for p in ports)
        if total > 64:
            raise ValueError(f"{total} bits will not fit on one bus")
        spec = ",".join(str(p.bits) for p in ports)
        y = y if y is not None else self.top
        mg = self._add("Splitter", self._col(), y,
                        **{"Input Splitting": spec,
                           "Output Splitting": str(total)})
        for i, p in enumerate(ports):
            self.c.connect(p.as_link(), (mg, SP(spec, i)))
        return Port(mg, SP(str(total), 0), total)

    def _cut(self, port, lo, hi, y=None):
        """
        Bits [lo, hi) of a single port.

        The wanted range is the second output port when something sits below
        it and the first when nothing does -- Digital numbers a splitter's
        ports from the least significant end, so a leading zero-width piece
        does not exist and shifts every index that follows.
        """
        if lo == 0 and hi == port.bits:
            return port
        parts = [x for x in (lo, hi - lo, port.bits - hi) if x]
        spec = ",".join(str(x) for x in parts)
        index = 1 if lo else 0
        y = y if y is not None else self.top
        sp = self._add("Splitter", self._col(), y,
                        **{"Input Splitting": str(port.bits),
                           "Output Splitting": spec})
        self.c.connect(port.as_link(), (sp, SP(str(port.bits), 0)))
        return Port(sp, SP(spec, index), hi - lo)

    # -------------------------------------------------------------- testing

    def testcase(self, header, rows):
        return self.c.testcase(header, rows, x=100, y=self.top - 400)

    def write(self, path, digital_jar, bridge_jar, java="java"):
        return self.c.write(path, digital_jar, bridge_jar, java)
