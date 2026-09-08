"""
digtrail -- turn a CLAASP differential trail into something publishable.

    from digtrail import Trail
    t = Trail.from_claasp(trail, cipher, rounds=7)

    print(t.text())                  # round-by-round, for the terminal
    t.save("fig3.svg")               # activity grid
    t.save("fig3.pdf")               # same, via matplotlib
    t.save("table6.tex")             # LaTeX table of the propagation
    t.save("trail.csv")              # for further processing

Everything here is optional.  Nothing in the build / verify / analyse pipeline
imports it, and the only hard dependency is the standard library: SVG, LaTeX,
CSV, JSON and Markdown are written directly.  PDF, PNG and JPG go through
matplotlib if it is installed and raise a clear message if it is not, rather
than making every user carry a plotting stack to run a SAT search.


WHY AN ACTIVITY GRID
--------------------
Papers on differential cryptanalysis draw the same picture: rounds down the
side, S-box positions across, a mark where the box is active.  It is the one
view that makes the shape of a trail legible -- where the difference narrows
to a single nibble, where a round costs nothing because the branch entering
the round function is zero, whether the pattern repeats.  A wall of hex does
not show that; the grid does.

The hex and binary listings are for checking, not for looking at.  Both are
kept because a trail is quoted in papers as a table of differences, and
retyping those by hand is how transcription errors get into print.
"""

import csv
import io
import json
import os
import re

__all__ = ["Trail", "sbox_tables"]


# --------------------------------------------------------------------------

def _hex(value, bits):
    return f"{value:0{max(1, bits // 4)}x}"


def _bin(value, bits):
    return format(value, f"0{bits}b")


class Trail:
    """
    A differential characteristic, in a form that can be printed or drawn.

    rounds:  [{"index": int, "state": {name: int}, "weight": float,
               "active": {layer: [positions]}}]
    """

    def __init__(self, rounds, state_bits, cell_bits=4, name="",
                 total_weight=None):
        self.rounds = rounds
        self.state_bits = state_bits
        self.cell_bits = cell_bits
        self.name = name
        self.total_weight = (total_weight if total_weight is not None
                             else sum(r["weight"] for r in rounds))

    # ------------------------------------------------------------- ingest

    @classmethod
    def from_claasp(cls, trail, cipher=None, name=""):
        """
        Read a CLAASP trail dict.

        Component ids carry the round in the middle -- sbox_3_17, xor_0_4 --
        so the round structure can be recovered without asking the cipher.
        S-box positions are numbered in the order they appear within their
        round, which is the order they were emitted and therefore the order
        of the cells they sit on.
        """
        values = trail.get("components_values", {})
        by_round = {}
        cell_bits = 4

        for cid, info in values.items():
            m = re.match(r"([a-z_]+)_(\d+)_(\d+)$", cid)
            if not m:
                continue
            kind, rnd, _idx = m.group(1), int(m.group(2)), int(m.group(3))
            r = by_round.setdefault(rnd, {"index": rnd, "state": {},
                                          "weight": 0.0, "active": {},
                                          "_sboxes": []})
            w = info.get("weight") or 0
            if kind == "sbox":
                r["_sboxes"].append((cid, w, info.get("value")))
                r["weight"] += w
                v = info.get("value")
                if isinstance(v, str) and v.startswith("0x"):
                    cell_bits = max(cell_bits, (len(v) - 2) * 4)
            elif kind in ("intermediate_output", "cipher_output"):
                v = info.get("value")
                if isinstance(v, str):
                    # The last round emits both an intermediate_output and a
                    # cipher_output carrying the same value.  Keeping both
                    # would give that row an extra column and misalign every
                    # table; one state per round is what a trail means.
                    r["state"]["state"] = int(v, 16)

        out = []
        for idx in sorted(by_round):
            r = by_round[idx]
            sb = sorted(r.pop("_sboxes"),
                        key=lambda t: int(t[0].rsplit("_", 1)[1]))
            r["active"] = {"S": [i for i, (_, w, _) in enumerate(sb) if w]}
            r["cells"] = [{"index": i, "weight": w, "value": v}
                          for i, (_, w, v) in enumerate(sb)]
            out.append(r)

        bits = 0
        pt = values.get("plaintext", {}).get("value")
        if isinstance(pt, str):
            bits = (len(pt) - 2) * 4
        if cipher is not None:
            try:
                bits = cipher.output_bit_size
            except AttributeError:
                pass

        t = cls(out, bits or 64, cell_bits,
                name or trail.get("cipher", ""),
                trail.get("total_weight"))
        t.plaintext = int(pt, 16) if isinstance(pt, str) else None
        return t

    @classmethod
    def from_states(cls, states, state_bits, weights=None, name="",
                    active=None):
        """
        Build from a plain list of round states, for a trail that came from
        somewhere other than CLAASP -- an STP model, or a table in a paper.
        """
        rounds = []
        for i, st in enumerate(states):
            rounds.append({
                "index": i,
                "state": st if isinstance(st, dict) else {"state": st},
                "weight": (weights or [0] * len(states))[i],
                "active": {"S": (active or [[]] * len(states))[i]},
                "cells": [],
            })
        return cls(rounds, state_bits, name=name)

    # -------------------------------------------------------------- text

    def text(self, radix="hex"):
        """Round-by-round listing.  radix: hex | bin | both."""
        fmt = _bin if radix == "bin" else _hex
        lines = []
        if self.name:
            lines.append(f"{self.name}")
        lines.append(f"{len(self.rounds)} rounds, "
                     f"total weight {self.total_weight} "
                     f"(probability 2^-{self.total_weight})")
        lines.append("")
        names = self._columns()
        head = f"{'R':>3}  {'weight':>7}  {'active':>6}  state"
        lines.append(head)
        lines.append("-" * max(len(head), 60))
        for r in self.rounds:
            act = len(r["active"].get("S", []))
            state = "  ".join(fmt(r["state"][n], self.state_bits)
                              if n in r["state"] else "-" * (self.state_bits // 4)
                              for n in names)
            lines.append(f"{r['index']:>3}  {r['weight']:>7}  "
                         f"{act:>6}  {state}")
            if radix == "both" and r["state"]:
                for v in r["state"].values():
                    lines.append(f"{'':>3}  {'':>7}  {'':>6}  "
                                 f"{_bin(v, self.state_bits)}")
        lines.append("")
        lines.append(f"active S-boxes: "
                     f"{sum(len(r['active'].get('S', [])) for r in self.rounds)}")
        return "\n".join(lines)

    # --------------------------------------------------------------- svg

    def svg(self, cell=17, gap=3, margin=54, show_weights=True):
        """
        The activity grid, written directly -- no plotting library needed.

        Rounds run down, S-box positions across, a filled cell where the box
        is active.  Weight-3 transitions are drawn darker than weight-2 ones,
        because which transitions are cheap is exactly what a reader wants to
        see and a plain binary grid throws that away.
        """
        cols = max((len(r["cells"]) for r in self.rounds), default=16) or 16
        rows = len(self.rounds)
        w = margin + cols * (cell + gap) + margin
        h = margin + rows * (cell + gap) + 34

        p = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" '
             f'height="{h}" viewBox="0 0 {w} {h}" font-family="Helvetica,'
             f'Arial,sans-serif">',
             f'<rect width="{w}" height="{h}" fill="#ffffff"/>']

        if self.name:
            p.append(f'<text x="{margin}" y="22" font-size="13" '
                     f'font-weight="600">{_esc(self.name)}</text>')
        p.append(f'<text x="{margin}" y="{38 if self.name else 22}" '
                 f'font-size="11" fill="#666">'
                 f'{rows} rounds &#183; weight {self.total_weight} &#183; '
                 f'{sum(len(r["active"].get("S", [])) for r in self.rounds)}'
                 f' active S-boxes</text>')

        top = margin
        for c in range(cols):
            x = margin + c * (cell + gap) + cell / 2
            if c % 4 == 0 or cols <= 16:
                p.append(f'<text x="{x:.1f}" y="{top - 6}" font-size="9" '
                         f'fill="#666" text-anchor="middle">{c}</text>')

        for i, r in enumerate(self.rounds):
            y = top + i * (cell + gap)
            p.append(f'<text x="{margin - 9}" y="{y + cell - 4}" '
                     f'font-size="10" fill="#444" text-anchor="end">'
                     f'{r["index"]}</text>')
            weights = {c["index"]: c["weight"] for c in r["cells"]}
            for c in range(cols):
                x = margin + c * (cell + gap)
                wt = weights.get(c, 0)
                if wt:
                    fill = "#1f4e9c" if wt <= 2 else "#7aa5df"
                else:
                    fill = "#eef0f4"
                p.append(f'<rect x="{x}" y="{y}" width="{cell}" '
                         f'height="{cell}" rx="2" fill="{fill}"/>')
            if show_weights and r["weight"]:
                x = margin + cols * (cell + gap) + 6
                p.append(f'<text x="{x}" y="{y + cell - 4}" font-size="9" '
                         f'fill="#666">{r["weight"]:g}</text>')

        ly = top + rows * (cell + gap) + 18
        for i, (fill, label) in enumerate((("#1f4e9c", "weight 2"),
                                           ("#7aa5df", "weight 3"),
                                           ("#eef0f4", "inactive"))):
            x = margin + i * 92
            p.append(f'<rect x="{x}" y="{ly - 9}" width="11" height="11" '
                     f'rx="2" fill="{fill}"/>')
            p.append(f'<text x="{x + 16}" y="{ly}" font-size="10" '
                     f'fill="#666">{label}</text>')

        p.append("</svg>")
        return "\n".join(p)

    # ------------------------------------------------------------- latex

    def _columns(self):
        """The state names, taken from the widest round so every row lines
        up even if a round happens to carry fewer."""
        names = []
        for r in self.rounds:
            for n in r["state"]:
                if n not in names:
                    names.append(n)
        return names

    def latex(self, caption=None, label=None, radix="hex", max_rounds=None):
        """
        A booktabs table of the propagation, in the shape papers use.

        Retyping a trail from a terminal into a paper is how transcription
        errors get into print, so the table comes out ready to \\input.
        """
        fmt = _bin if radix == "bin" else _hex
        rows = self.rounds[:max_rounds] if max_rounds else self.rounds
        names = self._columns()
        cols = "r" + "l" * max(1, len(names)) + "rr"

        out = ["\\begin{table}[t]", "\\centering",
               f"\\caption{{{caption or 'Differential characteristic'}}}"]
        if label:
            out.append(f"\\label{{{label}}}")
        out.append(f"\\begin{{tabular}}{{{cols}}}")
        out.append("\\toprule")
        head = ["$R$"] + [f"$\\Delta$ {_tex(n)}" for n in names] \
            + ["active", "weight"]
        out.append(" & ".join(head) + " \\\\")
        out.append("\\midrule")
        for r in rows:
            cells = [str(r["index"])]
            cells += [f"\\texttt{{{fmt(r['state'][n], self.state_bits)}}}"
                      if n in r["state"] else "--" for n in names] or ["--"]
            cells.append(str(len(r["active"].get("S", []))))
            cells.append(f"{r['weight']:g}")
            out.append(" & ".join(cells) + " \\\\")
        out.append("\\midrule")
        out.append(f"\\multicolumn{{{1 + max(1, len(names))}}}{{r}}{{total}} "
                   f"& {sum(len(r['active'].get('S', [])) for r in rows)} "
                   f"& {self.total_weight:g} \\\\")
        out.append("\\bottomrule")
        out.append("\\end{tabular}")
        out.append("\\end{table}")
        return "\n".join(out)

    def tikz(self, cell="3mm"):
        """The activity grid as TikZ, for a paper that wants vector output
        with the document's own fonts."""
        cols = max((len(r["cells"]) for r in self.rounds), default=16) or 16
        out = [f"\\begin{{tikzpicture}}[x={cell},y=-{cell}]"]
        for i, r in enumerate(self.rounds):
            weights = {c["index"]: c["weight"] for c in r["cells"]}
            out.append(f"  \\node[anchor=east,font=\\tiny] at (-0.3,{i}.5) "
                       f"{{{r['index']}}};")
            for c in range(cols):
                wt = weights.get(c, 0)
                fill = ("black!75" if wt and wt <= 2
                        else "black!35" if wt else "black!6")
                out.append(f"  \\fill[{fill}] ({c},{i}) rectangle "
                           f"++(0.88,0.88);")
        out.append("\\end{tikzpicture}")
        return "\n".join(out)

    # --------------------------------------------------------------- data

    def csv(self):
        buf = io.StringIO()
        names = self._columns()
        w = csv.writer(buf)
        w.writerow(["round"] + [f"delta_{n}" for n in names]
                   + ["active", "weight", "active_positions"])
        for r in self.rounds:
            w.writerow([r["index"]]
                       + [_hex(r["state"][n], self.state_bits)
                          if n in r["state"] else "" for n in names]
                       + [len(r["active"].get("S", [])), r["weight"],
                          " ".join(map(str, r["active"].get("S", [])))])
        return buf.getvalue()

    def to_dict(self):
        return {"name": self.name, "state_bits": self.state_bits,
                "total_weight": self.total_weight,
                "rounds": [{k: v for k, v in r.items()
                            if not k.startswith("_")}
                           for r in self.rounds]}

    def markdown(self):
        names = self._columns()
        out = [f"| R | {' | '.join(names) or 'state'} | active | weight |",
               f"|--:|{'--|' * (max(1, len(names)) + 2)}"]
        for r in self.rounds:
            vals = " | ".join(f"`{_hex(r['state'][n], self.state_bits)}`"
                              if n in r["state"] else "--"
                              for n in names) or "--"
            out.append(f"| {r['index']} | {vals} | "
                       f"{len(r['active'].get('S', []))} | {r['weight']:g} |")
        return "\n".join(out)

    # -------------------------------------------------------------- save

    #: Formats written with no third-party library at all.
    NATIVE = {".svg", ".tex", ".tikz", ".csv", ".json", ".md", ".txt"}
    #: Formats that need matplotlib.
    RENDERED = {".pdf", ".png", ".jpg", ".jpeg"}

    def save(self, path, **kw):
        """
        Write in whatever format the extension asks for.

            .svg .tex .tikz .csv .json .md .txt   standard library only
            .pdf .png .jpg                        needs matplotlib

        PDF and the bitmaps are kept behind an optional dependency on purpose:
        a SAT search should not require a plotting stack, and SVG already goes
        straight into LaTeX via \\includegraphics with the pdf backend, or into
        Inkscape.
        """
        ext = os.path.splitext(path)[1].lower()
        if ext == ".svg":
            data = self.svg(**kw)
        elif ext == ".tex":
            data = self.latex(**kw)
        elif ext == ".tikz":
            data = self.tikz(**kw)
        elif ext == ".csv":
            data = self.csv()
        elif ext == ".json":
            data = json.dumps(self.to_dict(), indent=2, default=str)
        elif ext == ".md":
            data = self.markdown()
        elif ext == ".txt":
            data = self.text(**kw)
        elif ext in self.RENDERED:
            return self._render(path, **kw)
        else:
            raise ValueError(
                f"unknown extension {ext!r}; native: "
                f"{' '.join(sorted(self.NATIVE))}; "
                f"with matplotlib: {' '.join(sorted(self.RENDERED))}")
        with open(path, "w") as fh:
            fh.write(data)
        return path

    def _render(self, path, dpi=300, cell=0.18, **kw):
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
            from matplotlib.patches import Rectangle
        except ImportError:
            raise RuntimeError(
                f"writing {os.path.splitext(path)[1]} needs matplotlib "
                f"(pip install matplotlib). Use .svg instead -- it needs "
                f"nothing, and LaTeX takes it directly.")

        cols = max((len(r["cells"]) for r in self.rounds), default=16) or 16
        rows = len(self.rounds)
        fig, ax = plt.subplots(figsize=(cols * cell + 1.4,
                                        rows * cell + 1.2))
        for i, r in enumerate(self.rounds):
            weights = {c["index"]: c["weight"] for c in r["cells"]}
            for c in range(cols):
                wt = weights.get(c, 0)
                colour = "#1f4e9c" if wt and wt <= 2 \
                    else "#7aa5df" if wt else "#eef0f4"
                ax.add_patch(Rectangle((c, -i), 0.88, -0.88,
                                       facecolor=colour, edgecolor="none"))
        ax.set_xlim(-0.6, cols + 0.4)
        ax.set_ylim(-rows - 0.4, 1.0)
        ax.set_xticks(range(0, cols, max(1, cols // 16)))
        ax.set_yticks([-i - 0.44 for i in range(rows)])
        ax.set_yticklabels([r["index"] for r in self.rounds], fontsize=7)
        ax.tick_params(length=0, labelsize=7)
        for s in ax.spines.values():
            s.set_visible(False)
        ax.set_xlabel("S-box position", fontsize=8)
        ax.set_ylabel("round", fontsize=8)
        if self.name:
            ax.set_title(f"{self.name} — weight {self.total_weight}",
                         fontsize=9)
        fig.tight_layout()
        fig.savefig(path, dpi=dpi,
                    format="jpeg" if path.lower().endswith((".jpg", ".jpeg"))
                    else None)
        plt.close(fig)
        return path


# --------------------------------------------------------------------------

def sbox_tables(table, name="S"):
    """
    The DDT and LAT of a lookup table, as text and LaTeX.

    Papers quote these next to a new S-box, and computing them by hand from a
    16-entry table is exactly the sort of thing that goes wrong quietly.
    """
    n = len(table)
    bits = (n - 1).bit_length()

    ddt = [[0] * n for _ in range(n)]
    for a in range(n):
        for x in range(n):
            ddt[a][table[x] ^ table[x ^ a]] += 1

    half = n // 2
    lat = [[0] * n for _ in range(n)]
    for u in range(n):
        for v in range(n):
            lat[u][v] = sum(
                1 for x in range(n)
                if bin(u & x).count("1") % 2 == bin(v & table[x]).count("1") % 2
            ) - half

    ddt_max = max(max(r) for r in ddt[1:]) if n > 1 else 0
    lat_max = max(abs(lat[u][v]) for u in range(n) for v in range(n)
                  if (u, v) != (0, 0))

    return {
        "name": name,
        "bits": bits,
        "table": list(table),
        "ddt": ddt,
        "lat": lat,
        "ddt_max": ddt_max,
        "lat_max": lat_max,
        "max_differential_probability": f"2^-{bits - ddt_max.bit_length() + 1}"
        if ddt_max else None,
        "bijective": sorted(table) == list(range(n)),
        "text": _grid_text(ddt, f"{name} DDT") + "\n"
                + _grid_text(lat, f"{name} LAT", signed=True),
        "latex": _grid_latex(ddt, f"DDT of ${name}$"),
    }


def _grid_text(grid, title, signed=False):
    n = len(grid)
    out = [title, "     " + " ".join(f"{c:>3X}" for c in range(n))]
    for r in range(n):
        cells = []
        for v in grid[r]:
            cells.append(f"{v:>3}" if (v or signed) else "  .")
        out.append(f" {r:>2X}  " + " ".join(cells))
    return "\n".join(out) + "\n"


def _grid_latex(grid, caption):
    n = len(grid)
    out = ["\\begin{table}[t]", "\\centering", f"\\caption{{{caption}}}",
           "\\small", f"\\begin{{tabular}}{{r|{'r' * n}}}",
           " & " + " & ".join(f"\\texttt{{{c:X}}}" for c in range(n))
           + " \\\\", "\\hline"]
    for r in range(n):
        out.append(f"\\texttt{{{r:X}}} & "
                   + " & ".join(str(v) if v else "." for v in grid[r])
                   + " \\\\")
    out += ["\\end{tabular}", "\\end{table}"]
    return "\n".join(out)


def _esc(s):
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))


def _tex(s):
    return re.sub(r"([_&%#$])", r"\\\1", str(s))
