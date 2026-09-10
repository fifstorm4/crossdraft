"""
Provenance: what was run, on what, against which circuit.

    from provenance import report, text, latex
    print(text(report(outdir="build/present")))

WHY BOTH HALVES
---------------
A result is reproducible when someone else can run the same analysis on the
same input and get the same answer.  Versions alone do not establish that.
Two people running identical CLAASP and identical Kissat on circuits that
differ by one wire will disagree, and nothing in a version string says so.

So this reports the tool versions *and* a SHA-256 of every circuit and
netlist the analysis touched.  The hash is what makes the claim checkable:
anyone can extract their own netlist and compare digests before wondering
why their weight differs from yours.

The output is meant to be pasted into a paper's methodology section, or
committed beside the results as a record.  `text()` for a terminal,
`latex()` for the paper, `json.dumps(report())` for a machine.
"""

import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys

__all__ = ["report", "text", "latex", "tool_versions", "circuit_digests"]

CROSSDRAFT_VERSION = "0.1.0"


def _run(cmd, pattern=None, timeout=15):
    """Run a command and pull a version out of whatever it prints."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    out = (r.stdout or "") + (r.stderr or "")
    if not out.strip():
        return None
    if pattern:
        m = re.search(pattern, out)
        return m.group(1) if m else None
    return out.strip().splitlines()[0].strip()


def _python_package(name):
    try:
        import importlib.metadata as md
        return md.version(name)
    except Exception:
        return None


def tool_versions(digital_jar=None):
    """
    Every external piece the pipeline can use, and whether it is present.

    Absence is reported rather than hidden: a run without espresso cannot
    build S-box constraints, and a reader should be able to see that from
    the record instead of inferring it from a missing table.
    """
    digital_jar = digital_jar or os.environ.get("DIGITAL_JAR")

    tools = {
        "crossdraft": CROSSDRAFT_VERSION,
        "python": platform.python_version(),
    }

    # Digital carries its version in the jar's manifest.
    if digital_jar and os.path.exists(digital_jar):
        v = None
        try:
            import zipfile
            with zipfile.ZipFile(digital_jar) as z:
                mf = z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace")
                m = re.search(r"Implementation-Version:\s*(\S+)", mf)
                v = m.group(1) if m else None
        except Exception:
            pass
        tools["Digital"] = v or "present (version not in manifest)"
        tools["Digital.jar"] = _sha256(digital_jar)[:16]
    else:
        tools["Digital"] = None

    tools["java"] = _run(["java", "-version"],
                         r'version "?([\w.+_-]+)') if shutil.which("java") \
        else None

    for pkg, label in (("claasp", "CLAASP"),
                       ("passagemath-standard", "passagemath"),
                       ("passagemath-modules", "passagemath-modules"),
                       ("matplotlib", "matplotlib"),
                       ("numpy", "numpy")):
        v = _python_package(pkg)
        if v:
            tools[label] = v
    if "CLAASP" not in tools:
        try:
            import claasp                                    # noqa: F401
            tools["CLAASP"] = "present (version unknown)"
        except ImportError:
            tools["CLAASP"] = None

    tools["kissat"] = _run(["kissat", "--version"]) \
        if shutil.which("kissat") else None
    tools["cadical"] = _run(["cadical", "--version"]) \
        if shutil.which("cadical") else None
    tools["espresso"] = ("present" if shutil.which("espresso") else None)
    tools["NIST STS"] = ("2.1.2"
                         if os.path.exists("/usr/local/bin/sts-2.1.2/assess")
                         else None)

    tools["host"] = (f"{platform.machine()} {platform.system()}, "
                     f"{os.cpu_count()} cores")
    return tools


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def circuit_digests(outdir, cipher=None):
    """
    Every .dig and .json in the build directory, with its digest and size.

    The netlist is what the analysis actually consumed, so it is the thing
    that has to match; the .dig is included because that is what a reader
    would redraw from.
    """
    out = []
    if not outdir or not os.path.isdir(outdir):
        return out
    for name in sorted(os.listdir(outdir)):
        if not name.endswith((".dig", ".json")):
            continue
        if cipher and not name.startswith(cipher):
            continue
        path = os.path.join(outdir, name)
        entry = {"file": name, "sha256": _sha256(path),
                 "bytes": os.path.getsize(path)}
        if name.endswith(".json"):
            try:
                d = json.load(open(path))
                entry["components"] = len(d.get("components", []))
                entry["nets"] = len(d.get("nets", []))
            except Exception:
                pass
        out.append(entry)
    return out


def verification(outdir):
    """
    Whether these circuits passed `verify`, and against what.

    A provenance record that says which solver ran but not whether the
    circuit was ever checked is half a record. The digests are already here;
    the missing half is the claim they were taken in support of.
    """
    import json
    path = os.path.join(outdir or "", ".verified.json")
    if not outdir or not os.path.exists(path):
        return {"verified": False,
                "note": "these circuits have not passed `verify`"}
    try:
        record = json.load(open(path))
    except (OSError, ValueError):
        return {"verified": False, "note": "the verification record is "
                                           "unreadable"}
    return {
        "verified": True,
        "vectors": record.get("vectors"),
        "rounds_checked": record.get("rounds_checked"),
        "definition_sha256": (record.get("definition") or "")[:16],
        "when": record.get("timestamp"),
    }


def report(outdir=None, cipher=None, digital_jar=None, analysis=None):
    """The whole record, as a plain dict."""
    return {
        "crossdraft": CROSSDRAFT_VERSION,
        "tools": tool_versions(digital_jar),
        "circuits": circuit_digests(outdir, cipher),
        "verification": verification(outdir),
        "analysis": analysis or {},
    }


# --------------------------------------------------------------------------

_ORDER = ["crossdraft", "python", "Digital", "Digital.jar", "java", "CLAASP",
          "passagemath", "passagemath-modules", "numpy", "matplotlib",
          "kissat", "cadical", "espresso", "NIST STS", "host"]


def text(rep):
    lines = [f"CrossDraft {rep['crossdraft']}", ""]
    tools = rep["tools"]
    width = max(len(k) for k in tools) + 2

    lines.append("environment")
    for key in _ORDER:
        if key not in tools:
            continue
        v = tools[key]
        lines.append(f"  {key:<{width}}{v if v else '-- not installed'}")
    for key in sorted(set(tools) - set(_ORDER)):
        lines.append(f"  {key:<{width}}{tools[key]}")

    if rep["circuits"]:
        lines += ["", "circuits analysed"]
        w = max(len(c["file"]) for c in rep["circuits"]) + 2
        for c in rep["circuits"]:
            extra = (f"  {c['components']} components, {c['nets']} nets"
                     if "components" in c else "")
            lines.append(f"  {c['file']:<{w}}sha256:{c['sha256'][:16]}"
                         f"…{extra}")

    v = rep.get("verification") or {}
    if v.get("verified"):
        lines += ["", "verification",
                  f"  published vectors   {v.get('vectors')}",
                  f"  circuit vs reference to round "
                  f"{v.get('rounds_checked')}",
                  f"  definition sha256   {v.get('definition_sha256')}…",
                  f"  checked at          {v.get('when')}"]
    elif rep["circuits"]:
        lines += ["", "verification",
                  f"  NOT VERIFIED -- {v.get('note')}"]

    if rep.get("analysis"):
        lines += ["", "analysis"]
        for k, v in rep["analysis"].items():
            lines.append(f"  {k}: {v}")

    lines += ["",
              "Quote the digests alongside any reported figure. Two runs on "
              "identical",
              "tool versions still disagree if the circuits differ, and only "
              "the digest",
              "shows that."]
    return "\n".join(lines)


def latex(rep, caption=None, label=None):
    """The same record as a table, for a methodology section."""
    tools = rep["tools"]
    rows = [(k, tools[k]) for k in _ORDER if tools.get(k)]
    out = ["\\begin{table}[t]", "\\centering",
           f"\\caption{{{caption or 'Software environment and analysed '
                        'circuits.'}}}"]
    if label:
        out.append(f"\\label{{{label}}}")
    out += ["\\small", "\\begin{tabular}{ll}", "\\toprule",
            "Component & Version \\\\", "\\midrule"]
    for k, v in rows:
        out.append(f"{_tex(k)} & {_tex(v)} \\\\")
    if rep["circuits"]:
        out += ["\\midrule", "Circuit & SHA-256 (first 16) \\\\",
                "\\midrule"]
        for c in rep["circuits"]:
            out.append(f"\\texttt{{{_tex(c['file'])}}} & "
                       f"\\texttt{{{c['sha256'][:16]}}} \\\\")
    out += ["\\bottomrule", "\\end{tabular}", "\\end{table}"]
    return "\n".join(out)


def _tex(s):
    return re.sub(r"([_&%#$])", r"\\\1", str(s))
