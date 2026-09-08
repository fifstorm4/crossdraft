#!/usr/bin/env python3
"""
diggui -- a browser front end for CrossDraft.

    python3 diggui.py                      # then open http://127.0.0.1:8765
    ./run.ps1 gui                          # or from the launcher

Digital is already the schematic editor and the CLI is already complete, so
this is neither of those. What a browser adds is the part neither does well:
seeing what is possible without reading --help, changing a round count and
running again, and reading a trail as a table rather than as a wall of log.

Anything meant for a paper still goes through the CLI, where the command is
the record of what was done. The export buttons here write the same files,
but the reproducible act is the command, not the click.

Single file, standard library only, no build step. Stages run as
subprocesses: Sage and the SAT solvers install signal handlers, which Python
allows only from the main thread, so calling them in a request handler dies
with a message about signals that names nothing to do with cryptanalysis.
"""

import html
import json
import os
import subprocess
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

STATE = {}
LOCK = threading.Lock()


# --------------------------------------------------------------------------

def run_cli(*args, timeout=None):
    """
    Run one CLI command as a subprocess and return (ok, output).

    Out of process for two reasons. Sage and the SAT solvers install signal
    handlers, which Python forbids outside the main thread, so a stage called
    from a request handler dies with "signal only works in main thread". And
    a solver that runs away takes only itself with it.
    """
    cmd = [sys.executable, os.path.join(HERE, "digcli.py")] + [str(a)
                                                               for a in args]
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True, env=dict(os.environ),
            timeout=timeout or int(os.environ.get("DIGGUI_TIMEOUT", "3600")))
        return r.returncode == 0, (r.stdout or "") + (r.stderr or "")
    except subprocess.TimeoutExpired:
        return False, ("timed out. A differential search is NP-hard and has "
                       "no useful bound on running time; reduce the round "
                       "count or raise DIGGUI_TIMEOUT.")
    except Exception:
        return False, traceback.format_exc()


def run_stage(cipher, stage, **kw):
    args = [stage, cipher]
    for k, v in kw.items():
        if v is None or v is False:
            continue
        flag = f"--{k.replace('_', '-')}"
        args.append(flag)
        if v is not True:
            args.append(v)
    ok, log = run_cli(*args)
    with LOCK:
        STATE.setdefault(cipher, {})[stage] = {"ok": ok, "log": log}
    return ok, log


def cipher_list():
    from ciphers import REGISTRY
    return REGISTRY


def parse_trail(log):
    """
    Pull the round-by-round table out of a command's output.

    The CLI already prints it under `--show`; re-parsing rather than
    recomputing keeps one source of truth for the numbers, so the table on
    screen and the table in a paper cannot drift apart.
    """
    rows, seen_header = [], False
    for line in log.splitlines():
        if line.strip().startswith("R ") and "weight" in line:
            seen_header = True
            continue
        if not seen_header:
            continue
        parts = line.split()
        if len(parts) >= 4 and parts[0].isdigit():
            rows.append({"round": int(parts[0]), "weight": parts[1],
                         "active": parts[2], "state": parts[3:]})
        elif rows and not line.strip():
            break
    return rows


def workspace_csvs():
    """CSV files in the working directory, for the replicate picker."""
    out = []
    for root in (os.getcwd(), os.path.join(HERE, "..", "examples")):
        if not os.path.isdir(root):
            continue
        for name in sorted(os.listdir(root)):
            if name.endswith(".csv"):
                p = os.path.join(root, name)
                out.append({"name": name, "path": os.path.abspath(p)})
    return out


# --------------------------------------------------------------------------

PAGE = r"""<!doctype html>
<meta charset="utf-8">
<title>CrossDraft</title>
<style>
:root {
  --bg:#12141a; --panel:#1a1d26; --line:#2a2f3d; --ink:#e6e8ef;
  --dim:#8b93a7; --ok:#3fb950; --bad:#f85149; --accent:#4b8bf5;
}
* { box-sizing:border-box }
body { margin:0; background:var(--bg); color:var(--ink);
  font:14px/1.55 ui-sans-serif,-apple-system,"Segoe UI",sans-serif }
header { padding:16px 26px; border-bottom:1px solid var(--line);
  display:flex; align-items:baseline; gap:16px }
h1 { margin:0; font-size:17px; font-weight:600 }
header .sub { color:var(--dim); font-size:12.5px }
main { display:grid; grid-template-columns:290px 1fr; min-height:calc(100vh - 55px) }
aside { border-right:1px solid var(--line); padding:16px; overflow:auto }
section { padding:18px 26px; min-width:0 }
.cipher { padding:10px 12px; border:1px solid var(--line); border-radius:8px;
  margin-bottom:8px; cursor:pointer; background:var(--panel) }
.cipher:hover { border-color:var(--accent) }
.cipher.sel { border-color:var(--accent); box-shadow:0 0 0 1px var(--accent) }
.cipher b { display:block; font-size:14px }
.cipher span { color:var(--dim); font-size:12px }
.dots { margin-top:6px; display:flex; gap:5px }
.dot { width:8px; height:8px; border-radius:50%; background:var(--line) }
.dot.ok { background:var(--ok) } .dot.bad { background:var(--bad) }
.row { display:flex; gap:9px; margin:4px 0 14px; flex-wrap:wrap;
  align-items:center }
button { background:var(--panel); color:var(--ink); border:1px solid var(--line);
  padding:8px 15px; border-radius:7px; cursor:pointer; font-size:13.5px }
button:hover:not(:disabled) { border-color:var(--accent) }
button:disabled { opacity:.35; cursor:not-allowed }
button.run { border-color:var(--accent) }
button.sm { padding:5px 11px; font-size:12.5px }
label { color:var(--dim); font-size:12.5px; display:flex; align-items:center;
  gap:6px }
input[type=number] { width:60px }
input, select { background:var(--bg); color:var(--ink);
  border:1px solid var(--line); border-radius:5px; padding:5px 7px;
  font-size:13px }
.toggle { display:inline-flex; border:1px solid var(--line); border-radius:7px;
  overflow:hidden }
.toggle button { border:0; border-radius:0; padding:6px 13px; font-size:12.5px }
.toggle button.on { background:var(--accent); color:#fff }
pre { background:var(--panel); border:1px solid var(--line); border-radius:8px;
  padding:14px; overflow:auto; font:12.5px/1.6 ui-monospace,Menlo,monospace;
  white-space:pre-wrap; margin:0 0 14px; max-height:340px }
.note { color:var(--dim); font-size:12.5px; margin:0 0 14px;
  border-left:2px solid var(--line); padding-left:12px }
h2 { font-size:12px; text-transform:uppercase; letter-spacing:.7px;
  color:var(--dim); margin:20px 0 8px; font-weight:600 }
h2:first-child { margin-top:0 }
.status { font-size:12.5px; color:var(--dim); margin-left:auto }
table { border-collapse:collapse; font:12.5px/1.5 ui-monospace,Menlo,monospace;
  margin:0 0 14px }
th, td { padding:5px 12px; text-align:right; border-bottom:1px solid var(--line) }
th { color:var(--dim); font-weight:600; font-size:11px; text-transform:uppercase }
td.state { text-align:left; color:var(--dim) }
tr.zero td { color:var(--dim) }
tfoot td { font-weight:600; border-top:1px solid var(--line); border-bottom:0 }
#fig svg { background:#fff; border:1px solid var(--line); border-radius:8px;
  max-width:100%; height:auto; padding:6px; margin-bottom:6px }
.tabs { display:flex; gap:4px; border-bottom:1px solid var(--line);
  margin-bottom:14px }
.tabs button { border:0; border-bottom:2px solid transparent;
  border-radius:0; padding:8px 14px; color:var(--dim) }
.tabs button.on { color:var(--ink); border-bottom-color:var(--accent) }
.hint { color:var(--dim); font-size:12px; margin:6px 0 0 }
code { background:var(--panel); padding:1px 5px; border-radius:4px;
  font-size:12px }
</style>

<header>
  <h1>CrossDraft</h1>
  <span class="sub">draw a cipher in Digital &middot; check it &middot; analyse it</span>
</header>

<main>
<aside>
  <h2>Ciphers</h2>
  <div id="list"></div>
  <h2>Bit order</h2>
  <div class="toggle" id="bitorder">
    <button data-v="lsb" class="on">LSB first</button>
    <button data-v="msb">MSB first</button>
  </div>
  <p class="note" style="margin-top:10px">
    Which end of a word is bit 0. PRESENT counts from the LSB; a paper that
    writes the leading digit as bit 0 wants MSB. The wrong choice yields a
    working circuit computing the mirror-image function.
  </p>
</aside>

<section>
  <div class="tabs">
    <button data-tab="pipeline" class="on">Pipeline</button>
    <button data-tab="replicate">Replicate</button>
    <button data-tab="sbox">S-boxes</button>
    <button data-tab="cost">Cost</button>
  </div>

  <div id="tab-pipeline">
    <div class="row">
      <button id="b-build"   class="run">1&nbsp; Build</button>
      <button id="b-verify"  disabled>2&nbsp; Verify</button>
      <button id="b-analyse" disabled>3&nbsp; Analyse</button>
      <label>rounds <input type="number" id="rounds" min="1" value="3"></label>
      <span class="status" id="status"></span>
    </div>
    <p class="note" id="why">
      Run these in order. The published vectors pin down the reference
      implementation, the reference pins down the circuit, and the circuit
      pins down the CLAASP model. Skip a stage and a mistake there becomes
      invisible: a mistranslated model still produces plausible trails, with
      nothing to compare them against.
    </p>
  </div>

  <div id="tab-replicate" style="display:none">
    <div class="row">
      <label>trail <select id="rep-csv"></select></label>
      <label>rounds <input type="number" id="rep-rounds" min="1" value="7"></label>
      <label>expected weight <input type="number" id="rep-weight" step="any" style="width:80px"></label>
      <label><input type="checkbox" id="rep-pin" checked> pin every round</label>
      <button id="b-replicate" class="run">Replicate</button>
      <span class="status" id="rep-status"></span>
    </div>
    <p class="note">
      A paper reports a characteristic as a table of round differences and a
      probability; the search that produced it ran in the authors' own model,
      which nobody else has. This asks a different model, built from a
      schematic, whether the same path is realisable and costs the same.
      <b>Pin every round</b> checks the published path itself rather than
      just its endpoints — without it the solver may reach the same output
      difference by its own route.
    </p>
  </div>

  <div id="tab-sbox" style="display:none">
    <div class="row">
      <button id="b-sbox" class="run">Show DDT and LAT</button>
      <span class="status" id="sbox-status"></span>
    </div>
    <p class="note">
      Differential and linear distribution tables, with the maximum
      differential probability. The tables a paper quotes beside a new S-box,
      computed rather than copied.
    </p>
  </div>

  <div id="tab-cost" style="display:none">
    <div class="row">
      <label>model
        <select id="cost-model">
          <option value="nangate45">NanGate 45nm</option>
          <option value="umc180">UMC 0.18um</option>
          <option value="nand_transistors">NAND transistors</option>
        </select>
      </label>
      <label>rounds <input type="number" id="cost-rounds" min="1" value="20"></label>
      <button id="b-cost" class="run">Estimate</button>
      <button id="b-bench" class="sm">Published figures</button>
      <span class="status" id="cost-status"></span>
    </div>
    <p class="note">
      Counts what is on the schematic and applies a stated gate model. It is
      reproducible and it is an estimate — no sharing, no technology mapping,
      no register cost. Published figures are grouped by the environment they
      were measured in and never ranked across groups, because the same
      cipher differs by more than thirty times between them.
    </p>
  </div>

  <div id="trail"></div>
  <div id="fig"></div>
  <div id="exports"></div>
  <pre id="log">Pick a cipher.</pre>
</section>
</main>

<script>
let sel = null, bitorder = "lsb", lastTrail = null;

const $ = id => document.getElementById(id);

async function load() {
  const data = await (await fetch("/api/ciphers")).json();
  const box = $("list");
  box.innerHTML = "";
  for (const [name, c] of Object.entries(data)) {
    const d = document.createElement("div");
    d.className = "cipher" + (name === sel ? " sel" : "");
    const st = c.state || {};
    d.innerHTML = `<b>${name}</b><span>block ${c.block_bits} &middot; key ${c.key_bits}
      &middot; ${c.rounds} rounds &middot; ${c.parts.join(", ")}</span>
      <div class="dots">${["build","verify","analyse"].map(s =>
        `<div class="dot ${st[s] === undefined ? "" : (st[s] ? "ok" : "bad")}"></div>`
      ).join("")}</div>`;
    d.onclick = () => { sel = name; render(data); };
    box.appendChild(d);
  }
  render(data);
  return data;
}

function render(data) {
  [...document.querySelectorAll(".cipher")].forEach((e, i) =>
    e.classList.toggle("sel", Object.keys(data)[i] === sel));
  const st = sel ? (data[sel].state || {}) : {};
  $("b-build").disabled = !sel;
  $("b-verify").disabled = !sel || !st.build;
  $("b-analyse").disabled = !sel || !st.verify;
  $("b-replicate").disabled = !sel || !st.build;
  $("b-sbox").disabled = !sel;
  $("b-cost").disabled = !sel || !st.build;
  if (sel && data[sel].note)
    $("why").textContent = "Note on " + sel + ": " + data[sel].note;
  if (sel) {
    $("rounds").value = Math.min(3, data[sel].rounds);
    $("cost-rounds").value = data[sel].rounds;
  }
}

function showTrail(rows) {
  const box = $("trail");
  if (!rows || !rows.length) { box.innerHTML = ""; return; }
  const total = rows.reduce((a, r) => a + parseFloat(r.weight || 0), 0);
  const act = rows.reduce((a, r) => a + parseInt(r.active || 0), 0);
  box.innerHTML = `<table>
    <thead><tr><th>Round</th><th>Weight</th><th>Active S-boxes</th>
      <th style="text-align:left">&Delta; state</th></tr></thead>
    <tbody>${rows.map(r => `<tr class="${parseFloat(r.weight) ? "" : "zero"}">
      <td>${r.round}</td><td>${r.weight}</td><td>${r.active}</td>
      <td class="state">${r.state.join(" ")}</td></tr>`).join("")}</tbody>
    <tfoot><tr><td>total</td><td>${total}</td><td>${act}</td>
      <td class="state">probability 2<sup>-${total}</sup></td></tr></tfoot>
  </table>`;
}

function showExports(cipher, kind, extra) {
  const box = $("exports");
  const fmts = ["svg", "pdf", "png", "tex", "tikz", "csv"];
  box.innerHTML = `<div class="row" style="margin-top:0">
    <span style="color:var(--dim);font-size:12.5px">Export:</span>
    ${fmts.map(f => `<button class="sm" data-fmt="${f}">${f}</button>`).join("")}
    <span class="status" id="exp-status"></span></div>
    <p class="hint">Files land in the directory the server was started from.
    For a paper, prefer the command line: the command is the record of what
    was done.</p>`;
  box.querySelectorAll("button").forEach(b => b.onclick = async () => {
    $("exp-status").textContent = "writing " + b.dataset.fmt + "...";
    const body = new URLSearchParams({cipher, kind, fmt: b.dataset.fmt,
                                      ...extra});
    const d = await (await fetch("/api/export", {method:"POST", body})).json();
    $("exp-status").textContent = d.ok ? "wrote " + d.file : "failed";
    if (!d.ok) $("log").textContent = d.log;
  });
}

async function run(stage) {
  $("status").textContent = stage + " running...";
  $("log").textContent = "";
  $("trail").innerHTML = ""; $("fig").innerHTML = ""; $("exports").innerHTML = "";
  const body = new URLSearchParams({
    cipher: sel, stage, rounds: $("rounds").value, bitorder});
  const d = await (await fetch("/api/run", {method:"POST", body})).json();
  $("log").textContent = d.log || "(no output)";
  $("status").textContent = stage + (d.ok ? " passed" : " FAILED");
  if (d.trail) { showTrail(d.trail); lastTrail = d.trail; }
  if (d.svg) $("fig").innerHTML = d.svg;
  if (d.ok && stage === "analyse")
    showExports(sel, "analyse", {rounds: $("rounds").value});
  load();
}

for (const st of ["build","verify","analyse"])
  $("b-" + st).onclick = () => run(st);

$("b-replicate").onclick = async () => {
  $("rep-status").textContent = "solving...";
  $("log").textContent = ""; $("trail").innerHTML = "";
  $("fig").innerHTML = ""; $("exports").innerHTML = "";
  const body = new URLSearchParams({
    cipher: sel, trail: $("rep-csv").value, rounds: $("rep-rounds").value,
    weight: $("rep-weight").value, pin: $("rep-pin").checked ? "1" : ""});
  const d = await (await fetch("/api/replicate", {method:"POST", body})).json();
  $("log").textContent = d.log || "(no output)";
  $("rep-status").textContent = d.ok
    ? (d.log.includes("MATCH") ? "replicated, weight matches"
                               : "replicated")
    : "not replicated";
  if (d.trail) showTrail(d.trail);
  if (d.svg) $("fig").innerHTML = d.svg;
  if (d.ok) showExports(sel, "replicate",
                        {rounds: $("rep-rounds").value,
                         trail: $("rep-csv").value,
                         pin: $("rep-pin").checked ? "1" : ""});
};

$("b-sbox").onclick = async () => {
  $("sbox-status").textContent = "computing...";
  $("trail").innerHTML = ""; $("fig").innerHTML = ""; $("exports").innerHTML = "";
  const body = new URLSearchParams({cipher: sel, stage: "sbox"});
  const d = await (await fetch("/api/simple", {method:"POST", body})).json();
  $("log").textContent = d.log;
  $("sbox-status").textContent = d.ok ? "" : "failed";
};

$("b-cost").onclick = async () => {
  $("cost-status").textContent = "counting...";
  $("trail").innerHTML = ""; $("fig").innerHTML = "";
  const body = new URLSearchParams({cipher: sel, stage: "cost",
    rounds: $("cost-rounds").value, model: $("cost-model").value});
  const d = await (await fetch("/api/simple", {method:"POST", body})).json();
  $("log").textContent = d.log;
  $("cost-status").textContent = d.ok ? "" : "failed";
};

$("b-bench").onclick = async () => {
  $("cost-status").textContent = "loading...";
  const body = new URLSearchParams({stage: "bench"});
  const d = await (await fetch("/api/simple", {method:"POST", body})).json();
  $("log").textContent = d.log;
  $("cost-status").textContent = "";
};

document.querySelectorAll(".tabs button").forEach(b => b.onclick = () => {
  document.querySelectorAll(".tabs button").forEach(x => x.classList.remove("on"));
  b.classList.add("on");
  for (const t of ["pipeline","replicate","sbox","cost"])
    $("tab-" + t).style.display = (t === b.dataset.tab) ? "" : "none";
});

document.querySelectorAll("#bitorder button").forEach(b => b.onclick = () => {
  document.querySelectorAll("#bitorder button").forEach(x => x.classList.remove("on"));
  b.classList.add("on");
  bitorder = b.dataset.v;
});

(async () => {
  await load();
  const csvs = await (await fetch("/api/csvs")).json();
  $("rep-csv").innerHTML = csvs.map(c =>
    `<option value="${c.path}">${c.name}</option>`).join("")
    || `<option value="">no .csv in this directory</option>`;
})();
</script>
"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _form(self):
        n = int(self.headers.get("Content-Length", 0))
        return {k: v[0] for k, v in
                parse_qs(self.rfile.read(n).decode()).items()}

    # ---------------------------------------------------------------- GET

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            return self._send(200, PAGE, "text/html")
        if path == "/api/ciphers":
            out = {}
            with LOCK:
                for name, spec in cipher_list().items():
                    out[name] = {
                        "block_bits": spec["block_bits"],
                        "key_bits": spec["key_bits"],
                        "rounds": spec["rounds"],
                        "parts": list(spec["parts"]),
                        "vectors": len(spec["vectors"]),
                        "note": spec.get("note", ""),
                        "state": {k: v["ok"]
                                  for k, v in STATE.get(name, {}).items()},
                    }
            return self._send(200, json.dumps(out))
        if path == "/api/csvs":
            return self._send(200, json.dumps(workspace_csvs()))
        return self._send(404, json.dumps({"error": "not found"}))

    # --------------------------------------------------------------- POST

    def do_POST(self):
        path = urlparse(self.path).path
        form = self._form()
        try:
            if path == "/api/run":
                return self._send(200, json.dumps(self._run(form)))
            if path == "/api/replicate":
                return self._send(200, json.dumps(self._replicate(form)))
            if path == "/api/simple":
                return self._send(200, json.dumps(self._simple(form)))
            if path == "/api/export":
                return self._send(200, json.dumps(self._export(form)))
        except Exception:
            return self._send(200, json.dumps(
                {"ok": False, "log": traceback.format_exc()}))
        return self._send(404, json.dumps({"error": "not found"}))

    # ------------------------------------------------------------ actions

    def _run(self, form):
        cipher = form.get("cipher", "")
        stage = form.get("stage", "")
        rounds = int(form.get("rounds", "3"))
        order = form.get("bitorder", "lsb")
        if cipher not in cipher_list():
            return {"ok": False, "log": "unknown cipher"}
        if stage not in ("build", "verify", "analyse"):
            return {"ok": False, "log": "unknown stage"}

        os.environ["DIGBRIDGE_BIT_ORDER"] = order
        if stage == "build":
            kw = {"bit_order": order}
        elif stage == "verify":
            kw = {"rounds": rounds}
        else:
            svg = os.path.join(os.getcwd(), "build", cipher, "trail.svg")
            os.makedirs(os.path.dirname(svg), exist_ok=True)
            kw = {"rounds": rounds, "show": True, "export": svg}

        ok, log = run_stage(cipher, stage, **kw)
        body = {"ok": ok, "log": log}
        if stage == "analyse":
            body["trail"] = parse_trail(log)
            p = os.path.join(os.getcwd(), "build", cipher, "trail.svg")
            if os.path.exists(p):
                body["svg"] = open(p).read()
        return body

    def _replicate(self, form):
        cipher = form.get("cipher", "")
        trail = form.get("trail", "")
        if cipher not in cipher_list():
            return {"ok": False, "log": "unknown cipher"}
        if not trail or not os.path.exists(trail):
            return {"ok": False,
                    "log": "no trail file selected. A CSV with a `round` "
                           "column and one `delta_*` column per state "
                           "variable, in hex, in this directory."}
        svg = os.path.join(os.getcwd(), "build", cipher, "replicate.svg")
        os.makedirs(os.path.dirname(svg), exist_ok=True)
        args = ["replicate", cipher, "--trail", trail,
                "--rounds", form.get("rounds", "7"), "--show",
                "--export", svg]
        if form.get("pin"):
            args.append("--pin-all")
        if form.get("weight"):
            args += ["--expect-weight", form["weight"]]
        ok, log = run_cli(*args)
        body = {"ok": ok, "log": log, "trail": parse_trail(log)}
        if os.path.exists(svg):
            body["svg"] = open(svg).read()
        return body

    def _simple(self, form):
        stage = form.get("stage", "")
        cipher = form.get("cipher", "")
        if stage == "bench":
            return dict(zip(("ok", "log"), run_cli("bench", "--environments")))
        if cipher not in cipher_list():
            return {"ok": False, "log": "unknown cipher"}
        if stage == "sbox":
            return dict(zip(("ok", "log"),
                            run_cli("sbox", cipher, "--show")))
        if stage == "cost":
            return dict(zip(("ok", "log"),
                            run_cli("cost", cipher,
                                    "--rounds", form.get("rounds", "20"),
                                    "--model",
                                    form.get("model", "nangate45"))))
        return {"ok": False, "log": "unknown action"}

    def _export(self, form):
        cipher = form.get("cipher", "")
        kind = form.get("kind", "analyse")
        fmt = form.get("fmt", "svg")
        if cipher not in cipher_list():
            return {"ok": False, "log": "unknown cipher"}
        name = f"{cipher}_{kind}.{fmt}"
        target = os.path.join(os.getcwd(), name)
        args = [kind, cipher, "--rounds", form.get("rounds", "3"),
                "--export", target]
        if kind == "replicate":
            args += ["--trail", form.get("trail", "")]
            if form.get("pin"):
                args.append("--pin-all")
        ok, log = run_cli(*args)
        return {"ok": ok and os.path.exists(target), "file": name,
                "log": log}


def main():
    port = int(os.environ.get("DIGGUI_PORT", "8765"))

    # Bind every interface, not loopback. Inside a container 127.0.0.1 is the
    # container's own loopback and nothing outside reaches it -- the port
    # forward finds nobody listening, and the browser reports the page as
    # simply not working with nothing anywhere to explain why.
    host = os.environ.get("DIGGUI_HOST", "0.0.0.0")

    if not os.environ.get("DIGITAL_JAR"):
        print("warning: DIGITAL_JAR is not set; build and verify will fail")
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"CrossDraft GUI on http://127.0.0.1:{port}")
    if host == "0.0.0.0":
        print("  (listening on every interface; set DIGGUI_HOST=127.0.0.1 "
              "to restrict it)")
    print("ctrl-c to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
