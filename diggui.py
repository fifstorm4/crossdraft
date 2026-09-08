#!/usr/bin/env python3
"""
diggui -- a browser front end for the build / verify / analyse workflow.

    python3 diggui.py                      # then open http://127.0.0.1:8765

Digital already is the schematic editor, so this is not another one.  What it
covers is the part that otherwise lives in a terminal: picking a cipher,
running the three stages in the right order, and seeing at a glance which of
them have passed.  The order matters -- published vectors pin down the
reference, the reference pins down the circuit, the circuit pins down the
CLAASP model -- and a row of buttons that greys out until the previous stage
is green enforces it better than a README does.

Single file, standard library only, no build step.  It shells out to the same
functions digcli.py calls, so the two cannot drift apart.
"""

import html
import io
import json
import os
import sys
import threading
import traceback
from contextlib import redirect_stdout, redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

STATE = {}          # cipher -> {stage: {"ok": bool, "log": str}}
LOCK = threading.Lock()


# --------------------------------------------------------------------------

def _args(**kw):
    """digcli's command functions take an argparse namespace; fake one."""
    class A:
        pass
    a = A()
    a.digital_jar = os.environ.get("DIGITAL_JAR")
    a.bridge_jar = os.environ.get(
        "BRIDGE_JAR", os.path.join(HERE, "java", "digbridge.jar"))
    a.outdir = None
    a.rounds = None
    a.trials = 8
    a.seed = 0
    a.solver = "KISSAT_EXT"
    a.no_search = False
    a.json = None
    for k, v in kw.items():
        setattr(a, k, v)
    return a


def run_stage(cipher, stage, **kw):
    """
    Run one stage and capture everything it prints.

    Stages run as a subprocess rather than in the handler thread.  Sage and
    the SAT solvers install signal handlers, and Python only allows that from
    the main thread, so calling digcli directly from a request handler dies
    with "signal only works in main thread".  Out of process also means a
    solver that runs away cannot take the server with it.
    """
    import subprocess

    cmd = [sys.executable, os.path.join(HERE, "digcli.py"), stage, cipher]
    for k, v in kw.items():
        if v is None or v is False:
            continue
        flag = f"--{k.replace('_', '-')}"
        if v is True:
            cmd.append(flag)          # a switch, not a value
        else:
            cmd += [flag, str(v)]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           env=dict(os.environ),
                           timeout=int(os.environ.get("DIGGUI_TIMEOUT",
                                                      "3600")))
        log = (r.stdout or "") + (r.stderr or "")
        ok = (r.returncode == 0)
    except subprocess.TimeoutExpired:
        log = ("timed out; raise DIGGUI_TIMEOUT or reduce the round count.\n"
               "A differential search is NP-hard and has no useful upper "
               "bound on running time.")
        ok = False
    except Exception:
        log = traceback.format_exc()
        ok = False

    with LOCK:
        STATE.setdefault(cipher, {})[stage] = {"ok": ok, "log": log}
    return ok, log


def cipher_list():
    from ciphers import REGISTRY
    return REGISTRY


# --------------------------------------------------------------------------

PAGE = """<!doctype html>
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
header { padding:18px 26px; border-bottom:1px solid var(--line);
  display:flex; align-items:baseline; gap:16px }
h1 { margin:0; font-size:17px; font-weight:600; letter-spacing:.2px }
header .sub { color:var(--dim); font-size:12.5px }
main { display:grid; grid-template-columns:300px 1fr; min-height:calc(100vh - 59px) }
aside { border-right:1px solid var(--line); padding:16px }
section { padding:20px 26px; min-width:0 }
.cipher { padding:11px 13px; border:1px solid var(--line); border-radius:8px;
  margin-bottom:9px; cursor:pointer; background:var(--panel) }
.cipher:hover { border-color:var(--accent) }
.cipher.sel { border-color:var(--accent); box-shadow:0 0 0 1px var(--accent) }
.cipher b { display:block; font-size:14px }
.cipher span { color:var(--dim); font-size:12px }
.dots { margin-top:7px; display:flex; gap:5px }
.dot { width:8px; height:8px; border-radius:50%; background:var(--line) }
.dot.ok { background:var(--ok) } .dot.bad { background:var(--bad) }
.stages { display:flex; gap:10px; margin:4px 0 18px; flex-wrap:wrap;
  align-items:center }
button { background:var(--panel); color:var(--ink); border:1px solid var(--line);
  padding:9px 17px; border-radius:7px; cursor:pointer; font-size:13.5px }
button:hover:not(:disabled) { border-color:var(--accent) }
button:disabled { opacity:.38; cursor:not-allowed }
button.run { border-color:var(--accent) }
label { color:var(--dim); font-size:12.5px; display:flex; align-items:center;
  gap:6px }
input[type=number] { width:62px; background:var(--bg); color:var(--ink);
  border:1px solid var(--line); border-radius:5px; padding:5px 7px }
.toggle { display:inline-flex; border:1px solid var(--line); border-radius:7px;
  overflow:hidden }
.toggle button { border:0; border-radius:0; padding:7px 15px; font-size:12.5px }
.toggle button.on { background:var(--accent); color:#fff }
#fig { margin:0 0 16px }
#fig svg { background:#fff; border:1px solid var(--line); border-radius:8px;
  max-width:100%; height:auto; padding:6px }
#fig .hint { color:var(--dim); font-size:12px; margin:8px 0 0 }
#fig { margin:0 0 16px }
#fig svg { background:#fff; border:1px solid var(--line); border-radius:8px;
  max-width:100%; height:auto; padding:6px }
#fig .hint { color:var(--dim); font-size:12px; margin:8px 0 0 }
pre { background:var(--panel); border:1px solid var(--line); border-radius:8px;
  padding:15px; overflow:auto; font:12.5px/1.6 ui-monospace,Menlo,monospace;
  white-space:pre-wrap; margin:0 0 16px }
.note { color:var(--dim); font-size:12.5px; margin:0 0 16px;
  border-left:2px solid var(--line); padding-left:12px }
h2 { font-size:13px; text-transform:uppercase; letter-spacing:.7px;
  color:var(--dim); margin:22px 0 9px; font-weight:600 }
.status { font-size:12.5px; color:var(--dim); margin-left:auto }
</style>

<header>
  <h1>CrossDraft</h1>
  <span class="sub">draw a cipher in Digital &middot; check it &middot; analyse it</span>
</header>

<main>
<aside>
  <h2 style="margin-top:0">Ciphers</h2>
  <div id="list"></div>
  <h2>Bit order</h2>
  <div class="toggle" id="bitorder">
    <button data-v="lsb" class="on">LSB first</button>
    <button data-v="msb">MSB first</button>
  </div>
  <p class="note" style="margin-top:11px">
    Which end of a word is bit 0. PRESENT counts from the LSB; papers that
    write the leading digit as bit 0 want MSB. The wrong choice yields a
    working circuit computing the mirror-image function.
  </p>
</aside>

<section>
  <h2 style="margin-top:0">Pipeline</h2>
  <div class="stages">
    <button id="b-build"   class="run">1 &nbsp;Build</button>
    <button id="b-verify"  disabled>2 &nbsp;Verify</button>
    <button id="b-analyse" disabled>3 &nbsp;Analyse</button>
    <label>rounds <input type="number" id="rounds" min="1" value="3"></label>
    <span class="status" id="status"></span>
  </div>
  <p class="note" id="why">
    Run these in order. The published vectors pin down the reference
    implementation, the reference pins down the circuit, and the circuit pins
    down the CLAASP model. Skip a stage and a mistake there becomes invisible:
    a mistranslated model still produces plausible differential trails, with
    nothing to compare them against.
  </p>
  <div id="fig"></div>
  <div id="fig"></div>
  <pre id="log">Pick a cipher.</pre>
</section>
</main>

<script>
let sel = null, bitorder = "lsb";

async function load() {
  const r = await fetch("/api/ciphers");
  const data = await r.json();
  const box = document.getElementById("list");
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
}

function render(data) {
  document.querySelectorAll(".cipher").forEach((e, i) =>
    e.classList.toggle("sel", Object.keys(data)[i] === sel));
  const st = sel ? (data[sel].state || {}) : {};
  document.getElementById("b-build").disabled = !sel;
  document.getElementById("b-verify").disabled = !sel || !st.build;
  document.getElementById("b-analyse").disabled = !sel || !st.verify;
  if (sel && data[sel].note)
    document.getElementById("why").textContent = "Note on " + sel + ": " + data[sel].note;
}

async function run(stage) {
  const s = document.getElementById("status");
  s.textContent = stage + " running...";
  document.getElementById("log").textContent = "";
  const body = new URLSearchParams({
    cipher: sel, stage,
    rounds: document.getElementById("rounds").value,
    bitorder
  });
  const r = await fetch("/api/run", {method:"POST", body});
  const d = await r.json();
  const fig = document.getElementById("fig");
  fig.innerHTML = d.svg
    ? d.svg + `<p class="hint">Activity grid written to ${d.dir}/trail.svg.
        For a paper: <code>digcli.py analyse ${sel} --rounds ${document.getElementById("rounds").value}
        --export fig.pdf --export table.tex</code></p>`
    : "";
  document.getElementById("log").textContent = d.log || "(no output)";
  s.textContent = stage + (d.ok ? " passed" : " FAILED");
  load();
}

for (const st of ["build","verify","analyse"])
  document.getElementById("b-" + st).onclick = () => run(st);

document.querySelectorAll("#bitorder button").forEach(b => b.onclick = () => {
  document.querySelectorAll("#bitorder button").forEach(x =>
    x.classList.remove("on"));
  b.classList.add("on");
  bitorder = b.dataset.v;
});

load();
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
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if urlparse(self.path).path != "/api/run":
            return self._send(404, json.dumps({"error": "not found"}))
        n = int(self.headers.get("Content-Length", 0))
        q = parse_qs(self.rfile.read(n).decode())
        cipher = q.get("cipher", [""])[0]
        stage = q.get("stage", [""])[0]
        rounds = int(q.get("rounds", ["3"])[0])
        order = q.get("bitorder", ["lsb"])[0]

        if cipher not in cipher_list():
            return self._send(400, json.dumps({"error": "unknown cipher"}))
        if stage not in ("build", "verify", "analyse"):
            return self._send(400, json.dumps({"error": "unknown stage"}))

        os.environ["DIGBRIDGE_BIT_ORDER"] = order

        if stage == "build":
            kw = {"bit_order": order}
        elif stage == "verify":
            kw = {"rounds": rounds}
        else:
            # Draw the activity grid straight into the page.  SVG needs no
            # rendering stack and scales, so it is what the browser gets;
            # the other formats stay behind an explicit export.
            svg = os.path.join(os.getcwd(), "build", cipher, "trail.svg")
            os.makedirs(os.path.dirname(svg), exist_ok=True)
            kw = {"rounds": rounds, "show": True, "export": svg}

        ok, log = run_stage(cipher, stage, **kw)
        body = {"ok": ok, "log": log}
        if stage == "analyse":
            path = os.path.join(os.getcwd(), "build", cipher, "trail.svg")
            if os.path.exists(path):
                body["svg"] = open(path).read()
                body["dir"] = os.path.dirname(path)
        return self._send(200, json.dumps(body))


def main():
    port = int(os.environ.get("DIGGUI_PORT", "8765"))

    # Bind every interface, not loopback.
    #
    # Inside a container 127.0.0.1 is the container's own loopback, which
    # nothing outside can reach -- `docker run -p 8765:8765` forwards to the
    # container's external interface and finds nobody listening, so the
    # browser reports the page as simply not working with no error anywhere
    # to explain it. Binding 0.0.0.0 is what makes the published port mean
    # something.
    #
    # Outside a container that also exposes the server to the local network.
    # Set DIGGUI_HOST=127.0.0.1 to keep it to this machine.
    host = os.environ.get("DIGGUI_HOST", "0.0.0.0")

    if not os.environ.get("DIGITAL_JAR"):
        print("warning: DIGITAL_JAR is not set; build and verify will fail")
    srv = ThreadingHTTPServer((host, port), Handler)
    print(f"CrossDraft GUI on http://127.0.0.1:{port}")
    if host == "0.0.0.0":
        print(f"  (listening on every interface; set DIGGUI_HOST=127.0.0.1 "
              f"to restrict it)")
    print("ctrl-c to stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
