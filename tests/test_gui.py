"""
Does the GUI actually serve, and do its three stages run?

    python3 tests/test_gui.py --digital-jar Digital.jar \
            --bridge-jar java/digbridge.jar

Starts the server, drives it over HTTP the way a browser would, and stops it.

Worth its own test because the GUI failed twice in ways nothing else could
have caught. It bound 127.0.0.1, which is unreachable from outside a
container however the port is published -- and the browser reports that as
the page simply not working, with no error anywhere. It also ran the stages
in the request thread, where Sage's signal handlers are illegal, so `analyse`
died with a message about signals that named nothing to do with analysis.

Neither is visible from reading the code, and neither shows up in a suite
that imports the module rather than speaking to it over a socket.
"""

import argparse
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def free_port():
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def get(url, timeout=10):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return r.status, r.read().decode("utf-8", "replace")


def post(url, fields, timeout=1800):
    data = "&".join(f"{k}={v}" for k, v in fields.items()).encode()
    with urllib.request.urlopen(url, data=data, timeout=timeout) as r:
        return json.loads(r.read().decode())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--digital-jar", required=True)
    ap.add_argument("--bridge-jar", required=True)
    ap.add_argument("--cipher", default="present")
    ap.add_argument("--rounds", type=int, default=2)
    ap.add_argument("--skip-analyse", action="store_true",
                    help="stop after verify; analyse needs CLAASP")
    a = ap.parse_args()

    port = free_port()
    env = dict(os.environ)
    env["DIGITAL_JAR"] = os.path.abspath(a.digital_jar)
    env["BRIDGE_JAR"] = os.path.abspath(a.bridge_jar)
    env["DIGGUI_PORT"] = str(port)

    gui = os.path.join(HERE, "..", "python", "diggui.py")
    proc = subprocess.Popen([sys.executable, gui], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True)
    fails = []

    def check(name, ok, note=""):
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{note}")
        if not ok:
            fails.append(name)

    try:
        # Reachability, not import-ability. The bind-address bug only shows
        # up when something opens a socket to the server.
        base = f"http://127.0.0.1:{port}"
        ready = False
        for _ in range(40):
            try:
                if get(base + "/api/ciphers", timeout=2)[0] == 200:
                    ready = True
                    break
            except (urllib.error.URLError, OSError):
                time.sleep(0.5)
        check("server answers on its published port", ready)
        if not ready:
            raise SystemExit(1)

        status, page = get(base + "/")
        check("serves the page", status == 200 and "CrossDraft" in page,
              f"  [{len(page)} bytes]")

        ciphers = json.loads(get(base + "/api/ciphers")[1])
        check("lists the ciphers", a.cipher in ciphers,
              f"  [{', '.join(sorted(ciphers))}]")

        # Each stage runs as a subprocess; a stage that dies takes its own
        # error back rather than the server with it.
        r = post(base + "/api/run",
                 {"cipher": a.cipher, "stage": "build",
                  "rounds": a.rounds, "bitorder": "lsb"})
        check("build", r.get("ok"), _tail(r))

        r = post(base + "/api/run",
                 {"cipher": a.cipher, "stage": "verify",
                  "rounds": a.rounds, "bitorder": "lsb"})
        check("verify", r.get("ok"), _tail(r))

        if a.skip_analyse:
            print("  SKIP  analyse (--skip-analyse)")
        else:
            r = post(base + "/api/run",
                     {"cipher": a.cipher, "stage": "analyse",
                      "rounds": a.rounds, "bitorder": "lsb"})
            check("analyse", r.get("ok"), _tail(r))
            check("returns the activity grid as inline SVG",
                  bool(r.get("svg")) and "<svg" in (r.get("svg") or ""),
                  f"  [{len(r.get('svg') or '')} bytes]")

        state = json.loads(get(base + "/api/ciphers")[1])[a.cipher]["state"]
        check("remembers which stages passed",
              state.get("build") and state.get("verify"),
              f"  [{state}]")

    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()

    print()
    if fails:
        print(f"{len(fails)} failure(s): {fails}")
        return 1
    print("the GUI serves, and its stages run")
    return 0


def _tail(r):
    if r.get("ok"):
        return ""
    log = (r.get("log") or "").strip().splitlines()
    return "  " + (log[-1] if log else "no output")


if __name__ == "__main__":
    sys.exit(main())
