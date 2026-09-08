"""
Related-key differentials, diffusion, and the NIST battery.

    python3 tests/test_statistical.py --digital-jar Digital.jar \
                                     --bridge-jar java/digbridge.jar

The NIST case is skipped with a message unless setup_nist.py has been run;
everything else needs only CLAASP.
"""
import argparse
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "python"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--digital-jar", required=True)
    ap.add_argument("--bridge-jar", required=True)
    ap.add_argument("--nist", action="store_true",
                    help="also run the NIST battery, which takes minutes")
    a = ap.parse_args()
    os.environ["DIGITAL_JAR"] = os.path.abspath(a.digital_jar)
    os.environ["BRIDGE_JAR"] = os.path.abspath(a.bridge_jar)

    fails = []

    def check(name, ok, note=""):
        print(f"  {'PASS' if ok else 'FAIL'}  {name}{note}")
        if not ok:
            fails.append(name)

    cli = os.path.join(HERE, "..", "python", "digcli.py")
    for c in ("present", "llbc"):
        if not os.path.exists(os.path.join(os.getcwd(), "build", c,
                                           f"{c}_round.json")):
            subprocess.run([sys.executable, cli, "build", c], check=True,
                           capture_output=True)

    import preload            # noqa: F401
    from digstat import (related_key, key_schedule_report, avalanche,
                         diffusion, nist)
    from claasp.ciphers.block_ciphers.present_block_cipher \
        import PresentBlockCipher

    # --- avalanche, against a cipher whose behaviour is known -----------
    # A full PRESENT should change about half the output bits; one round
    # should not, and should leave some output bits untouched.
    full = avalanche(PresentBlockCipher(number_of_rounds=31), samples=60,
                     verbose=False)
    ok = abs(full["plaintext"]["mean"] - 32) < 4 \
        and full["plaintext"]["never_changed_bits"] == 0
    check("avalanche of full PRESENT is near ideal", ok,
          f"  [{full['plaintext']['mean']:.2f} of 64, ideal 32]")

    one = avalanche(PresentBlockCipher(number_of_rounds=1), samples=60,
                    verbose=False)
    ok = one["plaintext"]["never_changed_bits"] > 0
    check("avalanche catches a one-round cipher", ok,
          f"  [{one['plaintext']['mean']:.2f} of 64, "
          f"{one['plaintext']['never_changed_bits']} bits never change]")

    # --- diffusion -------------------------------------------------------
    # Coverage must widen with the round count.  Requiring *full* coverage
    # would be testing the sampling budget rather than the cipher: the figure
    # is a union over a few random pairs per input bit, so it approaches full
    # from below and the round it crosses depends on how many pairs were
    # drawn.  Monotone growth is the property that actually holds.
    cov = [diffusion(PresentBlockCipher(number_of_rounds=n),
                     trials_per_bit=3)["coverage"] for n in (1, 2, 3)]
    check("diffusion coverage widens with rounds",
          cov[0] < cov[1] < cov[2],
          f"  [{', '.join(f'{c:.0%}' for c in cov)} over rounds 1-3]")

    # --- related key -----------------------------------------------------
    # Releasing the key difference cannot make the best characteristic more
    # expensive: the single-key model is a special case of the related-key
    # one, so the weight can only fall.
    from dig2claasp import build_cipher
    from ciphers import PRESENT
    cipher = build_cipher(
        os.path.join(os.getcwd(), "build", "present",
                     "present_round.json"),
        rounds=3, params=lambda i: PRESENT["params"](i, 0),
        block_bits=64, key_bits=80, family_name="present")
    r = related_key(cipher, key_bits=80, block_bits=64, verbose=False)
    ok = r["related_key"]["weight"] <= r["single_key"]["weight"]
    check("related-key weight never exceeds single-key", ok,
          f"  [single {r['single_key']['weight']}, "
          f"related {r['related_key']['weight']}, gap {r['gap_bits']}]")
    check("the gap comes with an interpretation",
          bool(r["interpretation"]))

    ks = key_schedule_report(cipher, key_bits=80, samples=200)
    check("key linearity is decided", isinstance(ks["linear_in_key"], bool),
          f"  [affine in the key: {ks['linear_in_key']}]")

    # --- NIST ------------------------------------------------------------
    if not a.nist:
        print("  SKIP  NIST battery (pass --nist to run it)")
    elif not os.path.exists("/usr/local/bin/sts-2.1.2/assess"):
        print("  SKIP  NIST battery (run setup_nist.py first)")
    else:
        # Two rounds of PRESENT is not random and the suite should say so.
        res = nist(PresentBlockCipher(number_of_rounds=2),
                   bits_per_sequence=32768, sequences=16,
                   round_start=0, round_end=1, verbose=False)
        rate = res["rounds"][0]["rate"] if res["rounds"] else 1.0
        check("NIST rejects a two-round cipher", rate < 0.5,
              f"  [{res['rounds'][0]['passed']}/"
              f"{res['rounds'][0]['total']} sub-tests passed, "
              f"{res['seconds']}s]")
        check("the run states what it used", "necessary, not sufficient"
              in res["caveat"])

    print()
    if fails:
        print(f"{len(fails)} failure(s): {fails}")
        return 1
    print("all statistical features work")
    return 0


if __name__ == "__main__":
    sys.exit(main())
