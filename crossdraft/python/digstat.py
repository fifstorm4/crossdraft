"""
digstat -- related-key differentials, and statistical randomness testing.

    from digstat import related_key, key_schedule_report, nist, avalanche

    related_key(cipher, rounds=4)      # single-key vs related-key, side by side
    nist(cipher, rounds=2)             # NIST SP 800-22 over the cipher's output
    avalanche(cipher)                  # diffusion, without any external tool

Both are optional and neither is imported by build / verify / analyse.


RELATED KEY
-----------
A single-key differential search pins the key difference to zero.  Releasing
it lets the attacker choose a relation between two unknown keys, which is a
stronger model and a weaker cipher -- and it is where key schedules that were
never analysed tend to fall over.

The gap between the two numbers is the interesting quantity.  A linear key
schedule propagates a master-key difference to every round key with
probability 1, so its related-key weight can collapse while the single-key
figure looks healthy.  LLBC is exactly this shape: G is rotations and XORs
only, and its proposal contains no related-key analysis at all.

Whether related-key attacks matter depends on the deployment.  They are not in
scope for a cipher used with random independent keys; they are very much in
scope wherever keys are derived, tweaked, or diversified per address.  Report
the gap and say which model you are in.


STATISTICAL TESTING
-------------------
NIST SP 800-22 answers "does this output look random", which is a much weaker
question than "is this cipher secure" and is easy to over-read.  Passing is
necessary, not sufficient: a two-round cipher failing every test tells you
something, a full cipher passing tells you almost nothing, and no statistical
suite has ever broken a serious design.

Its real use here is as a floor.  Run it on reduced rounds and watch where it
starts passing; a cipher still failing at round r has no diffusion worth the
name by round r, independently of any trail search.
"""

import math
import os
import time

__all__ = ["related_key", "key_schedule_report", "nist", "avalanche",
           "diffusion"]


# ==========================================================================
# Related key
# ==========================================================================

def related_key(cipher, key_bits=None, block_bits=None,
                solver="KISSAT_EXT", verbose=True):
    """
    The best differential characteristic in each model, side by side.

    Single key: the key difference is pinned to zero, so only the plaintext
    difference propagates.  Related key: it is free, and the solver may pick
    a relation between the two keys.

    Returns both weights and the gap.  A large gap says the key schedule is
    doing less than the data path -- which is the usual diagnosis when a
    schedule is linear, because then a master-key difference reaches every
    round key deterministically and costs nothing.
    """
    from claasp.cipher_modules.models.utils import set_fixed_variables
    from claasp.cipher_modules.models.sat.sat_models \
        .sat_xor_differential_model import SatXorDifferentialModel

    block_bits = block_bits or cipher.output_bit_size
    key_bits = key_bits or cipher.inputs_bit_size[cipher.inputs.index("key")]
    model = SatXorDifferentialModel(cipher)

    def run(label, fixed):
        t0 = time.time()
        trail = model.find_lowest_weight_xor_differential_trail(
            fixed_values=fixed, solver_name=solver)
        dt = time.time() - t0
        w = trail["total_weight"]
        active = sum(1 for k, v in trail["components_values"].items()
                     if "sbox" in k and v.get("weight"))
        if verbose:
            print(f"  {label:<12} weight {w:>7}  "
                  f"({active} active S-boxes)  [{dt:.1f}s]")
        return {"weight": w, "active_sboxes": active,
                "seconds": round(dt, 1), "trail": trail}

    single = run("single key", [
        set_fixed_variables("key", "equal", list(range(key_bits)),
                            [0] * key_bits),
        set_fixed_variables("plaintext", "not_equal",
                            list(range(block_bits)), [0] * block_bits),
    ])
    rel = run("related key", [
        set_fixed_variables("key", "not_equal", list(range(key_bits)),
                            [0] * key_bits),
    ])

    gap = single["weight"] - rel["weight"]
    kd = rel["trail"]["components_values"].get("key", {}).get("value")
    out = {
        "single_key": {k: v for k, v in single.items() if k != "trail"},
        "related_key": {k: v for k, v in rel.items() if k != "trail"},
        "gap_bits": gap,
        "key_difference": kd,
        "single_key_trail": single["trail"],
        "related_key_trail": rel["trail"],
        "interpretation": _rk_verdict(gap, single["weight"]),
    }
    if verbose:
        print(f"  gap          {gap:>7} bits")
        if kd:
            print(f"  key difference chosen: {kd}")
        print(f"  {out['interpretation']}")
    return out


def _rk_verdict(gap, single_weight):
    if gap <= 0:
        return ("no advantage from relating the keys at this round count; "
                "the key schedule is contributing as much as the data path")
    frac = gap / single_weight if single_weight else 1.0
    if frac >= 0.5:
        return (f"related-key characteristics are {gap} bits cheaper, over "
                f"half the single-key weight. That is the signature of a key "
                f"schedule a difference passes through nearly free -- check "
                f"whether it is linear, and whether the deployment lets an "
                f"attacker relate keys")
    return (f"related-key characteristics are {gap} bits cheaper. Worth "
            f"reporting alongside the single-key figure, and worth extending "
            f"to more rounds before drawing a conclusion")


def key_schedule_report(cipher, key_bits=None, samples=2000, seed=0):
    """
    Is the key schedule linear over GF(2)?

    A linear schedule sends a master-key difference to every round key with
    probability 1, which is what makes related-key trails cheap.  Testing it
    costs nothing: linearity means K(a) xor K(b) equals K(a xor b) xor K(0)
    for every pair, so random pairs settle it -- one counterexample proves
    non-linearity, and none over a few thousand pairs is strong evidence of
    linearity, since a single non-linear component would show up almost at
    once.
    """
    import random

    key_bits = key_bits or cipher.inputs_bit_size[cipher.inputs.index("key")]
    block_bits = cipher.output_bit_size
    random.seed(seed)

    zero = cipher.evaluate([0, 0])
    linear = True
    counterexample = None
    for _ in range(samples):
        a = random.getrandbits(key_bits)
        b = random.getrandbits(key_bits)
        if cipher.evaluate([0, a]) ^ cipher.evaluate([0, b]) \
                != cipher.evaluate([0, a ^ b]) ^ zero:
            linear = False
            counterexample = (a, b)
            break

    return {
        "samples": samples,
        "linear_in_key": linear,
        "counterexample": counterexample,
        "note": (
            "the whole cipher is affine in the key over GF(2) with the "
            "plaintext held at zero. A master-key difference then reaches "
            "the output deterministically, and related-key trails cost "
            "nothing in the key schedule"
            if linear else
            "not affine in the key; a key difference does not propagate for "
            "free"),
        "caveat": ("a property of this cipher object at this round count. "
                   "Non-linearity found by counterexample is proof; "
                   "linearity here is evidence, not proof"),
    }


# ==========================================================================
# Statistical testing
# ==========================================================================

def nist(cipher, test_type="avalanche", bits_per_sequence=131072,
         sequences=32, round_start=0, round_end=None, verbose=True):
    """
    NIST SP 800-22 over the cipher's output.

    Needs the `assess` binary from NIST STS 2.1.2 at /usr/local/bin/sts-2.1.2,
    which CLAASP shells out to; `setup_nist.py` builds it.

    Read the result as a floor, not a verdict.  Passing is necessary and far
    from sufficient: no statistical suite has broken a serious cipher, and a
    full-round design passing tells you almost nothing.  What is informative
    is *where* a reduced-round version starts passing -- a cipher still
    failing at round r has no diffusion worth the name by round r, and that
    conclusion needs no trail search to support it.

    test_type: "avalanche", "correlation", "cbc", "random", "low_density",
               "high_density"

    NIST recommends at least 10^6 bits per sequence and 55 or more sequences
    for the full battery; the defaults here are smaller so a first look
    finishes in minutes, and the returned dict says what was actually used.
    """
    from claasp.cipher_modules.statistical_tests.nist_statistical_tests \
        import NISTStatisticalTests

    if not os.path.exists("/usr/local/bin/sts-2.1.2/assess"):
        raise RuntimeError(
            "NIST STS is not installed. CLAASP expects "
            "/usr/local/bin/sts-2.1.2/assess; run setup_nist.py to build it.")

    round_end = cipher.number_of_rounds - 1 if round_end is None else round_end
    t0 = time.time()
    raw = NISTStatisticalTests(cipher).nist_statistical_tests(
        test_type, bits_in_one_sequence=bits_per_sequence,
        number_of_sequences=sequences,
        round_start=round_start, round_end=round_end)
    elapsed = time.time() - t0

    rounds = []
    for entry in raw.get("test_results", []):
        tests = entry.get("randomness_test", [])
        passed = sum(1 for t in tests if t.get("passed"))
        rounds.append({
            "passed": passed,
            "total": len(tests),
            "rate": passed / len(tests) if tests else 0.0,
            "failing": [t.get("test_id") for t in tests
                        if not t.get("passed")][:20],
        })

    out = {
        "test_type": test_type,
        "bits_per_sequence": bits_per_sequence,
        "sequences": sequences,
        "total_bits": bits_per_sequence * sequences,
        "rounds": rounds,
        "seconds": round(elapsed, 1),
        "standard": "NIST SP 800-22 rev1a, via STS 2.1.2",
        "caveat": (
            "passing is necessary, not sufficient. NIST recommends >= 10^6 "
            f"bits per sequence and >= 55 sequences; this run used "
            f"{bits_per_sequence:,} x {sequences}. Use it to find the round "
            "at which a reduced cipher starts passing, not to certify one "
            "that does."),
    }
    if verbose:
        for i, r in enumerate(rounds):
            print(f"  round {round_start + i}: {r['passed']}/{r['total']} "
                  f"sub-tests passed ({r['rate']:.1%})")
        print(f"  {bits_per_sequence:,} bits x {sequences} sequences, "
              f"{elapsed:.0f}s")
        print(f"  {out['caveat']}")
    return out


def nist_round_sweep(cipher_factory, rounds, **kw):
    """
    Where does a reduced cipher start looking random?

    cipher_factory(n) must return the cipher at n rounds.  This is the one
    reading of a statistical suite that is worth having: the round at which
    failures stop is a diffusion measurement, and it is independent of the
    trail search, so the two corroborate rather than repeat each other.
    """
    out = []
    for n in rounds:
        r = nist(cipher_factory(n), round_start=n - 1, round_end=n - 1,
                 verbose=False, **kw)
        rate = r["rounds"][0]["rate"] if r["rounds"] else 0.0
        passed = r["rounds"][0]["passed"] if r["rounds"] else 0
        total = r["rounds"][0]["total"] if r["rounds"] else 0
        out.append({"rounds": n, "passed": passed, "total": total,
                    "rate": rate})
        print(f"  {n:>2} rounds: {passed:>4}/{total} ({rate:.1%})")
    return out


# ==========================================================================
# Diffusion, with no external tool
# ==========================================================================

def avalanche(cipher, samples=512, seed=0, verbose=True):
    """
    Flip one input bit, count how many output bits change.

    The ideal is half the block. This is the cheapest diffusion measurement
    there is -- no solver, no external binary -- and it catches the coarse
    failures: a round count so low the cipher barely mixes, or a wiring
    mistake that leaves part of the state untouched.

    It says nothing about differential security. A cipher can have textbook
    avalanche and a weight-8 characteristic over three rounds; PRESENT does.
    """
    import random

    block_bits = cipher.output_bit_size
    key_bits = cipher.inputs_bit_size[cipher.inputs.index("key")]
    random.seed(seed)

    def sweep(which):
        total, worst_low, worst_high = 0, block_bits, 0
        untouched = (1 << block_bits) - 1
        for _ in range(samples):
            p = random.getrandbits(block_bits)
            k = random.getrandbits(key_bits)
            bit = random.randrange(block_bits if which == "plaintext"
                                   else key_bits)
            if which == "plaintext":
                d = cipher.evaluate([p, k]) ^ cipher.evaluate(
                    [p ^ (1 << bit), k])
            else:
                d = cipher.evaluate([p, k]) ^ cipher.evaluate(
                    [p, k ^ (1 << bit)])
            n = bin(d).count("1")
            total += n
            worst_low = min(worst_low, n)
            worst_high = max(worst_high, n)
            untouched &= ~d
        return {"mean": total / samples, "min": worst_low, "max": worst_high,
                "never_changed_bits": bin(untouched).count("1")}

    out = {"block_bits": block_bits, "samples": samples,
           "ideal": block_bits / 2,
           "plaintext": sweep("plaintext"), "key": sweep("key")}
    out["verdict"] = _avalanche_verdict(out)
    if verbose:
        for which in ("plaintext", "key"):
            s = out[which]
            print(f"  {which:<10} {s['mean']:.2f} / {block_bits} bits change "
                  f"(ideal {block_bits / 2:.0f}, range {s['min']}-{s['max']})")
            if s["never_changed_bits"]:
                print(f"             {s['never_changed_bits']} output bit(s) "
                      f"never changed at all")
        print(f"  {out['verdict']}")
    return out


def _avalanche_verdict(out):
    bad = []
    ks = out["key"]
    if ks["never_changed_bits"] == out["block_bits"]:
        return ("the key input does not reach the output at all. For a "
                "cipher whose key schedule is drawn this is a fault; for one "
                "whose round keys are supplied as constants -- PRESENT here, "
                "because its 80-bit key register exceeds a Digital bus -- it "
                "is expected, and only the plaintext row is meaningful")
    for which in ("plaintext", "key"):
        s = out[which]
        if s["never_changed_bits"]:
            bad.append(f"{s['never_changed_bits']} output bits never respond "
                       f"to a {which} bit -- that is a wiring fault or too "
                       f"few rounds, not a statistical fluctuation")
        elif abs(s["mean"] - out["ideal"]) > out["ideal"] * 0.1:
            bad.append(f"{which} avalanche is {s['mean']:.1f} against an "
                       f"ideal of {out['ideal']:.0f}")
    if bad:
        return "; ".join(bad)
    return ("avalanche is close to ideal in both inputs. Necessary, not "
            "sufficient: it says nothing about differential characteristics")


def diffusion(cipher, trials_per_bit=4, seed=0, verbose=False):
    """
    Which output bits each input bit can reach, as a coverage figure.

    Full coverage is the round count at which every input bit influences
    every output bit -- the R_f that meet-in-the-middle bounds are quoted
    against, and a number designers state and rarely show their working for.
    """
    import random

    block_bits = cipher.output_bit_size
    key_bits = cipher.inputs_bit_size[cipher.inputs.index("key")]
    random.seed(seed)

    # Union over several random (plaintext, key) pairs per input bit.  One
    # pair only shows the bits that happened to flip for it; the question is
    # which bits *can* flip, so the evidence has to accumulate.
    #
    # Cost is 2 * block_bits * trials_per_bit calls to evaluate(), which for a
    # 128-bit block at eight trials is two thousand of them.  CLAASP's
    # evaluate() is not fast, so the default is deliberately small and the
    # result is documented as an upper bound on R_f rather than a measurement
    # of it.  Raise trials_per_bit when a figure sits just short of full.
    reach = [0] * block_bits
    for bit in range(block_bits):
        acc = 0
        for _ in range(trials_per_bit):
            p = random.getrandbits(block_bits)
            k = random.getrandbits(key_bits)
            acc |= cipher.evaluate([p, k]) ^ cipher.evaluate(
                [p ^ (1 << bit), k])
        reach[bit] = bin(acc).count("1")

    full = sum(1 for r in reach if r == block_bits)
    return {
        "block_bits": block_bits,
        "trials_per_bit": trials_per_bit,
        "input_bits_reaching_every_output": full,
        "min_reach": min(reach), "max_reach": max(reach),
        "mean_reach": sum(reach) / len(reach),
        "full_diffusion": full == block_bits,
        "note": ("full diffusion means every input bit can change every "
                 "output bit. The round count where this first holds is the "
                 "R_f quoted in meet-in-the-middle bounds"),
        "coverage": round(sum(reach) / (block_bits * block_bits), 4),
        "caveat": (f"{trials_per_bit} random pairs per input bit. Sampling "
                   f"can miss a dependency that only shows up rarely, so a "
                   f"round count reported here is an upper bound on the "
                   f"true R_f; it never reports a dependency that is absent. "
                   f"Raise trials_per_bit if the figure sits just short of "
                   f"full."),
    }
