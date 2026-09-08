"""
digattack -- searches beyond one differential characteristic.

    from digattack import cluster, impossible_differentials, zero_correlation

    cluster(cipher, trail)                 # characteristic -> differential
    impossible_differentials(cipher)       # what cannot happen
    zero_correlation(cipher)               # the linear counterpart

Each is optional and each is slow in its own way, so they are separate calls
rather than part of `analyse`.

A note that applies to all three: a search that returns nothing has not proved
anything.  SAT and CP models are decision procedures with no useful bound on
running time, so "not found" and "does not exist" are different claims and
only the second needs an UNSAT certificate.  Every function here reports
which one it got.
"""

import math
import time

__all__ = ["cluster", "impossible_differentials", "zero_correlation",
           "differential_bound"]


def _fixed(cipher, key_bits, block_bits, plaintext=None, ciphertext=None):
    from claasp.cipher_modules.models.utils import (set_fixed_variables,
                                                    integer_to_bit_list)
    out = [set_fixed_variables("key", "equal", list(range(key_bits)),
                               [0] * key_bits)]
    if plaintext is None:
        out.append(set_fixed_variables("plaintext", "not_equal",
                                       list(range(block_bits)),
                                       [0] * block_bits))
    else:
        out.append(set_fixed_variables(
            "plaintext", "equal", list(range(block_bits)),
            integer_to_bit_list(plaintext, block_bits, "big")))
    if ciphertext is not None:
        last = cipher.get_all_components_ids()[-1]
        out.append(set_fixed_variables(
            last, "equal", list(range(block_bits)),
            integer_to_bit_list(ciphertext, block_bits, "big")))
    return out


# --------------------------------------------------------------------------

def cluster(cipher, input_diff, output_diff, weight, extra_weight=0,
            key_bits=None, block_bits=None, solver="KISSAT_EXT",
            verbose=True):
    """
    Sum every characteristic joining one input difference to one output
    difference.

    A trail search returns a single characteristic; an attack is governed by
    the differential, which is the sum over all of them.  The two differ
    whenever several paths share endpoints, and the difference is free
    probability -- the distinguisher can only get stronger, never weaker.

    That matters when a key recovery sits near a bound.  A data complexity of
    2^127 against a 128-bit block is at the edge of the codebook; a few bits
    of clustering gain move the result from "boundary case" to "attack".

    extra_weight widens the search to weights [w, w+extra], since heavier
    characteristics still contribute.  Cost grows quickly with it.
    """
    from claasp.cipher_modules.models.sat.sat_models \
        .sat_xor_differential_model import SatXorDifferentialModel

    block_bits = block_bits or cipher.output_bit_size
    key_bits = key_bits or cipher.inputs_bit_size[
        cipher.inputs.index("key")]

    model = SatXorDifferentialModel(cipher)
    fixed = _fixed(cipher, key_bits, block_bits, input_diff, output_diff)

    t0 = time.time()
    if extra_weight:
        trails = model.find_all_xor_differential_trails_with_weight_at_most(
            weight, weight + extra_weight, fixed_values=fixed,
            solver_name=solver)
    else:
        trails = model.find_all_xor_differential_trails_with_fixed_weight(
            weight, fixed_values=fixed, solver_name=solver)
    elapsed = time.time() - t0

    buckets = {}
    for t in trails:
        w = t["total_weight"]
        buckets[w] = buckets.get(w, 0) + 1

    total = sum(n * 2.0 ** (-w) for w, n in buckets.items())
    result = {
        "input_diff": input_diff,
        "output_diff": output_diff,
        "characteristic_weight": weight,
        "trails": len(trails),
        "by_weight": dict(sorted(buckets.items())),
        "differential_probability_log2": (math.log2(total) if total
                                          else None),
        "gain_bits": (math.log2(total) + weight) if total else 0.0,
        "seconds": round(elapsed, 1),
        "note": ("a lower bound on the differential: only the weights "
                 "searched are counted, and heavier characteristics that were "
                 "not enumerated would add to it"),
    }
    if verbose:
        print(f"  differential {input_diff:#x} -> {output_diff:#x}")
        print(f"  {len(trails)} characteristic(s) in "
              f"{elapsed:.1f}s")
        for w, n in result["by_weight"].items():
            print(f"    weight {w:g}: {n}")
        if total:
            print(f"  differential probability >= "
                  f"2^{result['differential_probability_log2']:.4f} "
                  f"(single characteristic 2^-{weight:g})")
            print(f"  gain {result['gain_bits']:.4f} bits")
    return result


def cluster_from_trail(cipher, trail, extra_weight=0, **kw):
    """cluster() with the endpoints taken from a trail CLAASP just returned."""
    cv = trail["components_values"]
    last = cipher.get_all_components_ids()[-1]
    return cluster(cipher,
                   int(cv["plaintext"]["value"], 16),
                   int(cv[last]["value"], 16),
                   int(trail["total_weight"]),
                   extra_weight=extra_weight, **kw)


# --------------------------------------------------------------------------

def impossible_differentials(cipher, cell_bits=4, key_bits=None,
                             block_bits=None, solver="Chuffed",
                             max_pairs=None, verbose=True):
    """
    Input/output difference pairs that cannot occur.

    Proved, not observed: each candidate pair is asserted and the model is
    asked for any characteristic realising it.  UNSATISFIABLE is the proof.
    A pair that merely fails to turn up in a trail search proves nothing.

    Candidates are single active cells at each end, which is where impossible
    differentials are found in practice and keeps the sweep to (n/c)^2 solver
    calls rather than 2^2n.

    The search runs on the SAT model.  CLAASP's dedicated impossible-
    differential models are CP and need a MiniZinc installation; asking the
    SAT model for any characteristic and taking UNSAT as the answer needs only
    a SAT solver and proves exactly the same thing.
    """
    from claasp.cipher_modules.models.utils import (set_fixed_variables,
                                                    integer_to_bit_list)
    from claasp.cipher_modules.models.sat.sat_models \
        .sat_xor_differential_model import SatXorDifferentialModel

    block_bits = block_bits or cipher.output_bit_size
    key_bits = key_bits or cipher.inputs_bit_size[
        cipher.inputs.index("key")]
    cells = block_bits // cell_bits
    last = cipher.get_all_components_ids()[-1]
    model = SatXorDifferentialModel(cipher)
    if solver in ("Chuffed", "chuffed"):
        solver = "KISSAT_EXT"

    found, tested, t0 = [], 0, time.time()
    for i in range(cells):
        in_active = list(range(cell_bits * i, cell_bits * (i + 1)))
        in_zero = [b for b in range(block_bits) if b not in in_active]
        for j in range(cells):
            if max_pairs and tested >= max_pairs:
                break
            out_active = list(range(cell_bits * j, cell_bits * (j + 1)))
            out_zero = [b for b in range(block_bits) if b not in out_active]
            fixed = [
                set_fixed_variables("key", "equal", list(range(key_bits)),
                                    [0] * key_bits),
                set_fixed_variables("plaintext", "equal", in_zero,
                                    integer_to_bit_list(0, len(in_zero),
                                                        "big")),
                set_fixed_variables(last, "equal", out_zero,
                                    integer_to_bit_list(0, len(out_zero),
                                                        "big")),
                set_fixed_variables("plaintext", "not_equal", in_active,
                                    integer_to_bit_list(0, len(in_active),
                                                        "big")),
                set_fixed_variables(last, "not_equal", out_active,
                                    integer_to_bit_list(0, len(out_active),
                                                        "big")),
            ]
            sol = model.find_one_xor_differential_trail(
                fixed_values=fixed, solver_name=solver)
            tested += 1
            if sol.get("status") == "UNSATISFIABLE":
                found.append((i, j))
                if verbose:
                    print(f"    impossible: input cell {i} -> "
                          f"output cell {j}")
    return {
        "cell_bits": cell_bits,
        "cells": cells,
        "tested_pairs": tested,
        "impossible": found,
        "seconds": round(time.time() - t0, 1),
        "note": ("each entry is an UNSAT certificate, so these are proved "
                 "impossible for this round count. The sweep covers "
                 "single-active-cell pairs only; wider truncated patterns "
                 "may hold more"),
    }


def zero_correlation(cipher, cell_bits=4, key_bits=None, block_bits=None,
                     solver="Chuffed", max_pairs=None, verbose=True):
    """
    The linear counterpart: input/output mask pairs of correlation zero.

    Same shape of argument as impossible differentials, over the linear model
    instead of the differential one, and the same caveat: UNSAT is the proof.
    """
    from claasp.cipher_modules.models.utils import (set_fixed_variables,
                                                    integer_to_bit_list)

    block_bits = block_bits or cipher.output_bit_size
    key_bits = key_bits or cipher.inputs_bit_size[
        cipher.inputs.index("key")]
    cells = block_bits // cell_bits
    last = cipher.get_all_components_ids()[-1]

    from claasp.cipher_modules.models.sat.sat_models.sat_xor_linear_model \
        import SatXorLinearModel
    model = SatXorLinearModel(cipher)
    if solver in ("Chuffed", "chuffed"):
        solver = "KISSAT_EXT"

    found, tested, t0 = [], 0, time.time()
    for i in range(cells):
        in_active = list(range(cell_bits * i, cell_bits * (i + 1)))
        in_zero = [b for b in range(block_bits) if b not in in_active]
        for j in range(cells):
            if max_pairs and tested >= max_pairs:
                break
            out_active = list(range(cell_bits * j, cell_bits * (j + 1)))
            out_zero = [b for b in range(block_bits) if b not in out_active]
            fixed = [
                set_fixed_variables("key", "equal", list(range(key_bits)),
                                    [0] * key_bits),
                set_fixed_variables("plaintext", "equal", in_zero,
                                    integer_to_bit_list(0, len(in_zero),
                                                        "big")),
                set_fixed_variables(last, "equal", out_zero,
                                    integer_to_bit_list(0, len(out_zero),
                                                        "big")),
                set_fixed_variables("plaintext", "not_equal", in_active,
                                    integer_to_bit_list(0, len(in_active),
                                                        "big")),
                set_fixed_variables(last, "not_equal", out_active,
                                    integer_to_bit_list(0, len(out_active),
                                                        "big")),
            ]
            sol = model.find_one_xor_linear_trail(fixed_values=fixed,
                                                  solver_name=solver)
            tested += 1
            if sol.get("status") == "UNSATISFIABLE":
                found.append((i, j))
                if verbose:
                    print(f"    zero correlation: input cell {i} -> "
                          f"output cell {j}")
    return {"cell_bits": cell_bits, "cells": cells, "tested_pairs": tested,
            "zero_correlation": found,
            "seconds": round(time.time() - t0, 1),
            "note": "UNSAT certificates, as for impossible differentials"}


# --------------------------------------------------------------------------

def differential_bound(cipher, weights, key_bits=None, block_bits=None,
                       solver="KISSAT_EXT", verbose=True):
    """
    Ask whether a characteristic of a given weight exists, one weight at a
    time, instead of minimising.

    Minimising has to prove that nothing lighter exists, which is where the
    time goes -- the LLBC designers report 482 hours for a 7-round optimum.
    A designer's claim is usually of the form "no trail beats 2^-n", and that
    is a satisfiability question at a single weight, which is far cheaper and
    answers what was actually claimed.

    Returns [(weight, "SATISFIABLE" | "UNSATISFIABLE" | ..., seconds)].
    """
    from claasp.cipher_modules.models.sat.sat_models \
        .sat_xor_differential_model import SatXorDifferentialModel

    block_bits = block_bits or cipher.output_bit_size
    key_bits = key_bits or cipher.inputs_bit_size[
        cipher.inputs.index("key")]
    model = SatXorDifferentialModel(cipher)
    fixed = _fixed(cipher, key_bits, block_bits)

    out = []
    for w in weights:
        t0 = time.time()
        sol = model.find_one_xor_differential_trail_with_fixed_weight(
            w, fixed_values=fixed, solver_name=solver)
        dt = round(time.time() - t0, 1)
        status = sol.get("status", "?")
        out.append((w, status, dt))
        if verbose:
            meaning = ("a characteristic of this weight exists"
                       if status == "SATISFIABLE"
                       else "no characteristic of this weight"
                       if status == "UNSATISFIABLE" else status)
            print(f"    weight {w:>4}: {status:<14} {meaning}  [{dt}s]")
    return out
