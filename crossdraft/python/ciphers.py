"""
ciphers -- one module per cipher, each a worked example to copy.

A cipher here supplies four things:

    PARTS      {name: builder function}   the circuits to draw
    REFERENCE  a plain-Python encrypt     to check the drawing against
    VECTORS    published test vectors     to check the reference against
    PLAN       how the parts are iterated and wired together

That order matters.  The published vectors pin down the reference; the
reference pins down the circuit; the circuit pins down the CLAASP model.  Skip
a link and a mistake at that point becomes invisible: a wrong CLAASP model
still yields plausible differential trails, with nothing to compare them to.

To add a cipher, copy one of these and replace the round function.  Nothing
else in the toolchain needs to know about it.
"""

# ==========================================================================
# PRESENT-80
#
#   Bogdanov et al., "PRESENT: An Ultra-Lightweight Block Cipher", CHES 2007.
#   64-bit block, 80-bit key, 31 rounds.
#
# Included because its diffusion is a bit permutation, which is the expensive
# case: pLayer costs 64 wires where a rotation costs two splitters.  The key
# register is 80 bits and so exceeds what one Digital bus carries, so the data
# path is drawn and the round keys are supplied from outside.
# ==========================================================================

PRESENT_SBOX = [0xC, 5, 6, 0xB, 9, 0, 0xA, 0xD, 3, 0xE, 0xF, 8, 4, 7, 1, 2]

# pLayer: input bit i moves to output bit P[i].
PRESENT_P = [(16 * i) % 63 for i in range(63)] + [63]

# The specification states pLayer forwards: input bit i moves to output bit
# P[i].  permute() states it backwards: output bit j takes input bit MAP[j].
# Both describe the same permutation and each is the other's inverse, so
# feeding one where the other is expected yields a working circuit computing
# the wrong direction -- which no test on the layer alone would reveal.
PRESENT_PMAP = [0] * 64
for _i, _p in enumerate(PRESENT_P):
    PRESENT_PMAP[_p] = _i


def present_round(b):
    """
    One PRESENT round: addRoundKey, sBoxLayer, pLayer.

        state' = pLayer(sBoxLayer(state xor rk))

    'state' pairs with "state'" and is therefore the loop variable; 'rk' has
    no partner and is supplied per round.
    """
    state = b.inp("state", 64)
    rk = b.inp("rk", 64)
    x = b.xor(state, rk)
    x = b.sbox_layer(x, PRESENT_SBOX, tag="S")
    x = b.permute(x, PRESENT_PMAP)
    b.out("state'", x)


def present_keystep(b):
    """
    One step of the PRESENT-80 key schedule, as a circuit.

        K <<< 61 ; S-box the top nibble ; xor the round counter into k19..k15

    The register is 80 bits, which no single Digital bus carries, so it is a
    Wide: two ports, and the rotation crosses the boundary between them.  The
    round key is the leading 64 bits, which the data path takes as `rk`.

    `rc` arrives as a per-round argument rather than being drawn, because the
    counter differs every round and a constant on the schematic could not.
    """
    k = b.wide_in("k", 80)
    rc = b.wide_in("rc", 80)

    # The round key is the leading 64 bits of the register *before* it is
    # updated: PRESENT extracts K_i, then rotates, substitutes and counts.
    # Taking it afterwards shifts every round key by one and the cipher is
    # wrong from the first round, while still being a perfectly valid map.
    b.out("rk", b.wide_slice(k, 16, 80))

    k = b.wide_rotl(k, 61)
    top = b.sbox_layer(b.wide_slice(k, 76, 80), PRESENT_SBOX, tag="K")
    k = b.wide_splice(k, 76, top)
    k = b.wide_xor(k, rc)

    b.wide_out("k'", k)


def present_reference(plaintext, key, rounds=31):
    """PRESENT-80, straight from the specification."""
    keys = _present_round_keys(key, rounds)
    s = plaintext
    for r in range(rounds):
        s ^= keys[r]
        s = sum(PRESENT_SBOX[(s >> (4 * i)) & 0xF] << (4 * i)
                for i in range(16))
        t = 0
        for i in range(64):
            if (s >> i) & 1:
                t |= 1 << PRESENT_P[i]
        s = t
    return s ^ keys[rounds]


def _present_round_keys(key, rounds):
    k, out = key, []
    for r in range(1, rounds + 2):
        out.append(k >> 16)
        k = ((k << 61) | (k >> 19)) & ((1 << 80) - 1)
        k = (k & ((1 << 76) - 1)) | (PRESENT_SBOX[k >> 76] << 76)
        k ^= r << 15
    return out


PRESENT = {
    "name": "present",
    "parts": {"round": present_round, "keystep": present_keystep},
    "reference": present_reference,
    "state": ["state"],
    "block_bits": 64,
    "key_bits": 80,
    "rounds": 31,
    # PRESENT numbers bits from the LSB: its pLayer is stated as "input bit i
    # moves to output bit 16i mod 63", counting up from the least significant
    # end.  PRESENT_PMAP below is written in that convention.
    "bit_order": "lsb",
    # Published in the CHES 2007 paper; reproduced independently before use.
    "vectors": [
        (0x0000000000000000, 0x00000000000000000000, 0x5579C1387B228445),
        (0x0000000000000000, 0xFFFFFFFFFFFFFFFFFFFF, 0xE72C46C0F5945049),
        (0xFFFFFFFFFFFFFFFF, 0x00000000000000000000, 0xA112FFC72F68417B),
        (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFFFFFF, 0x3333DCD3213210D2),
    ],
    # The drawn schedule produces rk itself; only the round counter has to be
    # supplied, and it is xored in at bits 15..19 as the specification says.
    # The 80-bit register is two words, so the schedule's state is k_0 / k_1.
    # `rk` is an extra output of the keystep rather than a state variable:
    # it is the leading 64 bits of the register, which the data path consumes
    # and the schedule does not carry forward.
    "key_state": ["k_0", "k_1"],
    "key_extra": {"rk": "rk"},
    "final_key": "rk",
    "key_params": lambda i, key: {"rc_0": (i + 1) << 15, "rc_1": 0},
    "params": lambda i, key: {},
    # PRESENT ends with one more addRoundKey after the last round.  That
    # trailing XOR is not part of the round function and so is not on the
    # schematic; declaring it here keeps the circuit a clean single round.

    "note": "80-bit key register exceeds one Digital bus, so round keys are "
            "supplied from outside; the trailing whitening key is applied "
            "after the loop.",
}


# ==========================================================================
# LLBC-128-128
#
#   Li, Wei, Pasalic, Li, Fan, IEEE Internet of Things J. 12(21), Nov 2025.
#   128-bit block, 128-bit key, 20 rounds, Feistel.
#
# Two readings of the paper are forced and both are load-bearing:
#
#   * Algorithm 1 line 7 omits R_i.  Taken literally the right half never
#     reaches the ciphertext and the map is not a permutation; Fig. 2 shows
#     R_i entering the final XOR, and that is what is drawn here.
#   * MixWord's M_L port takes SubCell2's output, not SubCell1's.  Reading
#     MixWord(L', L'') positionally against Eq. (1) suggests the opposite, but
#     Fig. 1 puts the S1 bank above the S2 bank while Fig. 2 puts M_R above
#     M_L, and the published characteristics are unrealisable the other way.
#
# Everything is 64 bits or narrower and the diffusion is rotations, so LLBC is
# markedly cheaper to draw than PRESENT.
# ==========================================================================

LLBC_S1 = [0x4, 0x7, 0x5, 0x1, 0xC, 0xB, 0xD, 0x8,
           0xE, 0xF, 0x6, 0x3, 0xA, 0x9, 0x2, 0x0]
LLBC_S2 = [0xE, 0xC, 0x8, 0x4, 0xB, 0xD, 0x1, 0x5,
           0xF, 0x3, 0xA, 0x2, 0x9, 0x7, 0x0, 0x6]
LLBC_B1, LLBC_B2 = 3, 19          # Table V, published specification
LLBC_RC0 = 0x243F6A88             # Table III
M64 = (1 << 64) - 1


def llbc_rc(i):
    k = i % 32
    r = ((LLBC_RC0 << k) | (LLBC_RC0 >> (32 - k))) & 0xFFFFFFFF if k \
        else LLBC_RC0
    return r << 32


def _rol(x, n, w=64):
    n %= w
    return ((x << n) | (x >> (w - n))) & ((1 << w) - 1) if n else x


def llbc_round(b):
    """
    One LLBC round.

        T  = L xor rk_hi xor rc
        L' = R xor MixWord(SubCell1(L <<< 3), SubCell2(T <<< 19)) xor rk_lo
        R' = T
    """
    L = b.inp("L", 64)
    R = b.inp("R", 64)
    rk_lo = b.inp("rk_lo", 64)
    rk_hi = b.inp("rk_hi", 64)
    rc = b.inp("rc", 64)

    T = b.xor(L, rk_hi, rc)
    s1 = b.sbox_layer(b.rotl(L, LLBC_B1), LLBC_S1, tag="A")
    s2 = b.sbox_layer(b.rotl(T, LLBC_B2), LLBC_S2, tag="B")

    # MixWord, Eq. (1), with M_L = SubCell2 output.
    s = b.xor(s2, s1)
    t0 = b.xor(b.rotl(s, LLBC_B1), s2)
    t1 = b.xor(b.rotl(t0, LLBC_B2), s)
    a = b.xor(b.rotl(t1, LLBC_B1), t0)
    bb = b.xor(b.rotl(a, LLBC_B2), t1)
    m = b.xor(a, bb)

    b.out("L'", b.xor(R, m, rk_lo))
    b.out("R'", T)


def llbc_keystep(b):
    """
    One step of the key schedule.

        k0' = k1
        k1' = G(G(k1)) xor k0 xor rc

    G treats its 64-bit argument as four 16-bit words w0..w3, w0 most
    significant, and returns
        (w0<<<3 xor w2) || (w1<<<1 xor w3) || w0<<<3 || w1<<<1
    """
    k0 = b.inp("k0", 64)
    k1 = b.inp("k1", 64)
    rc = b.inp("rc", 64)

    def G(src):
        w = b.words(src, 16)          # w[0] is the least significant word
        w0, w1, w2, w3 = w[3], w[2], w[1], w[0]
        r0 = b.rotl(w0, 3)
        r1 = b.rotl(w1, 1)
        o0 = b.xor(r0, w2)
        o1 = b.xor(r1, w3)
        return b.join([r1, r0, o1, o0])   # reversed: join takes LSW first

    b.out("k0'", k1)
    b.out("k1'", b.xor(G(G(k1)), k0, rc))


def llbc_G(k):
    w = [(k >> (16 * (3 - i))) & 0xFFFF for i in range(4)]
    r0, r1 = _rol(w[0], 3, 16), _rol(w[1], 1, 16)
    o = [r0 ^ w[2], r1 ^ w[3], r0, r1]
    return sum(o[i] << (16 * (3 - i)) for i in range(4))


def llbc_reference(plaintext, key, rounds=20):
    """
    LLBC-128-128 under the published specification, with the two readings
    documented at the top of this section.
    """
    L, R = (plaintext >> 64) & M64, plaintext & M64
    ks = [(key >> 64) & M64, key & M64]
    for j in range(rounds):
        ks.append(llbc_G(llbc_G(ks[j + 1])) ^ ks[j] ^ llbc_rc(j))
    for i in range(rounds):
        lo, hi = ks[i], ks[i + 1]
        T = L ^ hi ^ llbc_rc(i)
        s1 = sum(LLBC_S1[(_rol(L, LLBC_B1) >> (4 * j)) & 0xF] << (4 * j)
                 for j in range(16))
        s2 = sum(LLBC_S2[(_rol(T, LLBC_B2) >> (4 * j)) & 0xF] << (4 * j)
                 for j in range(16))
        ml, mr = s2, s1
        s = ml ^ mr
        t0 = _rol(s, LLBC_B1) ^ ml
        t1 = _rol(t0, LLBC_B2) ^ s
        a = _rol(t1, LLBC_B1) ^ t0
        m = a ^ (_rol(a, LLBC_B2) ^ t1)
        L, R = R ^ m ^ lo, T
    return (L << 64) | R


LLBC = {
    "name": "llbc",
    "parts": {"round": llbc_round, "keystep": llbc_keystep},
    "reference": llbc_reference,
    "state": ["L", "R"],
    "key_state": ["k0", "k1"],
    "key_map": {"rk_lo": "k0", "rk_hi": "k1"},
    "block_bits": 128,
    "key_bits": 128,
    "rounds": 20,
    "bit_order": "lsb",
    # The appendix vectors of the proposal correspond to (b1,b2) = (32,16),
    # which is what the authors' reference code uses, not the (3,19) of
    # Table V that the paper specifies and that is analysed here.  There is
    # therefore no published vector for the specified cipher; the reference
    # implementation is checked by invertibility and avalanche instead.
    "vectors": [],
    "params": lambda i, key: {"rc": llbc_rc(i)},
    "key_params": lambda i, key: {"rc": llbc_rc(i)},
    "note": "specification (b1,b2)=(3,19); the authors' GitHub code uses "
            "(32,16) and the paper's own test vectors match the code, not "
            "the specification.",
}


REGISTRY = {c["name"]: c for c in (PRESENT, LLBC)}


def claasp_kwargs(spec, rounds, outdir, key=0):
    """
    The build_cipher arguments for one cipher, in one place.

    A cipher's key schedule is wired up by several optional keys -- key_map,
    key_extra, final_key -- and every caller that assembles them by hand gets
    a chance to omit one and fail with "input 'rk' is neither state nor
    supplied".  Callers ask here instead.
    """
    import os

    kw = {
        "rounds": rounds,
        "params": lambda i: spec["params"](i, key),
        "block_bits": spec["block_bits"],
        "key_bits": spec["key_bits"],
        "family_name": spec["name"],
    }
    kj = os.path.join(outdir, f"{spec['name']}_keystep.json")
    if "keystep" in spec["parts"] and os.path.exists(kj):
        kw["key_json"] = kj
        kw["key_params"] = lambda i: spec.get(
            "key_params", lambda i, k: {})(i, key)
        for opt in ("key_map", "key_extra", "final_key"):
            if spec.get(opt):
                kw[opt] = spec[opt]
    return kw


def load(name, rounds, outdir, key=0):
    """Build the CLAASP object for a registered cipher."""
    import os
    from dig2claasp import build_cipher

    spec = REGISTRY[name]
    rj = os.path.join(outdir, f"{spec['name']}_round.json")
    if not os.path.exists(rj):
        raise FileNotFoundError(f"{rj} missing; run `digcli.py build {name}`")
    return build_cipher(rj, **claasp_kwargs(spec, rounds, outdir, key))
