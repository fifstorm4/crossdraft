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


# ==========================================================================
# SPECK 32/64
#
#   R. Beaulieu, D. Shors, J. Smith, S. Treatman-Clark, B. Weeks, L. Wingers,
#   "The SIMON and SPECK Families of Lightweight Block Ciphers",
#   IACR ePrint 2013/404.
#
# Here because it is ARX, and because it is the smallest ARX design there is:
# the round is three operations. Speck exercises the one thing an S-box
# cipher never touches -- addition modulo 2^n, whose differential behaviour
# is where ARX analysis gets hard, since the probability of a difference
# through an adder depends on the values and not only on the difference.
#
#   x = (x >>> 7) + y  (mod 2^16),  x ^= k
#   y = (y <<< 2) ^ x
#
# The rotation amounts are 7 and 2 for the 16-bit word size; larger Speck
# variants use 8 and 3.
# ==========================================================================

SPECK_ALPHA, SPECK_BETA = 7, 2
SPECK_WORD = 16


def _speck_round(x, y, k, w=SPECK_WORD, a=SPECK_ALPHA, b=SPECK_BETA):
    m = (1 << w) - 1
    x = (((x >> a) | (x << (w - a))) & m)
    x = (x + y) & m
    x ^= k
    y = (((y << b) | (y >> (w - b))) & m) ^ x
    return x, y


def speck_round(b):
    """
    One Speck round, with the round key supplied from outside.

    Speck's key schedule is the round function applied to the key words, so
    drawing it would repeat this circuit; the round keys are computed in the
    reference instead and handed in, which keeps this example about the ARX
    operations rather than about wiring.
    """
    x = b.inp("x", SPECK_WORD)
    y = b.inp("y", SPECK_WORD)
    k = b.inp("rk", SPECK_WORD)

    xr = b.rotr(x, SPECK_ALPHA)
    xn = b.xor(b.modadd(xr, y), k)
    yn = b.xor(b.rotl(y, SPECK_BETA), xn)

    b.out("x'", xn)
    b.out("y'", yn)


def _speck_round_keys(key, rounds):
    """l[2], l[1], l[0], k[0] packed little-endian, as the paper writes it."""
    m = (1 << SPECK_WORD) - 1
    words = [(key >> (SPECK_WORD * i)) & m for i in range(4)]
    k = [words[0]]
    ell = words[1:]
    for i in range(rounds - 1):
        new_l, new_k = _speck_round(ell[i % len(ell)], k[i], i)
        ell.append(new_l)
        k.append(new_k)
    return k


def speck_reference(plaintext, key, rounds=22):
    m = (1 << SPECK_WORD) - 1
    x, y = (plaintext >> SPECK_WORD) & m, plaintext & m
    for k in _speck_round_keys(key, rounds):
        x, y = _speck_round(x, y, k)
    return (x << SPECK_WORD) | y


SPECK = {
    "name": "speck",
    "parts": {"round": speck_round},
    "reference": speck_reference,
    "state": ["x", "y"],
    "block_bits": 32,
    "key_bits": 64,
    "rounds": 22,
    "bit_order": "lsb",
    # From the SIMON and SPECK paper's test-vector appendix.
    "vectors": [(0x6574694C, 0x1918111009080100, 0xA86842F2)],
    "params": lambda i, key: {"rk": _speck_round_keys(key, 22)[i]},
    "note": "ARX. The key schedule reuses the round function, so round keys "
            "are supplied from the reference rather than drawn.",
}


# ==========================================================================
# GIFT-64-128
#
#   S. Banik, S. K. Pandey, T. Peyrin, Y. Sasaki, S. M. Sim, Y. Todo,
#   "GIFT: A Small Present", CHES 2017.
#
# The third SPN here, and deliberately close to PRESENT: same shape, 4-bit
# S-boxes and a bit permutation, so the two can be built from the same parts
# and any assumption baked into having only PRESENT shows up.
#
# It differs in the two places that matter. The round key touches only two
# bits of each nibble rather than the whole state, so AddRoundKey is a
# masked XOR rather than a plain one; and the round constant is a 6-bit LFSR
# scattered across bits 3, 7, ..., 23 with bit 63 always set. Both are stated
# as constants supplied per round rather than drawn, because they change
# every round and a constant on the schematic could not.
# ==========================================================================

GIFT_SBOX = [1, 0xA, 4, 0xC, 6, 0xF, 3, 9,
             2, 0xD, 0xB, 7, 5, 0, 8, 0xE]


def _gift_p(i):
    """PermBits: input bit i moves to output bit P(i)."""
    return 4 * (i // 16) + 16 * ((3 * ((i % 16) // 4) + (i % 4)) % 4)         + (i % 4)


GIFT_P = [_gift_p(i) for i in range(64)]

# permute() states a permutation the other way round: out j takes in MAP[j].
GIFT_PMAP = [0] * 64
for _i, _p in enumerate(GIFT_P):
    GIFT_PMAP[_p] = _i


def gift_round(b):
    """
    One GIFT-64 round: SubCells, PermBits, AddRoundKey.

    `rk` arrives already spread across the state -- bit 4i takes v_i and bit
    4i+1 takes u_i -- and `rc` already carries the round constant in bits 3,
    7, ..., 23 and bit 63. Doing that spreading here would mean drawing
    thirty-two single-bit XORs; doing it in the driver keeps the round
    function to the three operations the specification names.
    """
    state = b.inp("state", 64)
    rk = b.inp("rk", 64)
    rc = b.inp("rc", 64)

    x = b.sbox_layer(state, GIFT_SBOX, tag="S")
    x = b.permute(x, GIFT_PMAP)
    b.out("state'", b.xor(x, rk, rc))


def _gift_key_schedule(key, rounds):
    """
    Round keys and constants, as (rk, rc) already positioned in the state.

    The key state is eight 16-bit words; each round takes u = k1 and v = k0,
    then rotates the whole state by two words with k0 and k1 rotated by 12
    and 2 on the way out.
    """
    w = [(key >> (16 * i)) & 0xFFFF for i in range(8)]
    c, out = 0, []
    for _ in range(rounds):
        c = ((c << 1) | (((c >> 5) & 1) ^ ((c >> 4) & 1) ^ 1)) & 0x3F
        u, v = w[1], w[0]
        rk = 0
        for i in range(16):
            if (v >> i) & 1:
                rk |= 1 << (4 * i)
            if (u >> i) & 1:
                rk |= 1 << (4 * i + 1)
        rc = 1 << 63
        for j in range(6):
            if (c >> j) & 1:
                rc |= 1 << (4 * j + 3)
        out.append((rk, rc))
        k0, k1 = w[0], w[1]
        w = w[2:] + [((k0 >> 12) | (k0 << 4)) & 0xFFFF,
                     ((k1 >> 2) | (k1 << 14)) & 0xFFFF]
    return out


def gift_reference(plaintext, key, rounds=28):
    state = plaintext
    for rk, rc in _gift_key_schedule(key, rounds):
        state = sum(GIFT_SBOX[(state >> (4 * i)) & 0xF] << (4 * i)
                    for i in range(16))
        moved = 0
        for i in range(64):
            if (state >> i) & 1:
                moved |= 1 << GIFT_P[i]
        state = moved ^ rk ^ rc
    return state


GIFT = {
    "name": "gift",
    "parts": {"round": gift_round},
    "reference": gift_reference,
    "state": ["state"],
    "block_bits": 64,
    "key_bits": 128,
    "rounds": 28,
    "bit_order": "lsb",
    # From the CHES 2017 appendix. The paper lists three; the second is
    # omitted here because it could not be confirmed against a second source
    # and a vector nobody has checked is worse than no vector at all.
    "vectors": [
        (0x0000000000000000, 0x00000000000000000000000000000000,
         0xF62BC3EF34F775AC),
        (0xC450C7727A9B8A7D, 0xBD91731EB6BC2713A1F9F6FFC75044E7,
         0xE3272885FA94BA8B),
    ],
    "params": lambda i, key: dict(zip(
        ("rk", "rc"), _gift_key_schedule(key, 28)[i])),
    "note": "the round key reaches only two bits of each nibble, and the "
            "round constant is a 6-bit LFSR; both are positioned by the "
            "driver rather than drawn.",
}


# ==========================================================================
# SIMON 32/64
#
#   R. Beaulieu, D. Shors, J. Smith, S. Treatman-Clark, B. Weeks, L. Wingers,
#   "The SIMON and SPECK Families of Lightweight Block Ciphers",
#   IACR ePrint 2013/404.
#
# Speck's sibling, and here for the operation Speck does not have. Simon's
# non-linearity is a bitwise AND rather than an addition:
#
#   x, y  ->  y xor ((x <<< 1) & (x <<< 8)) xor (x <<< 2) xor k,  x
#
# That makes it AND-RX rather than ARX, and it is the third kind of
# non-linear layer this toolchain has to model -- after the S-box lookup of
# PRESENT and GIFT, and the modular addition of Speck. All three now have a
# worked example, which is the point: a new design is usually a rearrangement
# of parts that already exist here.
# ==========================================================================

SIMON_WORD = 16
SIMON_ROUNDS = 32

# The five z sequences are 62-bit constants; Simon32/64 uses z0. Bits are
# taken from the top, so round i wants bit 61 - (i mod 62).
SIMON_Z = [4506230155203752166,
           2575579794259089498,
           3160415496042964403,
           3957284701066611983,
           3781244162168104175]
SIMON_Z0 = SIMON_Z[0]


def _srot(x, n, w=SIMON_WORD):
    n %= w
    return ((x << n) | (x >> (w - n))) & ((1 << w) - 1) if n else x


def simon_round(b):
    """
    One Simon round.

        x' = y xor ((x <<< 1) AND (x <<< 8)) xor (x <<< 2) xor rk
        y' = x

    Three rotations, one AND, three XORs. `gate("And", ...)` is the only
    piece here that no other example uses.
    """
    x = b.inp("x", SIMON_WORD)
    y = b.inp("y", SIMON_WORD)
    k = b.inp("rk", SIMON_WORD)

    f = b.xor(b.gate("And", b.rotl(x, 1), b.rotl(x, 8)), b.rotl(x, 2))
    b.out("x'", b.xor(y, f, k))
    b.out("y'", x)


def _simon_round_keys(key, rounds=SIMON_ROUNDS):
    """
    Simon32/64's key schedule, m = 4 words.

        k[i+4] = c xor z[i] xor k[i] xor (I xor S^-1)(S^-3 k[i+3] xor k[i+1])

    with c = 2^n - 4. Two details are easy to get backwards and both give a
    cipher that still looks like a cipher: the key words come out of the
    master key most significant first, so k[0] is the *high* word; and the z
    bit for round i is bit 61 - (i mod 62), counted from the top of the
    62-bit constant rather than the bottom.
    """
    m = (1 << SIMON_WORD) - 1
    c = m ^ 3                      # 2^n - 4
    words = 4
    k = [(key >> (SIMON_WORD * i)) & m for i in range(words)]
    for i in range(rounds - words):
        op = _srot(k[i + words - 1], -3 % SIMON_WORD)
        op ^= k[i + 1]
        op ^= _srot(op, -1 % SIMON_WORD)
        z = (SIMON_Z0 >> (61 - (i % 62))) & 1
        k.append(c ^ z ^ k[i] ^ op)
    return k[:rounds]


def simon_reference(plaintext, key, rounds=SIMON_ROUNDS):
    m = (1 << SIMON_WORD) - 1
    x, y = (plaintext >> SIMON_WORD) & m, plaintext & m
    for k in _simon_round_keys(key, rounds):
        x, y = y ^ (_srot(x, 1) & _srot(x, 8)) ^ _srot(x, 2) ^ k, x
    return (x << SIMON_WORD) | y


SIMON = {
    "name": "simon",
    "parts": {"round": simon_round},
    "reference": simon_reference,
    "state": ["x", "y"],
    "block_bits": 32,
    "key_bits": 64,
    "rounds": SIMON_ROUNDS,
    "bit_order": "lsb",
    "vectors": [(0x65656877, 0x1918111009080100, 0xC69BE9BB)],
    "params": lambda i, key: {"rk": _simon_round_keys(key)[i]},
    "note": "AND-RX. The non-linearity is a bitwise AND, so unlike Speck "
            "there is no carry and unlike PRESENT there is no lookup table.",
}


# ==========================================================================
# SKINNY-64-128
#
#   C. Beierle, J. Jean, S. Kolbl, G. Leander, A. Moradi, T. Peyrin,
#   Y. Sasaki, P. Sasdrich, S. M. Sim, "The SKINNY Family of Block Ciphers
#   and its Low-Latency Variant MANTIS", CRYPTO 2016.
#
# Here for MixColumns. SKINNY's matrix is binary -- no field multiplication
# at all -- which is the easy end of the same machinery that handles AES, and
# it means the round is four XORs per column rather than a table lookup.
#
# The tweakey is the other reason. Two 64-bit words are permuted every round
# and one of them is also stepped through a 4-bit LFSR, so the key schedule
# is a shuffle rather than an arithmetic recurrence. It is supplied from the
# reference here rather than drawn, for the same reason PRESENT's round keys
# once were: a cell permutation is sixteen wires and no logic, and drawing it
# would say nothing the constant does not.
# ==========================================================================

SKINNY_SBOX = [12, 6, 9, 0, 1, 10, 2, 11, 3, 8, 5, 13, 4, 14, 7, 15]

#: SKINNY's MixColumns. Binary, so mix_columns takes poly=None.
SKINNY_MC = [[1, 0, 1, 1],
             [1, 0, 0, 0],
             [0, 1, 1, 0],
             [1, 0, 1, 0]]

#: The tweakey cell permutation P_T.
SKINNY_PT = [9, 15, 8, 13, 10, 14, 12, 11, 0, 1, 2, 3, 4, 5, 6, 7]

SKINNY_CELL = 4
SKINNY_ROUNDS = 36


def _skinny_cells(x, n=16, w=SKINNY_CELL):
    return [(x >> (w * (n - 1 - i))) & ((1 << w) - 1) for i in range(n)]


def _skinny_pack(c, w=SKINNY_CELL):
    v = 0
    for x in c:
        v = (v << w) | x
    return v


def _skinny_rcs(n):
    """Round constants from a 6-bit LFSR."""
    out, c = [], 0
    for _ in range(n):
        c = ((c << 1) | (((c >> 5) & 1) ^ ((c >> 4) & 1) ^ 1)) & 0x3F
        out.append(c)
    return out


def _skinny_lfsr4(x):
    """TK2's cell update: (x3 x2 x1 x0) -> (x2 x1 x0, x3 xor x2)."""
    return ((x << 1) & 0xF) | (((x >> 3) & 1) ^ ((x >> 2) & 1))


def skinny_round(b):
    """
    One SKINNY round: SubCells, AddConstants and AddRoundTweakey, ShiftRows,
    MixColumns.

    `rtk` arrives with the round tweakey and the round constants already
    positioned across the state, because both are shuffles of material the
    driver already holds; drawing them would be sixteen wires and no logic.
    What is drawn is the part that is actually a computation.
    """
    state = b.inp("state", 64)
    rtk = b.inp("rtk", 64)

    x = b.sbox_layer(state, SKINNY_SBOX, tag="S")
    x = b.xor(x, rtk)

    # ShiftRows and MixColumns both work on cells, so take the state apart
    # once. words() hands them back least significant first; the
    # specification numbers them the other way, hence the reversal.
    cells = list(reversed(b.words(x, SKINNY_CELL)))
    shifted = [cells[4 * (i // 4) + ((i % 4) - (i // 4)) % 4]
               for i in range(16)]

    mixed = [None] * 16
    for col in range(4):
        column = [shifted[4 * r + col] for r in range(4)]
        for r, cell in enumerate(b.mix_columns(column, SKINNY_MC,
                                               SKINNY_CELL)):
            mixed[4 * r + col] = cell

    b.out("state'", b.join(list(reversed(mixed))))


def _skinny_round_tweakeys(tweakey, rounds=SKINNY_ROUNDS):
    """
    Round tweakeys with the round constants folded in.

    Only the first two rows take tweakey material; the constants land on
    cells 0, 4 and 8. Combining them here means the round circuit sees one
    64-bit value to XOR rather than two.
    """
    tk1 = _skinny_cells((tweakey >> 64) & ((1 << 64) - 1))
    tk2 = _skinny_cells(tweakey & ((1 << 64) - 1))
    out = []
    for c in _skinny_rcs(rounds):
        rtk = [0] * 16
        for i in range(8):
            rtk[i] = tk1[i] ^ tk2[i]
        rtk[0] ^= c & 0xF
        rtk[4] ^= (c >> 4) & 0x3
        rtk[8] ^= 0x2
        out.append(_skinny_pack(rtk))
        tk1 = [tk1[SKINNY_PT[i]] for i in range(16)]
        tk2 = [tk2[SKINNY_PT[i]] for i in range(16)]
        tk2 = [_skinny_lfsr4(tk2[i]) if i < 8 else tk2[i] for i in range(16)]
    return out


def skinny_reference(plaintext, tweakey, rounds=SKINNY_ROUNDS):
    state = _skinny_cells(plaintext)
    for rtk in _skinny_round_tweakeys(tweakey, rounds):
        state = [SKINNY_SBOX[v] for v in state]
        k = _skinny_cells(rtk)
        state = [state[i] ^ k[i] for i in range(16)]
        state = [state[4 * (i // 4) + ((i % 4) - (i // 4)) % 4]
                 for i in range(16)]
        out = list(state)
        for col in range(4):
            column = [state[4 * r + col] for r in range(4)]
            for r in range(4):
                v = 0
                for j in range(4):
                    if SKINNY_MC[r][j]:
                        v ^= column[j]
                out[4 * r + col] = v
        state = out
    return _skinny_pack(state)


SKINNY = {
    "name": "skinny",
    "parts": {"round": skinny_round},
    "reference": skinny_reference,
    "state": ["state"],
    "block_bits": 64,
    "key_bits": 128,
    "rounds": SKINNY_ROUNDS,
    "bit_order": "lsb",
    # From the CRYPTO 2016 paper's test-vector appendix.
    "vectors": [(0xCF16CFE8FD0F98AA,
                 0x9EB93640D088DA6376A39D1C8BEA71E1,
                 0x6CEDA1F43DE92B9E)],
    "params": lambda i, key: {"rtk": _skinny_round_tweakeys(key)[i]},
    "note": "MixColumns over a binary matrix, and a tweakey schedule that "
            "is a cell permutation plus a 4-bit LFSR.",
}


REGISTRY = {c["name"]: c
            for c in (PRESENT, LLBC, SPECK, GIFT, SIMON, SKINNY)}


#: What every cipher must state, and what a missing one costs.
REQUIRED = {
    "name": "the name used on the command line",
    "parts": "{'round': function} -- the circuits to draw",
    "reference": "reference(plaintext, key, rounds), in plain Python",
    "state": "the looping variables, matching the circuit's In labels",
    "block_bits": "block size",
    "key_bits": "key size",
    "rounds": "the full round count",
    "params": "params(round, key) -> {input: value} for each round",
}


def _check_cipher(spec, where):
    """
    Reject an incomplete definition here, with the field named.

    Every one of these is read somewhere later, and a missing one surfaces as
    a KeyError from inside whichever command reached it first -- which points
    at this toolchain's source rather than at the two lines the user has to
    write.
    """
    missing = [k for k in REQUIRED if k not in spec]
    if missing:
        lines = [f"{where}: cipher {spec.get('name', '?')!r} is missing "
                 f"{len(missing)} required field(s):"]
        for k in missing:
            lines.append(f"    {k:12s} {REQUIRED[k]}")
        lines.append("See ADD_A_CIPHER_ja.md for a complete example.")
        raise RuntimeError("\n".join(lines))

    if not spec.get("parts"):
        raise RuntimeError(
            f"{where}: cipher {spec['name']!r} has no parts. At least "
            f"{{'round': fn}} is needed -- that is the circuit to draw.")
    if "vectors" not in spec:
        spec["vectors"] = []


def _load_local_ciphers():
    """
    Pick up cipher definitions from the working directory.

    Without this, a user of the published image is stuck with the six
    examples: the container runs the image's copy of this file, so editing a
    checkout changes nothing and the failure is silent -- the new cipher
    simply never appears in `list`.

    So a file named `mycipher.py` (or whatever CROSSDRAFT_CIPHERS names)
    beside the circuits is imported and any dict in it that looks like a
    cipher is registered. That also puts a user's own designs where they
    belong: next to their results, not inside somebody else's toolchain, and
    not lost when the image is updated.

    A definition here overrides a built-in of the same name, which is how a
    variant gets tried without touching the originals.
    """
    import importlib.util
    import os

    names = os.environ.get("CROSSDRAFT_CIPHERS", "mycipher.py").split(os.pathsep)
    for name in names:
        path = name if os.path.isabs(name) else os.path.join(os.getcwd(), name)
        if not os.path.exists(path):
            continue
        spec = importlib.util.spec_from_file_location("_crossdraft_local",
                                                      path)
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)
        except Exception as e:
            raise RuntimeError(
                f"{path} could not be imported: {type(e).__name__}: {e}. "
                f"It is loaded as ordinary Python, so a syntax error or a "
                f"bad import stops everything here.") from e

        found = 0
        for value in vars(module).values():
            if not isinstance(value, dict):
                continue
            if not {"name", "parts", "reference"} <= set(value):
                continue
            _check_cipher(value, path)
            REGISTRY[value["name"]] = value
            found += 1
        if not found:
            raise RuntimeError(
                f"{path} defines no cipher. A cipher is a dict with at least "
                f"'name', 'parts' and 'reference'; see ADD_A_CIPHER_ja.md.")


_load_local_ciphers()


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
