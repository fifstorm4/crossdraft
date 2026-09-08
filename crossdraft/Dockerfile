# CrossDraft — everything needed to draw a cipher and analyse it.
#
#   docker build -t crossdraft .
#   docker run --rm -it -v "$PWD:/work" crossdraft selftest
#
# Why this image exists
# ---------------------
# The analysis stack has four pieces that each fail in their own way, and
# none of the failures says what is wrong:
#
#   * passagemath ships SageMath as focused wheels and omits `sage.all`,
#     which CLAASP imports.  Without a shim: ModuleNotFoundError.
#   * sage.rings.integer and sage.rings.integer_ring initialise each other,
#     so whichever CLAASP reaches first raises a circular-import error that
#     names a module the user never touched.
#   * CLAASP shells out to `espresso` for S-box constraints and to a SAT
#     solver for the search.  CaDiCaL does not print the statistics CLAASP's
#     result parser reads, so it fails with an IndexError deep inside the
#     parser; Kissat does print them.
#   * CLAASP masks a uint8 array with 0xffff, which NumPy 2 refuses.
#
# Every one of those cost an hour to diagnose.  Pinning them here means a
# collaborator's first run is `docker run`, not an afternoon.
#
# Reproducibility
# ---------------
# Tag each release and quote the digest in the paper:
#
#   docker run ghcr.io/fifstorm/crossdraft:0.1.0@sha256:...
#
# `cdraft env` inside the container prints every version it found, plus a
# SHA-256 of each circuit analysed. That pair -- image digest and circuit
# digest -- is what makes a reported figure checkable five years later.

FROM ubuntu:24.04

LABEL org.opencontainers.image.title="CrossDraft"
LABEL org.opencontainers.image.description="Draw a cipher once in Digital; \
check it against its test vectors and analyse it with CLAASP."
LABEL org.opencontainers.image.source="https://github.com/fifstorm/crossdraft"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1

# --------------------------------------------------------------------------
# System
# --------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-pip \
        openjdk-21-jdk-headless \
        build-essential git curl unzip ca-certificates \
        libgmp-dev libmpfr-dev libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

# --------------------------------------------------------------------------
# Digital — the schematic editor and simulator, and the netlist oracle
# --------------------------------------------------------------------------
ARG DIGITAL_URL=https://github.com/hneemann/Digital/releases/latest/download/Digital.zip
RUN curl -sL -o /tmp/Digital.zip "$DIGITAL_URL" \
    && unzip -q /tmp/Digital.zip -d /opt \
    && rm /tmp/Digital.zip
ENV DIGITAL_JAR=/opt/Digital/Digital.jar

# --------------------------------------------------------------------------
# SAT solving and logic minimisation
#
# Kissat rather than CaDiCaL: CLAASP parses "process-time" and
# "maximum-resident-set-size" out of the solver's output, and CaDiCaL prints
# neither even with --stats=true.
# --------------------------------------------------------------------------
RUN git clone -q --depth 1 https://github.com/arminbiere/kissat.git /tmp/kissat \
    && cd /tmp/kissat && ./configure -q && make -j"$(nproc)" \
    && cp build/kissat /usr/local/bin/ \
    && rm -rf /tmp/kissat

# espresso ships a prebuilt binary in the mirror's bin/.
RUN git clone -q --depth 1 \
        https://github.com/classabbyamp/espresso-logic.git /tmp/espresso \
    && cp /tmp/espresso/bin/espresso /usr/local/bin/ \
    && chmod +x /usr/local/bin/espresso \
    && rm -rf /tmp/espresso

# --------------------------------------------------------------------------
# SageMath (via passagemath) and CLAASP
#
# passagemath-combinat is what carries sage.sat, which CLAASP's SAT models
# import; the other five cover matrices, S-boxes, polynomial rings, MILP and
# polyhedra.
# --------------------------------------------------------------------------
RUN pip3 install \
        passagemath-modules passagemath-symbolics passagemath-brial \
        passagemath-glpk passagemath-polyhedra passagemath-combinat \
    && pip3 install claasp matplotlib

# --------------------------------------------------------------------------
# NIST SP 800-22, for the statistical battery
#
# NIST distributes STS 2.1.2 from csrc.nist.gov; a GitHub mirror of the same
# release is used because it is reachable from more build environments.
# CLAASP ships patched sources that drive `assess` non-interactively, and the
# stock makefile does not create the per-test output folders -- without them
# assess writes an empty report and CLAASP cannot parse it.
# --------------------------------------------------------------------------
RUN git clone -q --depth 1 \
        https://github.com/terrillmoore/NIST-Statistical-Test-Suite.git \
        /tmp/sts \
    && git clone -q --depth 1 --filter=blob:none --sparse \
        https://github.com/Crypto-TII/claasp.git /tmp/claasp-src \
    && cd /tmp/claasp-src && git sparse-checkout set required_dependencies \
    && cp required_dependencies/assess.c    /tmp/sts/sts/src/ \
    && cp required_dependencies/utilities.c /tmp/sts/sts/src/ \
    && cp required_dependencies/utilities.h /tmp/sts/sts/include/ \
    && cd /tmp/sts/sts && mkdir -p obj \
    && for t in Frequency BlockFrequency Runs LongestRun Rank FFT \
                NonOverlappingTemplate OverlappingTemplate Universal \
                LinearComplexity Serial ApproximateEntropy CumulativeSums \
                RandomExcursions RandomExcursionsVariant; do \
           mkdir -p "experiments/AlgorithmTesting/$t"; done \
    && make -j"$(nproc)" \
    && mkdir -p /usr/local/bin/sts-2.1.2 \
    && cp -r /tmp/sts/sts/* /usr/local/bin/sts-2.1.2/ \
    && ln -sf /usr/local/bin/sts-2.1.2/assess /usr/local/bin/niststs \
    && rm -rf /tmp/sts /tmp/claasp-src

# --------------------------------------------------------------------------
# CrossDraft
# --------------------------------------------------------------------------
WORKDIR /opt/crossdraft
COPY . .

# Build the netlist extractor against Digital.jar.
RUN cd java && make DIGITAL_JAR="$DIGITAL_JAR"
ENV BRIDGE_JAR=/opt/crossdraft/java/digbridge.jar

# The sage.all shim and the NumPy 2 fix, both applied by scripts that report
# what they changed and do nothing if it is already right.
RUN python3 python/setup_sage.py && python3 python/patch_claasp.py

# Fail the build rather than ship an image whose analysis path is broken.
RUN python3 -c "\
import sys; sys.path.insert(0, 'python'); import preload; \
from claasp.ciphers.block_ciphers.present_block_cipher import PresentBlockCipher; \
c = PresentBlockCipher().evaluate([0, 0]); \
assert c == 0x5579C1387B228445, hex(c); \
print('CLAASP reproduces the PRESENT test vector')"

ENV PYTHONPATH=/opt/crossdraft/python
WORKDIR /work

ENTRYPOINT ["python3", "/opt/crossdraft/python/digcli.py"]
CMD ["--help"]
