# Latch: post-quantum verification material for keyless software signing

This repository is our implementation and evaluation harness for our
research *Post-Quantum Cryptographic Analysis of Sigstore*. It contains

* a formal model implementation of the Sigstore signing and
  verification pipeline (identity certificate, signed certificate timestamp,
  RFC 3161 timestamp token, transparency log inclusion proof and signed
  checkpoint), parameterised by the signature scheme used at each position;
* **Latch**, the epoch anchored construction proposed in our research, in its
  hash-anchored modes;
* every baseline the paper compares against, implemented:
  ML-DSA, FN-DSA (Falcon), SLH-DSA, XMSS, LMS, per-service Merkle batching in
  the style of Merkle Tree Certificates, and the classical ECDSA/Ed25519
  deployment that Sigstore runs today.

## Requirements

* Python 3.8 or newer
* a C compiler
* OpenSSL `libcrypto` (development headers) for the hardware-accelerated
  SHA-256 path and for ECDSA/Ed25519; without it the build falls back to a
  portable SHA-256 and the classical baselines are unavailable
* `liboqs-python` for ML-DSA, FN-DSA, SLH-DSA and XMSS
* `matplotlib` for the figures, `pytest` for the test suite

```
python3 -m pip install -r requirements.txt
```

## Build

```
make
```

`make` compiles `src/latchcore.c` into `latch/liblatchcore.so`. The Makefile
uses `pkg-config` to locate `libcrypto`; on macOS with Homebrew set

```
export PKG_CONFIG_PATH=/opt/homebrew/opt/openssl@3/lib/pkgconfig:$PKG_CONFIG_PATH
```

before running `make`. If `libcrypto` is not found the library still builds
with the bundled SHA-256 implementation, and every hash-based measurement is
then slower for all methods alike.

## Test

```
python3 -m pytest tests -q
```

The suite checks the SHA-256 implementation against the standard library, the
WOTS-TW parameter derivation against FIPS 205, one-time signature round trips
at every parameter set, RFC 6962 inclusion proofs against an independent
recomputation, the incremental log tree against the batch construction, LMS
round trips, and a family of negative tests: replayed one-time keys, tampered
bundle fields, transplanted epoch heads, forged digests, and anchored bundles
checked against a pinned root.

## Running experiments

```
make
python3 bench/run_bench.py --batch 1024     
python3 bench/sweeps.py                     
python3 bench/hnfl.py                       
python3 bench/complexity.py                 
python3 figures/make_figures.py             
```

Results are written to `data/*.json` and figures to `figures/`. A full run
takes about one hour, dominated by the SLH-DSA rows. Add `--quick` to
`run_bench.py` for a reduced configuration that finishes in a few minutes.

## Layout

```
src/latchcore.c      SHA-256, tweakable hash, WOTS-TW, RFC 6962 trees, LM-OTS,
                     LMS, and the OpenSSL bindings for ECDSA and Ed25519
latch/core.py        ctypes bindings for the C core
latch/encoding.py    length delimited wire encoding shared by all methods
latch/merkle.py      RFC 6962 tree helpers and the incremental log tree
latch/sigalgs.py     uniform interface over liboqs, LMS and OpenSSL schemes
latch/scheme.py      Latch: one-time signer, anchor service, verifier
latch/baselines.py   Sigstore pipeline and per-service Merkle batching
bench/               benchmark drivers
tests/               test suite
```

## Measurement conventions

In our research, all methods are encoded with the same length delimited field format, so
reported sizes differ only in the cryptographic objects they carry and not in
the serialisation. Time is split into three phases that are measured
separately as *signer* covers key generation and the artifact signature,
*service* covers everything the issuing and logging infrastructure does for one
signing event including its amortised share of the per epoch signature, and
*verifier* covers parsing and checking a complete bundle. Inclusion proofs
against a log of size 2^27 are materialised along the co-path only, which
reproduces the verifier cost exactly while avoiding a 4 GiB tree. Anchored
variants are measured against an epoch tree of 2^20 epochs.

