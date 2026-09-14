import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from latch import baselines, core, merkle, scheme
from latch.encoding import enc, unpack

IDN = scheme.Identity("https://accounts.google.com", "release-bot@example.com")
OTHER = scheme.Identity("https://accounts.google.com", "victim@example.com")


def digests(n):
    return [core.sha256(i.to_bytes(4, "big")) for i in range(n)]


def test_sha256_vectors():
    import hashlib
    for m in (b"", b"abc", b"a" * 1000, secrets.token_bytes(4096)):
        assert core.sha256(m) == hashlib.sha256(m).digest()


@pytest.mark.parametrize("n,w,length", [(16, 16, 35), (24, 16, 51), (32, 16, 67),
                                        (16, 4, 68), (16, 256, 18)])
def test_wots_parameters(n, w, length):
    p = core.Params(n, w)
    assert p.len == length


@pytest.mark.parametrize("n,w", [(16, 16), (24, 16), (32, 16), (16, 4), (16, 256)])
def test_wots_roundtrip(n, w):
    p = core.Params(n, w)
    sk, ps, kid = (secrets.token_bytes(n), secrets.token_bytes(n),
                   secrets.token_bytes(16))
    a = core.adrs(kid)
    pk = core.wots_pkgen(p, sk, ps, a)
    for _ in range(5):
        d = secrets.token_bytes(n)
        sig = core.wots_sign(p, sk, ps, a, d)
        assert core.wots_pk_from_sig(p, sig, d, ps, a) == pk
        other = secrets.token_bytes(n)
        assert core.wots_pk_from_sig(p, sig, other, ps, a) != pk


def test_wots_tweak_separation():
    p = core.Params(16, 16)
    sk, ps = secrets.token_bytes(16), secrets.token_bytes(16)
    a1 = core.adrs(secrets.token_bytes(16))
    a2 = core.adrs(secrets.token_bytes(16))
    assert core.wots_pkgen(p, sk, ps, a1) != core.wots_pkgen(p, sk, ps, a2)


@pytest.mark.parametrize("m", [1, 2, 3, 5, 8, 13, 64, 257, 1000])
def test_merkle(m):
    leaves = [merkle.leaf_hash(secrets.token_bytes(24)) for _ in range(m)]
    root = merkle.root(leaves)
    paths, root2 = merkle.all_paths(leaves)
    assert root == root2
    for i in range(m):
        assert paths[i] == merkle.path(leaves, i)
        assert merkle.verify(leaves[i], i, m, paths[i], root)
        assert not merkle.verify(merkle.leaf_hash(b"x"), i, m, paths[i], root)


def test_merkle_synthetic_proof():
    leaf = merkle.leaf_hash(b"entry")
    for size in (1 << 10, 1 << 20, 1 << 27):
        idx = secrets.randbelow(size)
        proof, root = merkle.synthetic_proof(leaf, idx, size)
        assert merkle.verify(leaf, idx, size, proof, root)
        assert len(proof) == merkle.proof_length(idx, size)


def test_encoding_roundtrip():
    fields = [b"", b"a", secrets.token_bytes(3), secrets.token_bytes(200),
              secrets.token_bytes(70000)]
    assert unpack(enc(*fields)) == fields


def test_lms():
    w, h = 8, 5
    sk, ident = secrets.token_bytes(32), secrets.token_bytes(16)
    tree = core.lms_build(w, h, sk, ident)
    root = core.lms_root(tree)
    for q in range(4):
        sig = core.lms_sign(w, h, sk, ident, q, b"message %d" % q, tree)
        assert core.lms_verify(w, h, ident, q, b"message %d" % q, sig, root)
        assert not core.lms_verify(w, h, ident, q, b"other", sig, root)


@pytest.mark.parametrize("level", [1, 3, 5])
def test_latch_roundtrip(level):
    L = scheme.Latch(level=level, batch=32)
    ds = digests(32)
    wires = L.service([L.client(IDN, d) for d in ds])
    for i in (0, 7, 31):
        assert L.verify(wires[i], IDN, ds[i])
        assert not L.verify(wires[i], OTHER, ds[i])
        assert not L.verify(wires[i], IDN, core.sha256(b"wrong"))


def test_latch_rejects_replayed_key():
    L = scheme.Latch(level=1, batch=8)
    req = L.client(IDN, digests(1)[0])
    assert L.admit(req)
    assert not L.admit(req)


def test_latch_rejects_bad_signature():
    L = scheme.Latch(level=1, batch=8)
    req = L.client(IDN, digests(1)[0])
    bad = scheme.Request(req.issuer, req.subject, req.kid, req.pk_ots, req.R,
                         core.sha256(b"swapped"), req.sig_ots)
    assert not L.admit(bad)


def test_latch_tampered_fields():
    L = scheme.Latch(level=1, batch=16)
    ds = digests(16)
    wires = L.service([L.client(IDN, d) for d in ds])
    f = unpack(wires[3])
    for pos in range(len(f)):
        g = list(f)
        if len(g[pos]) == 0:
            g[pos] = b"\x01"
        else:
            g[pos] = bytes([g[pos][0] ^ 0xFF]) + g[pos][1:]
        assert not L.verify(enc(*g), IDN, ds[3])


def test_latch_cross_epoch_transplant():
    L = scheme.Latch(level=1, batch=8)
    d1 = digests(8)
    w1 = L.service([L.client(IDN, d) for d in d1])
    d2 = [core.sha256(b"b" + i.to_bytes(4, "big")) for i in range(8)]
    w2 = L.service([L.client(IDN, d) for d in d2])
    a = unpack(w1[2])
    b = unpack(w2[2])
    mixed = enc(*(a[:9] + b[9:]))
    assert not L.verify(mixed, IDN, d1[2])


def test_latch_anchored():
    L = scheme.Latch(level=1, batch=8, anchored=True)
    L.preload_epochs(500)
    ds = digests(8)
    sc = L.service([L.client(IDN, d) for d in ds])
    head_index = L.head_index
    L.preload_epochs(300)
    view = L.anchor_view()
    wires = L.restaple_all(sc, view, head_index)
    lm = view.root()
    assert len(view.path(head_index)) >= 9
    assert L.verify(wires[4], IDN, ds[4], landmark=lm)
    assert not L.verify(wires[4], IDN, ds[4], landmark=None)
    assert not L.verify(wires[4], IDN, ds[4], landmark=core.sha256(b"other root"))


def test_anchor_pinned_before_break():
    L = scheme.Latch(level=1, batch=8, anchored=True)
    L.preload_epochs(200)
    L.run_epoch(IDN, digests(8), now=1800000000)
    pinned = L.anchor_view().root()
    ds = [core.sha256(b"forged")]
    later = L.run_epoch(OTHER, ds, now=1799999000)
    assert not L.verify(later[0], OTHER, ds[0], landmark=pinned)
    assert L.verify(later[0], OTHER, ds[0], landmark=L.anchor_view().root())


@pytest.mark.parametrize("alg", ["ml-dsa-44", "falcon-512", "ecdsa-p256", "ed25519"])
def test_sigstore_baseline(alg):
    S = baselines.PqSigstore(alg, alg)
    ds = digests(4)
    wires = S.service([S.client(IDN, d) for d in ds])
    assert S.verify(wires[1], IDN, ds[1])
    assert not S.verify(wires[1], OTHER, ds[1])
    assert not S.verify(wires[1], IDN, core.sha256(b"nope"))


@pytest.mark.parametrize("anchored", [False, True])
def test_mtc_baseline(anchored):
    M = baselines.BatchedSigstore("ml-dsa-44", "ml-dsa-44", anchored=anchored)
    if anchored:
        M.preload_epochs(100)
    ds = digests(8)
    wires = M.run_epoch(IDN, ds)
    lm = {k: v.root() for k, v in M.anchor_views().items()} if anchored else None
    assert M.verify(wires[2], IDN, ds[2], landmark=lm)
    assert not M.verify(wires[2], IDN, core.sha256(b"nope"), landmark=lm)


def test_latch_bundle_smaller_than_baselines():
    ds = digests(64)
    L = scheme.Latch(level=1, batch=64)
    S = baselines.PqSigstore("ml-dsa-44", "ml-dsa-44")
    M = baselines.BatchedSigstore("ml-dsa-44", "ml-dsa-44")
    lw = L.service([L.client(IDN, d) for d in ds])
    sw = S.service([S.client(IDN, d) for d in ds[:4]])
    mw = M.service([M.client(IDN, d) for d in ds])
    assert len(lw[0]) < len(mw[0]) < len(sw[0])
    assert L.log_entry_size() < M.log_entry_size() < S.log_entry_size()
