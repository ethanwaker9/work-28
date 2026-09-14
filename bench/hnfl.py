import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latch import baselines, core, merkle, scheme

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
VICTIM = scheme.Identity("https://accounts.google.com", "maintainer@example.org")
T_Q = 1900000000
T_STAR = T_Q - 86400


def honest_history(method, identity, n_epochs=8, per=16):
    for e in range(n_epochs):
        ds = [core.sha256(b"h" + bytes([e, i])) for i in range(per)]
        method.run_epoch(identity, ds, now=T_STAR - 1000 * (n_epochs - e))


def forge_sigstore(method, identity, message):
    digest = core.sha256(message)
    reqs = [method.client(identity, digest, now=T_STAR)]
    wires = method.service(reqs, now=T_STAR)
    if getattr(method, "anchored", False):
        if hasattr(method, "anchor_views"):
            wires = method.restaple_all(wires, method.anchor_views())
        else:
            wires = method.restaple_all(wires, method.anchor_view())
    return wires[0], digest


def run():
    rows = []

    m = baselines.PqSigstore("ml-dsa-44", "ml-dsa-44")
    honest_history(m, scheme.Identity("https://accounts.google.com", "other@example.org"))
    t0 = time.perf_counter()
    wire, digest = forge_sigstore(m, VICTIM, b"trojan payload")
    dt = (time.perf_counter() - t0) * 1e3
    rows.append({"method": "Sigstore/ML-DSA-44 (signature anchored)",
                 "accepted": m.verify(wire, VICTIM, digest), "forge_ms": dt})

    mt = baselines.BatchedSigstore("ml-dsa-44", "ml-dsa-44")
    honest_history(mt, scheme.Identity("https://accounts.google.com", "other@example.org"))
    t0 = time.perf_counter()
    wire, digest = forge_sigstore(mt, VICTIM, b"trojan payload")
    dt = (time.perf_counter() - t0) * 1e3
    rows.append({"method": "MTC/ML-DSA-44 (signature anchored)",
                 "accepted": mt.verify(wire, VICTIM, digest), "forge_ms": dt})

    L = scheme.Latch(level=1, batch=16)
    honest_history(L, scheme.Identity("https://accounts.google.com", "other@example.org"))
    t0 = time.perf_counter()
    wire, digest = forge_sigstore(L, VICTIM, b"trojan payload")
    dt = (time.perf_counter() - t0) * 1e3
    rows.append({"method": "Latch (signature anchored)",
                 "accepted": L.verify(wire, VICTIM, digest), "forge_ms": dt})

    LA = scheme.Latch(level=1, batch=16, anchored=True)
    LA.preload_epochs(4096)
    honest_history(LA, scheme.Identity("https://accounts.google.com", "other@example.org"))
    pinned = LA.anchor_view().root()
    pinned_epochs = LA.htree.size
    t0 = time.perf_counter()
    wire, digest = forge_sigstore(LA, VICTIM, b"trojan payload")
    dt = (time.perf_counter() - t0) * 1e3
    accepted = LA.verify(wire, VICTIM, digest, landmark=pinned)
    rows.append({"method": "Latch-A (hash anchored)", "accepted": accepted,
                 "forge_ms": dt, "pinned_epochs": pinned_epochs})

    replay = LA.verify(wire, VICTIM, digest, landmark=LA.anchor_view().root())
    rows.append({"method": "Latch-A (anchor refreshed after t_Q)", "accepted": replay,
                 "forge_ms": dt})

    mta = baselines.BatchedSigstore("ml-dsa-44", "ml-dsa-44", anchored=True)
    mta.preload_epochs(4096)
    honest_history(mta, scheme.Identity("https://accounts.google.com", "other@example.org"))
    pinned_mtc = {k: v.root() for k, v in mta.anchor_views().items()}
    t0 = time.perf_counter()
    wire, digest = forge_sigstore(mta, VICTIM, b"trojan payload")
    dt = (time.perf_counter() - t0) * 1e3
    rows.append({"method": "MTC-A (hash anchored)",
                 "accepted": mta.verify(wire, VICTIM, digest, landmark=pinned_mtc),
                 "forge_ms": dt})

    return rows


def anchor_cost():
    out = []
    for e in range(6, 25, 3):
        n = 1 << e
        heads = [merkle.leaf_hash(i.to_bytes(8, "big")) for i in range(min(n, 1 << 16))]
        t0 = time.perf_counter()
        merkle.root(heads)
        dt = (time.perf_counter() - t0) * 1e3
        out.append({"log2_epochs": e, "anchor_bytes": 32,
                    "proof_bytes": 32 * e, "root_ms": dt})
    return out


def main():
    os.makedirs(DATA, exist_ok=True)
    res = {"forgery": run(), "anchor_cost": anchor_cost()}
    with open(os.path.join(DATA, "hnfl.json"), "w") as f:
        json.dump(res, f, indent=2)
    for r in res["forgery"]:
        print(f"{r['method']:42s} accepted={str(r['accepted']):5s} "
              f"cost={r['forge_ms']:.3f} ms")


if __name__ == "__main__":
    main()
