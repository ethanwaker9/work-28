import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latch import baselines, core, scheme, sigalgs
from latch.encoding import enc

IDENTITY = scheme.Identity("https://accounts.google.com", "release-bot@example.com")
DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")


def digests(n, salt=b""):
    return [core.sha256(salt + i.to_bytes(4, "big")) for i in range(n)]


def med(fn, reps):
    out = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t) * 1e3)
    return statistics.median(out)


def sweep_batch():
    rows = []
    for logb in range(0, 15):
        b = 1 << logb
        L = scheme.Latch(level=1, batch=b)
        ds = digests(b, b"b")
        reqs = [L.client(IDENTITY, d) for d in ds]
        t0 = time.perf_counter()
        wires = L.service(reqs)
        svc = (time.perf_counter() - t0) * 1e3 / b
        rows.append({"batch": b, "bundle": len(wires[b // 2]), "service_ms": svc})
    M = baselines.PqSigstore("ml-dsa-44", "ml-dsa-44")
    ds = digests(64, b"c")
    reqs = [M.client(IDENTITY, d) for d in ds]
    t0 = time.perf_counter()
    w = M.service(reqs)
    base = {"bundle": len(w[0]), "service_ms": (time.perf_counter() - t0) * 1e3 / 64}
    return {"latch": rows, "sigstore": base}


def sweep_logsize():
    rows = []
    for e in range(10, 33, 2):
        N = 1 << e
        L = scheme.Latch(level=1, batch=1024)
        S = baselines.PqSigstore("ml-dsa-44", "ml-dsa-44", log_size=N)
        MT = baselines.BatchedSigstore("ml-dsa-44", "ml-dsa-44", log_size=N)
        ds = digests(8, b"n")
        lw = L.run_epoch(IDENTITY, ds)
        sw = S.run_epoch(IDENTITY, ds)
        mw = MT.run_epoch(IDENTITY, ds)
        rows.append({"log2N": e, "latch": len(lw[0]), "sigstore": len(sw[0]),
                     "mtc": len(mw[0])})
    return rows


def sweep_winternitz():
    rows = []
    for w in (4, 16, 256):
        for n in (16, 24):
            p = core.Params(n, w)
            L = scheme.Latch(level=1 if n == 16 else 3, batch=1024)
            L.params = p
            L.pubseed = L.pubseed[:n] if len(L.pubseed) >= n else L.pubseed + bytes(n - len(L.pubseed))
            ds = digests(64, b"w%d" % w)
            wires = L.run_epoch(IDENTITY, ds)
            idx = 32
            vt = med(lambda: L.verify(wires[idx], IDENTITY, ds[idx]), 30)
            reqs = [L.client(IDENTITY, d) for d in digests(32, b"x")]
            ct = med(lambda: L.client(IDENTITY, ds[0]), 30)
            rows.append({"w": w, "n": n, "len": p.len, "sig_bytes": p.sig_bytes,
                         "bundle": len(wires[idx]), "verify_ms": vt, "client_ms": ct})
    return rows


def sweep_amortization():
    out = {}
    B = 1024
    L = scheme.Latch(level=1, batch=B)
    ds = digests(B, b"a")
    wires = L.run_epoch(IDENTITY, ds)
    anchor_sig = L.anchor.sig_bytes
    head_len = len(scheme.epoch_head(L.origin, 0, 1800000000, bytes(32), B, bytes(32)))
    shared = head_len + anchor_sig + 8
    per = len(wires[0]) - shared
    out["latch"] = {"shared": shared, "per": per}
    S = baselines.PqSigstore("ml-dsa-44", "ml-dsa-44")
    sw = S.run_epoch(IDENTITY, digests(4, b"a"))
    out["sigstore"] = {"shared": 0, "per": len(sw[0])}
    MT = baselines.BatchedSigstore("ml-dsa-44", "ml-dsa-44")
    mw = MT.run_epoch(IDENTITY, ds)
    svc = sigalgs.make("ml-dsa-44")
    mshared = 3 * (svc.sig_bytes + 60)
    out["mtc"] = {"shared": mshared, "per": len(mw[0]) - mshared}
    return out


def verify_breakdown():
    B = 256
    L = scheme.Latch(level=1, batch=B)
    ds = digests(B, b"v")
    wires = L.run_epoch(IDENTITY, ds)
    idx = B // 2
    core.reset_hash_calls()
    L.verify(wires[idx], IDENTITY, ds[idx])
    total_calls = core.hash_calls()
    p = L.params
    ots = med(lambda: core.wots_pk_from_sig(
        p, bytes(p.sig_bytes), bytes(p.n), L.pubseed, core.adrs(bytes(16))), 200)
    anchor = med(lambda: L.anchor.verify(b"head", L.anchor.sign(b"head")), 50)
    full = med(lambda: L.verify(wires[idx], IDENTITY, ds[idx]), 200)
    return {"hash_calls": total_calls, "ots_ms": ots, "anchor_pair_ms": anchor,
            "full_ms": full, "path_nodes": 8}


def service_scaling():
    rows = []
    for b in (1, 4, 16, 64, 256, 1024):
        L = scheme.Latch(level=1, batch=b)
        reqs = [L.client(IDENTITY, d) for d in digests(b, b"s")]
        t0 = time.perf_counter()
        L.service(reqs)
        lt = (time.perf_counter() - t0) * 1e3 / b
        S = baselines.PqSigstore("ml-dsa-44", "ml-dsa-44")
        r2 = [S.client(IDENTITY, d) for d in digests(b, b"s")]
        t0 = time.perf_counter()
        S.service(r2)
        st = (time.perf_counter() - t0) * 1e3 / b
        MT = baselines.BatchedSigstore("ml-dsa-44", "ml-dsa-44")
        r3 = [MT.client(IDENTITY, d) for d in digests(b, b"s")]
        t0 = time.perf_counter()
        MT.service(r3)
        mt = (time.perf_counter() - t0) * 1e3 / b
        rows.append({"batch": b, "latch": lt, "sigstore": st, "mtc": mt})
    return rows


def main():
    os.makedirs(DATA, exist_ok=True)
    out = {
        "batch": sweep_batch(),
        "logsize": sweep_logsize(),
        "winternitz": sweep_winternitz(),
        "amortization": sweep_amortization(),
        "breakdown": verify_breakdown(),
        "service_scaling": service_scaling(),
    }
    with open(os.path.join(DATA, "sweeps.json"), "w") as f:
        json.dump(out, f, indent=2)
    print(json.dumps(out["amortization"], indent=2))
    print(json.dumps(out["breakdown"], indent=2))


if __name__ == "__main__":
    main()
