import argparse
import json
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latch import baselines, core, scheme

IDENTITY = scheme.Identity("https://accounts.google.com", "release-bot@example.com")
LOG_SIZE = 1 << 27
BATCH = 1024


def digests(n, salt=b""):
    return [core.sha256(salt + i.to_bytes(4, "big")) for i in range(n)]


def timeit(fn, reps):
    out = []
    for _ in range(reps):
        t = time.perf_counter()
        fn()
        out.append((time.perf_counter() - t) * 1e3)
    return statistics.median(out)


def build_methods(level, batch=BATCH, log_size=LOG_SIZE):
    if level == 1:
        svc, eph = "ml-dsa-44", "ml-dsa-44"
        methods = [
            ("Sigstore/ML-DSA-44", baselines.PqSigstore("ml-dsa-44", "ml-dsa-44", log_size), 40, batch),
            ("Sigstore/Falcon-512", baselines.PqSigstore("falcon-512", "falcon-512", log_size), 40, 64),
            ("Sigstore/SLH-DSA-128f", baselines.PqSigstore("slh-dsa-sha2-128f", "slh-dsa-sha2-128f", log_size), 5, 8),
            ("Sigstore/SLH-DSA-128s", baselines.PqSigstore("slh-dsa-sha2-128s", "slh-dsa-sha2-128s", log_size), 5, 2),
            ("Sigstore/XMSS+ML-DSA", baselines.PqSigstore("ml-dsa-44", "xmss-sha2-10-256", log_size), 20, 64),
            ("Sigstore/LMS+ML-DSA", baselines.PqSigstore("ml-dsa-44", "lms-sha256-h10-w8", log_size), 20, 64),
            ("MTC/ML-DSA-44", baselines.BatchedSigstore("ml-dsa-44", "ml-dsa-44", log_size), 40, batch),
            ("MTC-A/ML-DSA-44", baselines.BatchedSigstore("ml-dsa-44", "ml-dsa-44", log_size, anchored=True), 40, batch),
            ("Latch", scheme.Latch(level=1, batch=batch), 40, batch),
            ("Latch-A", scheme.Latch(level=1, batch=batch, anchored=True), 40, batch),
        ]
    elif level == 3:
        methods = [
            ("Sigstore/ML-DSA-65", baselines.PqSigstore("ml-dsa-65", "ml-dsa-65", log_size), 40, batch),
            ("Sigstore/Falcon-1024", baselines.PqSigstore("falcon-1024", "falcon-1024", log_size), 40, 64),
            ("Sigstore/SLH-DSA-192f", baselines.PqSigstore("slh-dsa-sha2-192f", "slh-dsa-sha2-192f", log_size), 5, 8),
            ("Sigstore/SLH-DSA-192s", baselines.PqSigstore("slh-dsa-sha2-192s", "slh-dsa-sha2-192s", log_size), 5, 2),
            ("MTC/ML-DSA-65", baselines.BatchedSigstore("ml-dsa-65", "ml-dsa-65", log_size), 40, batch),
            ("MTC-A/ML-DSA-65", baselines.BatchedSigstore("ml-dsa-65", "ml-dsa-65", log_size, anchored=True), 40, batch),
            ("Latch", scheme.Latch(level=3, batch=batch), 40, batch),
            ("Latch-A", scheme.Latch(level=3, batch=batch, anchored=True), 40, batch),
        ]
    else:
        methods = [
            ("Sigstore/ECDSA-P256", baselines.PqSigstore("ecdsa-p256", "ecdsa-p256", log_size), 40, 64),
            ("Sigstore/Ed25519", baselines.PqSigstore("ed25519", "ed25519", log_size), 40, 64),
        ]
    return methods


EPOCH_TREE = 1 << 20


def measure(name, m, batch, reps):
    anchored = getattr(m, "anchored", False)
    if anchored:
        m.preload_epochs(EPOCH_TREE // 2)
    ds = digests(batch, b"m")
    t0 = time.perf_counter()
    reqs = [m.client(IDENTITY, d) for d in ds]
    client_ms = (time.perf_counter() - t0) * 1e3 / batch
    t0 = time.perf_counter()
    wires = m.service(reqs)
    service_ms = (time.perf_counter() - t0) * 1e3 / batch
    lm = None
    if anchored:
        head_index = (m.head_index if hasattr(m, "head_index")
                      else m.ca.head_index)
        m.preload_epochs(EPOCH_TREE // 2 - 1)
        if hasattr(m, "anchor_views"):
            views = m.anchor_views()
            wires = m.restaple_all(wires, views, head_index)
            lm = {k: v.root() for k, v in views.items()}
        else:
            view = m.anchor_view()
            wires = m.restaple_all(wires, view, head_index)
            lm = view.root()
    idx = batch // 2
    ok = m.verify(wires[idx], IDENTITY, ds[idx], landmark=lm)
    if not ok:
        raise RuntimeError("verification failed for " + name)
    verify_ms = timeit(lambda: m.verify(wires[idx], IDENTITY, ds[idx], landmark=lm), reps)
    sizes = [len(w) for w in wires]
    return {
        "method": name,
        "client_ms": client_ms,
        "service_ms": service_ms,
        "verify_ms": verify_ms,
        "bundle_bytes": int(statistics.median(sizes)),
        "log_bytes": m.log_entry_size(),
        "batch": batch,
    }


def hash_profile(level, batch):
    m = scheme.Latch(level=level, batch=batch)
    ds = digests(batch, b"h")
    core.reset_hash_calls()
    reqs = [m.client(IDENTITY, d) for d in ds]
    client_calls = core.hash_calls() / batch
    core.reset_hash_calls()
    wires = m.service(reqs)
    service_calls = core.hash_calls() / batch
    k = min(batch, 128)
    core.reset_hash_calls()
    for i in range(k):
        m.verify(wires[i], IDENTITY, ds[i])
    verify_calls = core.hash_calls() / k
    return {"client": client_calls, "service": service_calls, "verify": verify_calls}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch", type=int, default=BATCH)
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))), "data"))
    ap.add_argument("--quick", action="store_true")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    batch = 64 if args.quick else args.batch
    results = {}
    for level in (1, 3, 0):
        rows = []
        for name, m, reps, mb in build_methods(level, batch):
            if args.quick:
                reps = min(reps, 3)
                mb = min(mb, 32)
            row = measure(name, m, mb, reps)
            rows.append(row)
            print(f"{level} {name:24s} bundle={row['bundle_bytes']:6d} "
                  f"log={row['log_bytes']:6d} client={row['client_ms']:8.3f} "
                  f"service={row['service_ms']:9.3f} verify={row['verify_ms']:8.3f}")
        results[str(level)] = rows
    results["hash_profile"] = {str(l): hash_profile(l, batch) for l in (1, 3, 5)}
    with open(os.path.join(args.out, "main.json"), "w") as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
