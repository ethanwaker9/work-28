import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from latch import core, scheme, sigalgs

DATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")

NH = 32
STRUCT = 200


def wots_counts(n, w):
    p = core.Params(n, w)
    keygen = p.len * w
    sign = p.len * (w - 1) // 2 + 1
    verify = p.len * (w - 1) // 2 + 2
    return p, keygen, sign, verify


def model(level, batch, log_size, epochs):
    cfg = scheme.LEVELS[level]
    n, w = cfg["n"], cfg["w"]
    p, kg, sg, vf = wots_counts(n, w)
    anchor = sigalgs.make(cfg["anchor"])
    lb = max(1, (batch - 1).bit_length())
    ln = max(1, (log_size - 1).bit_length())
    le = max(1, (epochs - 1).bit_length())
    out = {}
    out["latch"] = {
        "bundle": p.len * n + 2 * n + 16 + 32 + NH * lb + anchor.sig_bytes + STRUCT,
        "bundle_anchored": p.len * n + 2 * n + 16 + 32 + NH * (lb + le) + STRUCT,
        "client_hash": kg + sg + 1,
        "service_hash": vf + 3,
        "service_sig": 1.0 / batch,
        "verify_hash": vf + lb + 2,
        "verify_sig": 1,
        "log": p.len * n + 2 * n + 16 + 32 + STRUCT,
    }
    svc = sigalgs.make(cfg["anchor"])
    eph = svc
    out["sigstore"] = {
        "bundle": eph.pk_bytes + 5 * svc.sig_bytes + NH * ln + STRUCT + 32,
        "client_hash": 0,
        "client_sig": 3,
        "service_sig": 4,
        "verify_sig": 5,
        "verify_hash": ln + 2,
        "log": eph.pk_bytes + 3 * svc.sig_bytes + STRUCT + 32,
    }
    out["mtc"] = {
        "bundle": eph.pk_bytes + svc.sig_bytes + 3 * (NH * lb + svc.sig_bytes) + STRUCT + 100,
        "bundle_anchored": eph.pk_bytes + svc.sig_bytes + 3 * NH * (lb + le) + STRUCT,
        "client_sig": 3,
        "service_sig": 3.0 / batch,
        "verify_sig": 4,
        "verify_hash": 3 * lb + 6,
        "log": eph.pk_bytes + svc.sig_bytes + STRUCT + 32,
    }
    return out


def main():
    os.makedirs(DATA, exist_ok=True)
    res = {}
    for level in (1, 3):
        res[str(level)] = model(level, 1024, 1 << 27, 1 << 20)
    with open(os.path.join(DATA, "complexity.json"), "w") as f:
        json.dump(res, f, indent=2)
    print(json.dumps(res, indent=2))


if __name__ == "__main__":
    main()
