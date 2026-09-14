import secrets
import time

from . import core, merkle, sigalgs
from .encoding import chunks, enc, r32, u32, u64, unpack

DOMAIN_MSG = b"latch/v1/msg"
DOMAIN_LEAF = b"latch/v1/leaf"
DOMAIN_HEAD = b"latch/v1/head"

LEVELS = {
    1: {"n": 16, "w": 16, "anchor": "ml-dsa-44"},
    3: {"n": 24, "w": 16, "anchor": "ml-dsa-65"},
    5: {"n": 32, "w": 16, "anchor": "ml-dsa-87"},
}


class Identity:
    def __init__(self, issuer, subject):
        self.issuer = issuer.encode() if isinstance(issuer, str) else issuer
        self.subject = subject.encode() if isinstance(subject, str) else subject

    def matches(self, issuer, subject):
        return self.issuer == issuer and self.subject == subject


def msg_digest(n, R, pk_ots, issuer, subject, artifact_digest):
    return core.sha256(enc(DOMAIN_MSG, R, pk_ots, issuer, subject, artifact_digest))[:n]


def leaf_record(issuer, subject, kid, pk_ots, R, artifact_digest, sig_ots):
    return enc(DOMAIN_LEAF, issuer, subject, kid, pk_ots, R, artifact_digest, sig_ots)


def epoch_head(origin, epoch, t, root, size, prev):
    return enc(DOMAIN_HEAD, origin, u32(epoch), u64(t), root, u32(size), prev)


class OneTimeKey:
    def __init__(self, params, pubseed):
        self.params = params
        self.pubseed = pubseed
        self.skseed = secrets.token_bytes(params.n)
        self.kid = secrets.token_bytes(16)
        self.adrs = core.adrs(self.kid)
        self.pk = core.wots_pkgen(params, self.skseed, pubseed, self.adrs)

    def sign(self, digest):
        return core.wots_sign(self.params, self.skseed, self.pubseed, self.adrs, digest)


class Request:
    __slots__ = ("issuer", "subject", "kid", "pk_ots", "R", "digest", "sig_ots")

    def __init__(self, issuer, subject, kid, pk_ots, R, digest, sig_ots):
        self.issuer = issuer
        self.subject = subject
        self.kid = kid
        self.pk_ots = pk_ots
        self.R = R
        self.digest = digest
        self.sig_ots = sig_ots

    def record(self):
        return leaf_record(self.issuer, self.subject, self.kid, self.pk_ots, self.R,
                           self.digest, self.sig_ots)


class Latch:
    def __init__(self, level=1, batch=1024, anchor_alg=None, origin=b"latch.example/log",
                 anchored=False, name=None):
        cfg = LEVELS[level]
        self.level = level
        self.params = core.Params(cfg["n"], cfg["w"])
        self.pubseed = secrets.token_bytes(cfg["n"])
        self.anchor = sigalgs.make(anchor_alg or cfg["anchor"])
        self.origin = origin
        self.batch = batch
        self.anchored = anchored
        self.epoch = 0
        self.pending = []
        self.seen = set()
        self.htree = merkle.IncrementalTree()
        self.headlist = []
        self.prev = bytes(32)
        self.last_entry = 0
        self.paths = []
        self.head_index = 0
        self.head_path = []
        self.name = name or ("latch-a" if anchored else "latch")

    def make_request(self, identity, digest):
        key = OneTimeKey(self.params, self.pubseed)
        R = secrets.token_bytes(self.params.n)
        mu = msg_digest(self.params.n, R, key.pk, identity.issuer, identity.subject, digest)
        sig = key.sign(mu)
        return Request(identity.issuer, identity.subject, key.kid, key.pk, R, digest, sig)

    def admit(self, req):
        if req.kid in self.seen:
            return False
        mu = msg_digest(self.params.n, req.R, req.pk_ots, req.issuer, req.subject,
                        req.digest)
        rec = core.wots_pk_from_sig(self.params, req.sig_ots, mu, self.pubseed,
                                    core.adrs(req.kid))
        if rec != req.pk_ots:
            return False
        self.seen.add(req.kid)
        self.pending.append(req)
        return True

    def close_epoch(self, now=1800000000):
        reqs = self.pending
        self.pending = []
        leaves = [merkle.leaf_hash(r.record()) for r in reqs]
        paths, root = merkle.all_paths(leaves)
        self.paths = paths
        head = epoch_head(self.origin, self.epoch, now, root, len(leaves), self.prev)
        sig = self.anchor.sign(head)
        hl = merkle.leaf_hash(head)
        self.head_path = self.htree.append(hl)
        self.headlist.append(hl)
        self.head_index = self.htree.size - 1
        self.prev = self.htree.root()
        self.epoch += 1
        return reqs, leaves, head, sig

    def preload_epochs(self, count):
        for _ in range(count):
            leaf = secrets.token_bytes(32)
            self.htree.append(leaf)
            self.headlist.append(leaf)
        self.epoch += count

    def anchor_view(self):
        return merkle.FrozenTree(self.headlist)

    def landmark(self):
        return self.htree.root()

    def bundle(self, req, index, leaves, head, sig):
        proof = self.paths[index]
        return enc(req.issuer, req.subject, req.kid, req.pk_ots, req.R, req.digest,
                   req.sig_ots, u32(index), b"".join(proof), head, sig)

    def restaple(self, wire, view, head_index):
        f = unpack(wire)
        path = view.path(head_index)
        return enc(*(f[:10] + [u32(head_index), u32(view.size), b"".join(path)]))

    def restaple_all(self, wires, view, head_index=None):
        h = self.head_index if head_index is None else head_index
        return [self.restaple(w, view, h) for w in wires]

    def client(self, identity, digest, now=1800000000):
        return self.make_request(identity, digest)

    def service(self, reqs, now=1800000000):
        for r in reqs:
            if not self.admit(r):
                raise ValueError("rejected submission")
        kept, leaves, head, sig = self.close_epoch(now)
        self.last_entry = len(kept[0].record()) if kept else 0
        wires = [self.bundle(r, i, leaves, head, sig) for i, r in enumerate(kept)]
        return wires

    def run_epoch(self, identity, digests, now=1800000000):
        reqs = [self.client(identity, d, now) for d in digests]
        wires = self.service(reqs, now)
        if self.anchored:
            return self.restaple_all(wires, self.anchor_view())
        return wires

    def sign(self, identity, digest, now=1800000000):
        return self.run_epoch(identity, [digest], now)[0]

    def log_entry_size(self):
        return self.last_entry

    def verify(self, wire, identity=None, digest=None, landmark=None):
        f = unpack(wire)
        issuer, subject, kid, pk_ots, R, dg, sig_ots = f[0], f[1], f[2], f[3], f[4], f[5], f[6]
        index = r32(f[7])
        proof = chunks(f[8], 32)
        head = f[9]
        mu = msg_digest(self.params.n, R, pk_ots, issuer, subject, dg)
        rec = core.wots_pk_from_sig(self.params, sig_ots, mu, self.pubseed, core.adrs(kid))
        if rec != pk_ots:
            return False
        hf = unpack(head)
        if hf[0] != DOMAIN_HEAD or hf[1] != self.origin:
            return False
        root = hf[4]
        size = r32(hf[5])
        leaf = merkle.leaf_hash(leaf_record(issuer, subject, kid, pk_ots, R, dg, sig_ots))
        if not merkle.verify(leaf, index, size, proof, root):
            return False
        if self.anchored:
            hidx = r32(f[10])
            hsize = r32(f[11])
            hpath = chunks(f[12], 32)
            if landmark is None:
                return False
            if not merkle.verify(merkle.leaf_hash(head), hidx, hsize, hpath, landmark):
                return False
        else:
            if not self.anchor.verify(head, f[10]):
                return False
        if identity is not None and not identity.matches(issuer, subject):
            return False
        if digest is not None and dg != digest:
            return False
        return True
