import secrets

from . import core, merkle, sigalgs
from .encoding import chunks, enc, r32, u32, u64, unpack

ORIGIN_CA = b"fulcio.example/ca"
ORIGIN_TSA = b"tsa.example/ts"
ORIGIN_LOG = b"rekor.example/log"
LOG_ID = bytes(32)
POLICY_OID = b"1.3.6.1.4.1.57264.3"
DOMAIN_BATCH = b"batch/v1/head"


def tbs_certificate(serial, alg_id, pk_e, issuer, subject, nb, na):
    return enc(b"tbs", serial, alg_id, pk_e, issuer, subject, u64(nb), u64(na),
               b"codeSigning", bytes(20), bytes(20))


def sct_message(tbs, timestamp):
    return enc(b"sct", LOG_ID, u64(timestamp), tbs)


def tst_info(sig_a, timestamp, nonce):
    return enc(b"tst", POLICY_OID, core.sha256(sig_a), u64(timestamp), nonce)


def log_body(digest, sig_a, cert):
    return enc(b"hashedrekord", b"0.0.2", b"sha2-256", digest, sig_a, cert)


def checkpoint(origin, size, root, timestamp):
    return enc(b"ckpt", origin, u64(size), root, u64(timestamp))


def batch_head(origin, epoch, now, root, size):
    return enc(DOMAIN_BATCH, origin, u32(epoch), u64(now), root, u32(size))


class BatchService:
    def __init__(self, alg, origin, anchored=False):
        self.anchored = anchored
        self.signer = sigalgs.make(alg)
        self.origin = origin
        self.epoch = 0
        self.htree = merkle.IncrementalTree()
        self.headlist = []
        self.paths = []
        self.head_index = 0
        self.head_path = []

    def close(self, messages, now):
        leaves = [merkle.leaf_hash(m) for m in messages]
        paths, root = merkle.all_paths(leaves)
        self.paths = paths
        head = batch_head(self.origin, self.epoch, now, root, len(leaves))
        sig = self.signer.sign(head)
        hl = merkle.leaf_hash(head)
        self.head_path = self.htree.append(hl)
        self.headlist.append(hl)
        self.head_index = self.htree.size - 1
        self.epoch += 1
        return paths, head, sig

    def preload(self, count):
        for _ in range(count):
            leaf = secrets.token_bytes(32)
            self.htree.append(leaf)
            self.headlist.append(leaf)

    def anchor_view(self):
        return merkle.FrozenTree(self.headlist)

    def landmark(self):
        return self.htree.root()

    def head_proof(self, head):
        return self.head_index, self.head_path, self.htree.size


class PqSigstore:
    def __init__(self, ephemeral, service, log_size=1 << 27, name=None):
        self.ephemeral_alg = ephemeral
        self.ca = sigalgs.make(service)
        self.ct = sigalgs.make(service)
        self.tsa = sigalgs.make(service)
        self.log = sigalgs.make(service)
        self.verifier = sigalgs.make(ephemeral)
        self.log_size = log_size
        self.service_alg = service
        self.name = name or f"sigstore/{ephemeral}"
        self.last_entry = 0

    def client(self, identity, digest, now=1800000000):
        eph = sigalgs.make(self.ephemeral_alg)
        pop = eph.sign(identity.subject)
        sig_a = eph.sign(digest)
        return (eph.pk, pop, sig_a, digest, identity)

    def service(self, reqs, now=1800000000):
        wires = []
        bodies = []
        rows = []
        for pk_e, pop, sig_a, digest, identity in reqs:
            if not self.verifier.verify_with_pk(pk_e, identity.subject, pop):
                raise ValueError("bad proof of possession")
            serial = secrets.token_bytes(20)
            tbs = tbs_certificate(serial, self.ephemeral_alg.encode(), pk_e,
                                  identity.issuer, identity.subject, now, now + 600)
            sct = enc(LOG_ID, u64(now), self.ct.sign(sct_message(tbs, now)))
            cert = enc(tbs, sct, self.ca.sign(enc(tbs, sct)))
            tsti = tst_info(sig_a, now, secrets.token_bytes(8))
            token = enc(tsti, self.tsa.sign(tsti))
            body = log_body(digest, sig_a, cert)
            bodies.append(body)
            rows.append((cert, sig_a, token, body))
        self.last_entry = len(bodies[0]) if bodies else 0
        for cert, sig_a, token, body in rows:
            leaf = merkle.leaf_hash(body)
            idx = secrets.randbelow(self.log_size)
            proof, root = merkle.synthetic_proof(leaf, idx, self.log_size)
            ck = checkpoint(ORIGIN_LOG, self.log_size, root, now)
            ck_sig = self.log.sign(ck)
            wires.append(enc(cert, sig_a, token, u64(idx), b"".join(proof), ck, ck_sig))
        return wires

    def run_epoch(self, identity, digests, now=1800000000):
        reqs = [self.client(identity, d, now) for d in digests]
        return self.service(reqs, now)

    def sign(self, identity, digest, now=1800000000):
        return self.run_epoch(identity, [digest], now)[0]

    def log_entry_size(self):
        return self.last_entry

    def verify(self, wire, identity=None, digest=None, landmark=None):
        f = unpack(wire)
        cert, sig_a, token, idxb, proofb, ck, ck_sig = f[:7]
        cf = unpack(cert)
        tbs, sct, ca_sig = cf[0], cf[1], cf[2]
        sf = unpack(sct)
        now = r32(sf[1])
        if not self.ct.verify(sct_message(tbs, now), sf[2]):
            return False
        if not self.ca.verify(enc(tbs, sct), ca_sig):
            return False
        tf = unpack(tbs)
        if not self.verifier.verify_with_pk(tf[3], digest, sig_a):
            return False
        tk = unpack(token)
        if not self.tsa.verify(tk[0], tk[1]):
            return False
        if not self.log.verify(ck, ck_sig):
            return False
        leaf = merkle.leaf_hash(log_body(digest, sig_a, cert))
        if not merkle.verify(leaf, r32(idxb), self.log_size, chunks(proofb, 32),
                             unpack(ck)[3]):
            return False
        if identity is not None and not identity.matches(tf[4], tf[5]):
            return False
        return True


class BatchedSigstore:
    def __init__(self, ephemeral, service, log_size=1 << 27, anchored=False,
                 scope="all", name=None):
        self.ephemeral_alg = ephemeral
        self.service_alg = service
        self.log_size = log_size
        self.anchored = anchored
        self.scope = scope
        self.ca = BatchService(service, ORIGIN_CA, anchored)
        self.tsa = BatchService(service, ORIGIN_TSA, anchored)
        self.log = BatchService(service, ORIGIN_LOG, anchored)
        self.direct_tsa = sigalgs.make(service)
        self.direct_log = sigalgs.make(service)
        self.verifier = sigalgs.make(ephemeral)
        self.last_entry = 0
        self.name = name or ("mtc-a/" if anchored else "mtc/") + ephemeral

    def preload_epochs(self, count):
        for svc in (self.ca, self.tsa, self.log):
            svc.preload(count)

    def landmarks(self):
        return {"ca": self.ca.landmark(), "tsa": self.tsa.landmark(),
                "log": self.log.landmark()}

    def client(self, identity, digest, now=1800000000):
        eph = sigalgs.make(self.ephemeral_alg)
        pop = eph.sign(identity.subject)
        sig_a = eph.sign(digest)
        return (eph.pk, pop, sig_a, digest, identity)

    def service(self, reqs, now=1800000000):
        tbss, rows = [], []
        for pk_e, pop, sig_a, digest, identity in reqs:
            if not self.verifier.verify_with_pk(pk_e, identity.subject, pop):
                raise ValueError("bad proof of possession")
            serial = secrets.token_bytes(20)
            tbs = tbs_certificate(serial, self.ephemeral_alg.encode(), pk_e,
                                  identity.issuer, identity.subject, now, now + 600)
            tbss.append(tbs)
            rows.append((tbs, sig_a, digest))
        ca_paths, ca_head, ca_sig = self.ca.close(tbss, now)
        tstis, bodies = [], []
        for tbs, sig_a, digest in rows:
            tsti = tst_info(sig_a, now, secrets.token_bytes(8))
            tstis.append(tsti)
            bodies.append(log_body(digest, sig_a, tbs))
        self.last_entry = len(bodies[0]) if bodies else 0
        if self.scope == "all":
            tsa_paths, tsa_head, tsa_sig = self.tsa.close(tstis, now)
            log_paths, log_head, log_sig = self.log.close(bodies, now)
        wires = []
        for i, (tbs, sig_a, digest) in enumerate(rows):
            parts = [tbs, sig_a, tstis[i], u32(i), b"".join(ca_paths[i]), ca_head]
            parts += self._tail(self.ca, ca_head, ca_sig)
            if self.scope == "all":
                parts += [u32(i), b"".join(tsa_paths[i]), tsa_head]
                parts += self._tail(self.tsa, tsa_head, tsa_sig)
                parts += [u32(i), b"".join(log_paths[i]), log_head]
                parts += self._tail(self.log, log_head, log_sig)
            else:
                leaf = merkle.leaf_hash(bodies[i])
                lidx = secrets.randbelow(self.log_size)
                lpath, lroot = merkle.synthetic_proof(leaf, lidx, self.log_size)
                ck = checkpoint(ORIGIN_LOG, self.log_size, lroot, now)
                parts += [self.direct_tsa.sign(tstis[i]), u64(lidx), b"".join(lpath),
                          ck, self.direct_log.sign(ck)]
            wires.append(enc(*parts))
        return wires

    def _tail(self, svc, head, sig):
        return [sig]

    def anchor_views(self):
        return {"ca": self.ca.anchor_view(), "tsa": self.tsa.anchor_view(),
                "log": self.log.anchor_view()}

    def restaple(self, wire, views, head_index=None):
        f = unpack(wire)
        out = list(f[:3])
        k = 3
        for key, svc in (("ca", self.ca), ("tsa", self.tsa), ("log", self.log)):
            v = views[key]
            h = svc.head_index if head_index is None else head_index
            out += [f[k], f[k + 1], f[k + 2], u32(h), u32(v.size),
                    b"".join(v.path(h))]
            k += 4
        return enc(*out)

    def restaple_all(self, wires, views, head_index=None):
        return [self.restaple(w, views, head_index) for w in wires]

    def run_epoch(self, identity, digests, now=1800000000):
        reqs = [self.client(identity, d, now) for d in digests]
        wires = self.service(reqs, now)
        if self.anchored:
            return self.restaple_all(wires, self.anchor_views())
        return wires

    def sign(self, identity, digest, now=1800000000):
        return self.run_epoch(identity, [digest], now)[0]

    def log_entry_size(self):
        return self.last_entry

    def _check(self, svc, msg, f, k, landmark):
        idx = r32(f[k])
        path = chunks(f[k + 1], 32)
        head = f[k + 2]
        hf = unpack(head)
        if hf[0] != DOMAIN_BATCH or hf[1] != svc.origin:
            return None
        if not merkle.verify(merkle.leaf_hash(msg), idx, r32(hf[5]), path, hf[4]):
            return None
        if self.anchored:
            if landmark is None:
                return None
            if not merkle.verify(merkle.leaf_hash(head), r32(f[k + 3]), r32(f[k + 4]),
                                 chunks(f[k + 5], 32), landmark):
                return None
            return k + 6
        if not svc.signer.verify(head, f[k + 3]):
            return None
        return k + 4

    def verify(self, wire, identity=None, digest=None, landmark=None):
        f = unpack(wire)
        tbs, sig_a, tsti = f[0], f[1], f[2]
        tf = unpack(tbs)
        if not self.verifier.verify_with_pk(tf[3], digest, sig_a):
            return False
        lm = landmark or {}
        k = self._check(self.ca, tbs, f, 3, lm.get("ca"))
        if k is None:
            return False
        if self.scope == "all":
            k = self._check(self.tsa, tsti, f, k, lm.get("tsa"))
            if k is None:
                return False
            k = self._check(self.log, log_body(digest, sig_a, tbs), f, k, lm.get("log"))
            if k is None:
                return False
        else:
            if not self.direct_tsa.verify(tsti, f[k]):
                return False
            ck = f[k + 3]
            if not self.direct_log.verify(ck, f[k + 4]):
                return False
            if not merkle.verify(merkle.leaf_hash(log_body(digest, sig_a, tbs)),
                                 r32(f[k + 1]), self.log_size, chunks(f[k + 2], 32),
                                 unpack(ck)[3]):
                return False
        if identity is not None and not identity.matches(tf[4], tf[5]):
            return False
        return True
