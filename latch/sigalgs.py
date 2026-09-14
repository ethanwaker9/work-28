import secrets

import oqs

from . import core

OQS_ALGS = {
    "ml-dsa-44": "ML-DSA-44",
    "ml-dsa-65": "ML-DSA-65",
    "ml-dsa-87": "ML-DSA-87",
    "falcon-512": "Falcon-512",
    "falcon-1024": "Falcon-1024",
    "slh-dsa-sha2-128s": "SLH_DSA_PURE_SHA2_128S",
    "slh-dsa-sha2-128f": "SLH_DSA_PURE_SHA2_128F",
    "slh-dsa-sha2-192s": "SLH_DSA_PURE_SHA2_192S",
    "slh-dsa-sha2-192f": "SLH_DSA_PURE_SHA2_192F",
}

OQS_STATEFUL = {
    "xmss-sha2-10-256": ("XMSS-SHA2_10_256", 10),
    "xmss-sha2-16-256": ("XMSS-SHA2_16_256", 16),
    "xmss-sha2-20-256": ("XMSS-SHA2_20_256", 20),
}

LMS_ALGS = {
    "lms-sha256-h10-w8": (8, 10),
    "lms-sha256-h10-w4": (4, 10),
    "lms-sha256-h15-w8": (8, 15),
}

LEVEL = {
    "ecdsa-p256": 0, "ecdsa-p384": 0, "ed25519": 0,
    "ml-dsa-44": 2, "ml-dsa-65": 3, "ml-dsa-87": 5,
    "falcon-512": 1, "falcon-1024": 5,
    "slh-dsa-sha2-128s": 1, "slh-dsa-sha2-128f": 1,
    "slh-dsa-sha2-192s": 3, "slh-dsa-sha2-192f": 3,
    "xmss-sha2-10-256": 1, "xmss-sha2-16-256": 1, "xmss-sha2-20-256": 1,
    "lms-sha256-h10-w8": 1, "lms-sha256-h10-w4": 1, "lms-sha256-h15-w8": 1,
}


class Signer:
    def __init__(self, name):
        self.name = name

    def sign(self, msg):
        raise NotImplementedError

    def verify(self, msg, sig):
        return self.verify_with_pk(self.pk, msg, sig)

    def verify_with_pk(self, pk, msg, sig):
        raise NotImplementedError

    @property
    def pk_bytes(self):
        return len(self.pk)

    @property
    def sig_bytes(self):
        raise NotImplementedError


class OqsSigner(Signer):
    def __init__(self, name):
        super().__init__(name)
        self._alg = OQS_ALGS[name]
        self._s = oqs.Signature(self._alg)
        self.pk = self._s.generate_keypair()
        self._v = oqs.Signature(self._alg)
        self._len = None

    def sign(self, msg):
        return self._s.sign(msg)

    def verify_with_pk(self, pk, msg, sig):
        return self._v.verify(msg, sig, pk)

    @property
    def sig_bytes(self):
        if self._len is None:
            self._len = len(self._s.sign(b"probe"))
        return self._len


class XmssSigner(Signer):
    def __init__(self, name):
        super().__init__(name)
        self._alg, self.h = OQS_STATEFUL[name]
        self._s = oqs.StatefulSignature(self._alg)
        self.pk = self._s.generate_keypair()
        self._v = oqs.StatefulSignature(self._alg)
        self._len = None

    def sign(self, msg):
        return self._s.sign(msg)

    def verify_with_pk(self, pk, msg, sig):
        return self._v.verify(msg, sig, pk)

    @property
    def sig_bytes(self):
        if self._len is None:
            self._len = len(self._s.sign(b"probe"))
        return self._len


class LmsSigner(Signer):
    def __init__(self, name):
        super().__init__(name)
        self.w, self.h = LMS_ALGS[name]
        self.skseed = secrets.token_bytes(32)
        self.ident = secrets.token_bytes(16)
        self.tree = core.lms_build(self.w, self.h, self.skseed, self.ident)
        self.pk = self.ident + core.lms_root(self.tree)
        self.q = 0

    def sign(self, msg):
        s = core.lms_sign(self.w, self.h, self.skseed, self.ident, self.q, msg, self.tree)
        self.q = (self.q + 1) % (1 << self.h)
        return s

    def verify_with_pk(self, pk, msg, sig):
        q = int.from_bytes(sig[:4], "big")
        return core.lms_verify(self.w, self.h, pk[:16], q, msg, sig, pk[16:])

    @property
    def sig_bytes(self):
        return 4 + 32 + core.lmots_p(self.w) * 32 + self.h * 32


class EcSigner(Signer):
    def __init__(self, name):
        super().__init__(name)
        self.curve = core.EC_CURVES[name]
        self.sk, self.pk = core.ec_keygen(self.curve)

    def sign(self, msg):
        return core.ec_sign(self.curve, self.sk, msg)

    def verify_with_pk(self, pk, msg, sig):
        return core.ec_verify(self.curve, pk, msg, sig)

    @property
    def sig_bytes(self):
        return len(self.sign(b"probe"))


def make(name):
    if name in OQS_ALGS:
        return OqsSigner(name)
    if name in OQS_STATEFUL:
        return XmssSigner(name)
    if name in LMS_ALGS:
        return LmsSigner(name)
    if name in core.EC_CURVES:
        return EcSigner(name)
    raise ValueError("unknown signature algorithm " + name)
