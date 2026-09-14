import ctypes
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))


def _libpath():
    for name in ("liblatchcore.so", "liblatchcore.dylib", "latchcore.dll"):
        p = os.path.join(_HERE, name)
        if os.path.exists(p):
            return p
    raise OSError(
        "liblatchcore not found; run 'make' in the repository root first"
    )


_lib = ctypes.CDLL(_libpath())


class LcParams(ctypes.Structure):
    _fields_ = [
        ("n", ctypes.c_int),
        ("w", ctypes.c_int),
        ("logw", ctypes.c_int),
        ("len1", ctypes.c_int),
        ("len2", ctypes.c_int),
        ("len", ctypes.c_int),
    ]


_lib.lc_params_init.argtypes = [ctypes.POINTER(LcParams), ctypes.c_int, ctypes.c_int]
_lib.lc_params_init.restype = ctypes.c_int

_lib.lc_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
_lib.lc_sha256.restype = None

_lib.lc_thash.argtypes = [ctypes.POINTER(LcParams), ctypes.c_char_p, ctypes.c_char_p,
                          ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
_lib.lc_thash.restype = None

_lib.lc_wots_pkgen.argtypes = [ctypes.POINTER(LcParams), ctypes.c_char_p, ctypes.c_char_p,
                               ctypes.c_char_p, ctypes.c_char_p]
_lib.lc_wots_sign.argtypes = [ctypes.POINTER(LcParams), ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
_lib.lc_wots_pk_from_sig.argtypes = [ctypes.POINTER(LcParams), ctypes.c_char_p, ctypes.c_char_p,
                                     ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]

_lib.lc_mt_leaf.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
_lib.lc_mt_root.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
_lib.lc_mt_path.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t, ctypes.c_char_p]
_lib.lc_mt_path.restype = ctypes.c_int
_lib.lc_mt_all_paths.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                                 ctypes.POINTER(ctypes.c_int), ctypes.c_char_p]
_lib.lc_mt_all_paths.restype = ctypes.c_int
_lib.lc_mt_verify.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_size_t,
                              ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p]
_lib.lc_mt_verify.restype = ctypes.c_int

_lib.lc_lmots_p.argtypes = [ctypes.c_int]
_lib.lc_lmots_p.restype = ctypes.c_int
_lib.lc_lms_build.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_char_p]
_lib.lc_lms_keygen.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                               ctypes.c_char_p]
_lib.lc_lms_sign_t.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_char_p,
                               ctypes.c_uint32, ctypes.c_char_p, ctypes.c_size_t,
                               ctypes.c_char_p, ctypes.c_char_p]
_lib.lc_lms_sign_t.restype = ctypes.c_int
_lib.lc_lms_verify.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32,
                               ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p]
_lib.lc_lms_verify.restype = ctypes.c_int

_lib.lc_ec_available.restype = ctypes.c_int
_lib.lc_ec_keygen.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int),
                              ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
_lib.lc_ec_keygen.restype = ctypes.c_int
_lib.lc_ec_sign.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                            ctypes.c_size_t, ctypes.c_char_p, ctypes.POINTER(ctypes.c_int)]
_lib.lc_ec_sign.restype = ctypes.c_int
_lib.lc_ec_verify.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p,
                              ctypes.c_size_t, ctypes.c_char_p, ctypes.c_int]
_lib.lc_ec_verify.restype = ctypes.c_int

_lib.lc_hash_counter.restype = ctypes.c_uint64
_lib.lc_hash_counter_reset.restype = None


def hash_calls():
    return _lib.lc_hash_counter()


def reset_hash_calls():
    _lib.lc_hash_counter_reset()


def sha256(data):
    out = ctypes.create_string_buffer(32)
    _lib.lc_sha256(data, len(data), out)
    return out.raw[:32]


class Params:
    def __init__(self, n, w):
        self.c = LcParams()
        if _lib.lc_params_init(ctypes.byref(self.c), n, w) != 0:
            raise ValueError("unsupported parameter set")
        self.n = n
        self.w = w
        self.len1 = self.c.len1
        self.len2 = self.c.len2
        self.len = self.c.len

    @property
    def sig_bytes(self):
        return self.len * self.n

    def __repr__(self):
        return f"Params(n={self.n}, w={self.w}, len={self.len})"


ADRS_BYTES = 22


def adrs(kid, typ=0, chain=0, hpos=0):
    if len(kid) != 16:
        raise ValueError("key identifier must be 16 bytes")
    return (kid + bytes([typ & 0xFF])
            + chain.to_bytes(2, "big")
            + hpos.to_bytes(2, "big")
            + b"\x00")


def wots_pkgen(p, skseed, pubseed, a):
    out = ctypes.create_string_buffer(p.n)
    _lib.lc_wots_pkgen(ctypes.byref(p.c), skseed, pubseed, a, out)
    return out.raw[:p.n]


def wots_sign(p, skseed, pubseed, a, digest):
    out = ctypes.create_string_buffer(p.sig_bytes)
    _lib.lc_wots_sign(ctypes.byref(p.c), skseed, pubseed, a, digest, out)
    return out.raw[:p.sig_bytes]


def wots_pk_from_sig(p, sig, digest, pubseed, a):
    out = ctypes.create_string_buffer(p.n)
    _lib.lc_wots_pk_from_sig(ctypes.byref(p.c), sig, digest, pubseed, a, out)
    return out.raw[:p.n]


def mt_leaf(data):
    out = ctypes.create_string_buffer(32)
    _lib.lc_mt_leaf(data, len(data), out)
    return out.raw[:32]


def mt_root(leaves):
    blob = b"".join(leaves)
    out = ctypes.create_string_buffer(32)
    _lib.lc_mt_root(blob, len(leaves), out)
    return out.raw[:32]


def mt_path(leaves, idx):
    blob = b"".join(leaves)
    buf = ctypes.create_string_buffer(64 * 32)
    plen = _lib.lc_mt_path(blob, len(leaves), idx, buf)
    raw = buf.raw
    return [raw[32 * i:32 * (i + 1)] for i in range(plen)]


def mt_root_raw(blob, m):
    out = ctypes.create_string_buffer(32)
    _lib.lc_mt_root(blob, m, out)
    return out.raw[:32]


def mt_path_raw(blob, m, idx):
    buf = ctypes.create_string_buffer(64 * 32)
    plen = _lib.lc_mt_path(blob, m, idx, buf)
    raw = buf.raw
    return [raw[32 * i:32 * (i + 1)] for i in range(plen)]


def mt_all_paths(leaves):
    m = len(leaves)
    maxlen = max(1, (m - 1).bit_length())
    blob = b"".join(leaves)
    buf = ctypes.create_string_buffer(m * maxlen * 32)
    plens = (ctypes.c_int * m)()
    root = ctypes.create_string_buffer(32)
    ml = _lib.lc_mt_all_paths(blob, m, buf, plens, root)
    raw = buf.raw
    paths = []
    for i in range(m):
        base = i * ml * 32
        paths.append([raw[base + 32 * j: base + 32 * (j + 1)] for j in range(plens[i])])
    return paths, root.raw[:32]


def mt_verify(leaf, idx, size, path, root):
    blob = b"".join(path)
    return bool(_lib.lc_mt_verify(leaf, idx, size, blob, len(path), root))


def lmots_p(w):
    return _lib.lc_lmots_p(w)


def lms_tree_bytes(h):
    return (1 << (h + 1)) * 32


def lms_build(w, h, skseed, ident):
    buf = ctypes.create_string_buffer(lms_tree_bytes(h))
    _lib.lc_lms_build(w, h, skseed, ident, buf)
    return buf


def lms_root(tree):
    return tree.raw[32:64]


def lms_sig_bytes(w, h):
    return 4 + 32 + lmots_p(w) * 32 + h * 32


def lms_sign(w, h, skseed, ident, q, msg, tree):
    out = ctypes.create_string_buffer(lms_sig_bytes(w, h))
    ln = _lib.lc_lms_sign_t(w, h, skseed, ident, q, msg, len(msg), tree, out)
    return out.raw[:ln]


def lms_verify(w, h, ident, q, msg, sig, root):
    return bool(_lib.lc_lms_verify(w, h, ident, q, msg, len(msg), sig, root))


if sys.version_info < (3, 8):
    raise RuntimeError("Python 3.8 or newer is required")


EC_CURVES = {"ecdsa-p256": 0, "ecdsa-p384": 1, "ed25519": 2}


def ec_available():
    return bool(_lib.lc_ec_available())


def ec_keygen(curve):
    sk = ctypes.create_string_buffer(512)
    pk = ctypes.create_string_buffer(512)
    a = ctypes.c_int(0)
    b = ctypes.c_int(0)
    if _lib.lc_ec_keygen(curve, sk, ctypes.byref(a), pk, ctypes.byref(b)) != 0:
        raise RuntimeError("key generation failed")
    return sk.raw[:a.value], pk.raw[:b.value]


def ec_sign(curve, sk, msg):
    sig = ctypes.create_string_buffer(512)
    n = ctypes.c_int(0)
    if _lib.lc_ec_sign(curve, sk, len(sk), msg, len(msg), sig, ctypes.byref(n)) != 0:
        raise RuntimeError("signing failed")
    return sig.raw[:n.value]


def ec_verify(curve, pk, msg, sig):
    return bool(_lib.lc_ec_verify(curve, pk, len(pk), msg, len(msg), sig, len(sig)))
