import secrets

from . import core


def leaf_hash(data):
    return core.mt_leaf(data)


def root(leaves):
    return core.mt_root(leaves)


def path(leaves, idx):
    return core.mt_path(leaves, idx)


def all_paths(leaves):
    return core.mt_all_paths(leaves)


def root_raw(blob, m):
    return core.mt_root_raw(blob, m)


def path_raw(blob, m, idx):
    return core.mt_path_raw(blob, m, idx)


def verify(leaf, idx, size, proof, expected_root):
    return core.mt_verify(leaf, idx, size, proof, expected_root)


def proof_length(idx, size):
    if size <= 1:
        return 0
    k = 1
    while k * 2 < size:
        k *= 2
    if idx < k:
        return proof_length(idx, k) + 1
    return proof_length(idx - k, size - k) + 1


def synthetic_proof(leaf, idx, size, rng=None):
    plen = proof_length(idx, size)
    rnd = rng or secrets.token_bytes
    proof = [rnd(32) for _ in range(plen)]
    fn, sn = idx, size - 1
    acc = leaf
    for node in proof:
        if (fn & 1) or fn == sn:
            acc = core.sha256(b"\x01" + node + acc)
            while (not (fn & 1)) and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            acc = core.sha256(b"\x01" + acc + node)
        fn >>= 1
        sn >>= 1
    return proof, acc


class IncrementalTree:
    def __init__(self):
        self.stack = []
        self.size = 0
        self.last_path = []

    def append(self, leaf):
        node = leaf
        level = 0
        path = []
        while self.stack and self.stack[-1][0] == level:
            lvl, left = self.stack.pop()
            path.append(left)
            node = core.sha256(b"\x01" + left + node)
            level += 1
        self.stack.append((level, node))
        for lvl, h in reversed(self.stack[:-1]):
            path.append(h)
        self.size += 1
        self.last_path = path
        return path

    def root(self):
        if not self.stack:
            return core.sha256(b"")
        acc = self.stack[-1][1]
        for lvl, h in reversed(self.stack[:-1]):
            acc = core.sha256(b"\x01" + h + acc)
        return acc


class FrozenTree:
    def __init__(self, leaves):
        self.size = len(leaves)
        self.levels = [list(leaves)]
        cur = self.levels[0]
        while len(cur) > 1:
            nxt = []
            for i in range(0, len(cur) - 1, 2):
                nxt.append(core.sha256(b"\x01" + cur[i] + cur[i + 1]))
            if len(cur) & 1:
                nxt.append(cur[-1])
            self.levels.append(nxt)
            cur = nxt

    def root(self):
        return self.levels[-1][0] if self.size else core.sha256(b"")

    def path(self, idx):
        out = []
        for lvl in self.levels[:-1]:
            sib = idx ^ 1
            if sib < len(lvl):
                out.append(lvl[sib])
            idx >>= 1
        return out
