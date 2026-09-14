#include "latchcore.h"
#include <string.h>
#include <stdlib.h>

#ifdef LC_USE_OPENSSL
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/x509.h>
#endif

static uint64_t g_hash_calls = 0;

uint64_t lc_hash_counter(void) { return g_hash_calls; }
void lc_hash_counter_reset(void) { g_hash_calls = 0; }

#ifndef LC_USE_OPENSSL

static const uint32_t K256[64] = {
    0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
    0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
    0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
    0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
    0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
    0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
    0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
    0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};

#define ROTR(x,n) (((x) >> (n)) | ((x) << (32 - (n))))
#define S0(x) (ROTR(x,2) ^ ROTR(x,13) ^ ROTR(x,22))
#define S1(x) (ROTR(x,6) ^ ROTR(x,11) ^ ROTR(x,25))
#define s0(x) (ROTR(x,7) ^ ROTR(x,18) ^ ((x) >> 3))
#define s1(x) (ROTR(x,17) ^ ROTR(x,19) ^ ((x) >> 10))

static void sha256_compress(uint32_t st[8], const uint8_t block[64]) {
    uint32_t w[64], a,b,c,d,e,f,g,h,t1,t2;
    int i;
    for (i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[4*i] << 24) | ((uint32_t)block[4*i+1] << 16) |
               ((uint32_t)block[4*i+2] << 8) | ((uint32_t)block[4*i+3]);
    for (i = 16; i < 64; i++)
        w[i] = s1(w[i-2]) + w[i-7] + s0(w[i-15]) + w[i-16];
    a=st[0]; b=st[1]; c=st[2]; d=st[3]; e=st[4]; f=st[5]; g=st[6]; h=st[7];
    for (i = 0; i < 64; i++) {
        t1 = h + S1(e) + ((e & f) ^ (~e & g)) + K256[i] + w[i];
        t2 = S0(a) + ((a & b) ^ (a & c) ^ (b & c));
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    st[0]+=a; st[1]+=b; st[2]+=c; st[3]+=d; st[4]+=e; st[5]+=f; st[6]+=g; st[7]+=h;
}

static void sha256_raw(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    uint32_t st[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                      0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    uint8_t block[64];
    size_t i = 0;
    uint64_t bits = (uint64_t)inlen * 8;
    while (inlen - i >= 64) { sha256_compress(st, in + i); i += 64; }
    size_t rem = inlen - i;
    memcpy(block, in + i, rem);
    block[rem] = 0x80;
    if (rem >= 56) {
        memset(block + rem + 1, 0, 63 - rem);
        sha256_compress(st, block);
        memset(block, 0, 56);
    } else {
        memset(block + rem + 1, 0, 55 - rem);
    }
    for (int k = 0; k < 8; k++) block[56 + k] = (uint8_t)(bits >> (56 - 8*k));
    sha256_compress(st, block);
    for (int k = 0; k < 8; k++) {
        out[4*k]   = (uint8_t)(st[k] >> 24);
        out[4*k+1] = (uint8_t)(st[k] >> 16);
        out[4*k+2] = (uint8_t)(st[k] >> 8);
        out[4*k+3] = (uint8_t)(st[k]);
    }
}
#endif

void lc_sha256(const uint8_t *in, size_t inlen, uint8_t out[32]) {
    g_hash_calls++;
#ifdef LC_USE_OPENSSL
    SHA256_CTX c;
    SHA256_Init(&c);
    SHA256_Update(&c, in, inlen);
    SHA256_Final(out, &c);
#else
    sha256_raw(in, inlen, out);
#endif
}

int lc_params_init(lc_params *p, int n, int w) {
    int logw;
    if (w == 4) logw = 2;
    else if (w == 16) logw = 4;
    else if (w == 256) logw = 8;
    else return -1;
    if (n <= 0 || n > 32) return -1;
    p->n = n;
    p->w = w;
    p->logw = logw;
    p->len1 = (8 * n + logw - 1) / logw;
    int maxcs = p->len1 * (w - 1);
    int bits = 0;
    while ((1 << bits) <= maxcs) bits++;
    p->len2 = (bits + logw - 1) / logw;
    p->len = p->len1 + p->len2;
    if (p->len > LC_MAX_LEN) return -1;
    return 0;
}

void lc_thash(const lc_params *p, const uint8_t *pubseed, const uint8_t adrs[LC_ADRS_BYTES],
              const uint8_t *msg, size_t msglen, uint8_t *out) {
    uint8_t buf[64 + LC_ADRS_BYTES + LC_MAX_LEN * 32];
    uint8_t digest[32];
    size_t off = 0;
    memcpy(buf, pubseed, (size_t)p->n); off += (size_t)p->n;
    memcpy(buf + off, adrs, LC_ADRS_BYTES); off += LC_ADRS_BYTES;
    memcpy(buf + off, msg, msglen); off += msglen;
    lc_sha256(buf, off, digest);
    memcpy(out, digest, (size_t)p->n);
}

static void adrs_set_chain(uint8_t adrs[LC_ADRS_BYTES], uint32_t c) {
    adrs[17] = (uint8_t)(c >> 8); adrs[18] = (uint8_t)c;
}

static void adrs_set_hash(uint8_t adrs[LC_ADRS_BYTES], uint32_t h) {
    adrs[19] = (uint8_t)(h >> 8); adrs[20] = (uint8_t)h;
}

static void adrs_set_type(uint8_t adrs[LC_ADRS_BYTES], uint8_t t) { adrs[16] = t; }

static void chain(const lc_params *p, const uint8_t *in, int start, int steps,
                  const uint8_t *pubseed, uint8_t adrs[LC_ADRS_BYTES], uint8_t *out) {
    memcpy(out, in, (size_t)p->n);
    for (int j = start; j < start + steps && j < p->w; j++) {
        adrs_set_hash(adrs, (uint32_t)j);
        lc_thash(p, pubseed, adrs, out, (size_t)p->n, out);
    }
}

static void base_w(const lc_params *p, const uint8_t *x, int outlen, int *out) {
    int in = 0, bits = 0, total = 0;
    for (int i = 0; i < outlen; i++) {
        if (bits == 0) { total = x[in++]; bits = 8; }
        bits -= p->logw;
        out[i] = (total >> bits) & (p->w - 1);
    }
}

static void wots_encode(const lc_params *p, const uint8_t *digest, int *msg) {
    base_w(p, digest, p->len1, msg);
    int csum = 0;
    for (int i = 0; i < p->len1; i++) csum += p->w - 1 - msg[i];
    csum <<= ((8 - ((p->len2 * p->logw) % 8)) % 8);
    int csbytes = (p->len2 * p->logw + 7) / 8;
    uint8_t cs[8];
    for (int i = 0; i < csbytes; i++) cs[i] = (uint8_t)(csum >> (8 * (csbytes - 1 - i)));
    base_w(p, cs, p->len2, msg + p->len1);
}

static void wots_sk(const lc_params *p, const uint8_t *skseed, const uint8_t *pubseed,
                    const uint8_t adrs[LC_ADRS_BYTES], int i, uint8_t *out) {
    uint8_t buf[64 + LC_ADRS_BYTES + 32];
    uint8_t a[LC_ADRS_BYTES];
    uint8_t digest[32];
    memcpy(a, adrs, LC_ADRS_BYTES);
    adrs_set_type(a, 5);
    adrs_set_chain(a, (uint32_t)i);
    adrs_set_hash(a, 0);
    size_t off = 0;
    memcpy(buf, pubseed, (size_t)p->n); off += (size_t)p->n;
    memcpy(buf + off, a, LC_ADRS_BYTES); off += LC_ADRS_BYTES;
    memcpy(buf + off, skseed, (size_t)p->n); off += (size_t)p->n;
    lc_sha256(buf, off, digest);
    memcpy(out, digest, (size_t)p->n);
}

void lc_wots_pkgen(const lc_params *p, const uint8_t *skseed, const uint8_t *pubseed,
                   const uint8_t adrs[LC_ADRS_BYTES], uint8_t *pk) {
    uint8_t tmp[LC_MAX_LEN * 32];
    uint8_t a[LC_ADRS_BYTES];
    uint8_t sk[32];
    memcpy(a, adrs, LC_ADRS_BYTES);
    adrs_set_type(a, 0);
    for (int i = 0; i < p->len; i++) {
        wots_sk(p, skseed, pubseed, adrs, i, sk);
        adrs_set_chain(a, (uint32_t)i);
        chain(p, sk, 0, p->w - 1, pubseed, a, tmp + (size_t)i * p->n);
    }
    uint8_t b[LC_ADRS_BYTES];
    memcpy(b, adrs, LC_ADRS_BYTES);
    adrs_set_type(b, 1);
    adrs_set_chain(b, 0);
    adrs_set_hash(b, 0);
    lc_thash(p, pubseed, b, tmp, (size_t)p->len * p->n, pk);
}

void lc_wots_sign(const lc_params *p, const uint8_t *skseed, const uint8_t *pubseed,
                  const uint8_t adrs[LC_ADRS_BYTES], const uint8_t *digest, uint8_t *sig) {
    int msg[LC_MAX_LEN];
    uint8_t a[LC_ADRS_BYTES];
    uint8_t sk[32];
    wots_encode(p, digest, msg);
    memcpy(a, adrs, LC_ADRS_BYTES);
    adrs_set_type(a, 0);
    for (int i = 0; i < p->len; i++) {
        wots_sk(p, skseed, pubseed, adrs, i, sk);
        adrs_set_chain(a, (uint32_t)i);
        chain(p, sk, 0, msg[i], pubseed, a, sig + (size_t)i * p->n);
    }
}

void lc_wots_pk_from_sig(const lc_params *p, const uint8_t *sig, const uint8_t *digest,
                         const uint8_t *pubseed, const uint8_t adrs[LC_ADRS_BYTES], uint8_t *pk) {
    int msg[LC_MAX_LEN];
    uint8_t tmp[LC_MAX_LEN * 32];
    uint8_t a[LC_ADRS_BYTES];
    wots_encode(p, digest, msg);
    memcpy(a, adrs, LC_ADRS_BYTES);
    adrs_set_type(a, 0);
    for (int i = 0; i < p->len; i++) {
        adrs_set_chain(a, (uint32_t)i);
        chain(p, sig + (size_t)i * p->n, msg[i], p->w - 1 - msg[i], pubseed, a,
              tmp + (size_t)i * p->n);
    }
    uint8_t b[LC_ADRS_BYTES];
    memcpy(b, adrs, LC_ADRS_BYTES);
    adrs_set_type(b, 1);
    adrs_set_chain(b, 0);
    adrs_set_hash(b, 0);
    lc_thash(p, pubseed, b, tmp, (size_t)p->len * p->n, pk);
}

void lc_mt_leaf(const uint8_t *data, size_t len, uint8_t out[32]) {
    uint8_t *buf = (uint8_t *)malloc(len + 1);
    buf[0] = 0x00;
    memcpy(buf + 1, data, len);
    lc_sha256(buf, len + 1, out);
    free(buf);
}

static void mt_node(const uint8_t l[32], const uint8_t r[32], uint8_t out[32]) {
    uint8_t buf[65];
    buf[0] = 0x01;
    memcpy(buf + 1, l, 32);
    memcpy(buf + 33, r, 32);
    lc_sha256(buf, 65, out);
}

static size_t split(size_t n) {
    size_t k = 1;
    while (k * 2 < n) k *= 2;
    return k;
}

static void mth(const uint8_t *leaves, size_t n, uint8_t out[32]) {
    if (n == 0) { lc_sha256((const uint8_t *)"", 0, out); return; }
    if (n == 1) { memcpy(out, leaves, 32); return; }
    size_t k = split(n);
    uint8_t l[32], r[32];
    mth(leaves, k, l);
    mth(leaves + k * 32, n - k, r);
    mt_node(l, r, out);
}

void lc_mt_root(const uint8_t *leaves, size_t m, uint8_t out[32]) { mth(leaves, m, out); }

static int mt_path_rec(const uint8_t *leaves, size_t n, size_t idx, uint8_t *path) {
    if (n <= 1) return 0;
    size_t k = split(n);
    int plen;
    if (idx < k) {
        plen = mt_path_rec(leaves, k, idx, path);
        mth(leaves + k * 32, n - k, path + (size_t)plen * 32);
    } else {
        plen = mt_path_rec(leaves + k * 32, n - k, idx - k, path);
        mth(leaves, k, path + (size_t)plen * 32);
    }
    return plen + 1;
}

int lc_mt_path(const uint8_t *leaves, size_t m, size_t idx, uint8_t *path) {
    return mt_path_rec(leaves, m, idx, path);
}

static void mt_all(const uint8_t *leaves, size_t off, size_t n, uint8_t *paths, int *plens,
                   int maxlen, uint8_t out[32]) {
    if (n == 1) { memcpy(out, leaves + off * 32, 32); return; }
    size_t k = split(n);
    uint8_t l[32], r[32];
    mt_all(leaves, off, k, paths, plens, maxlen, l);
    mt_all(leaves, off + k, n - k, paths, plens, maxlen, r);
    for (size_t i = off; i < off + k; i++) {
        memcpy(paths + ((size_t)i * maxlen + plens[i]) * 32, r, 32);
        plens[i]++;
    }
    for (size_t i = off + k; i < off + n; i++) {
        memcpy(paths + ((size_t)i * maxlen + plens[i]) * 32, l, 32);
        plens[i]++;
    }
    mt_node(l, r, out);
}

int lc_mt_all_paths(const uint8_t *leaves, size_t m, uint8_t *paths, int *plens,
                    uint8_t root[32]) {
    int maxlen = 0;
    size_t t = 1;
    while (t < m) { t <<= 1; maxlen++; }
    for (size_t i = 0; i < m; i++) plens[i] = 0;
    if (m == 0) { lc_sha256((const uint8_t *)"", 0, root); return 0; }
    mt_all(leaves, 0, m, paths, plens, maxlen ? maxlen : 1, root);
    return maxlen ? maxlen : 1;
}

int lc_mt_verify(const uint8_t leaf[32], size_t idx, size_t m, const uint8_t *path,
                 int plen, const uint8_t root[32]) {
    if (idx >= m) return 0;
    size_t fn = idx, sn = m - 1;
    uint8_t r[32];
    memcpy(r, leaf, 32);
    for (int i = 0; i < plen; i++) {
        if (sn == 0) return 0;
        if ((fn & 1u) || fn == sn) {
            mt_node(path + (size_t)i * 32, r, r);
            while (!(fn & 1u) && fn != 0) { fn >>= 1; sn >>= 1; }
        } else {
            mt_node(r, path + (size_t)i * 32, r);
        }
        fn >>= 1; sn >>= 1;
    }
    if (sn != 0) return 0;
    return memcmp(r, root, 32) == 0;
}

int lc_lmots_p(int w) {
    if (w == 1) return 265;
    if (w == 2) return 133;
    if (w == 4) return 67;
    if (w == 8) return 34;
    return -1;
}

static int lmots_ls(int w) {
    if (w == 1) return 7;
    if (w == 2) return 6;
    if (w == 4) return 4;
    return 0;
}

static int lmots_coef(const uint8_t *s, int i, int w) {
    int shift = 8 - (w * (i % (8 / w)) + w);
    return (s[i * w / 8] >> shift) & ((1 << w) - 1);
}

static void u32be(uint8_t *o, uint32_t v) {
    o[0] = (uint8_t)(v >> 24); o[1] = (uint8_t)(v >> 16);
    o[2] = (uint8_t)(v >> 8);  o[3] = (uint8_t)v;
}

static void lmots_x(const uint8_t *skseed, const uint8_t I[16], uint32_t q, int i, uint8_t out[32]) {
    uint8_t buf[16 + 4 + 2 + 32];
    memcpy(buf, I, 16);
    u32be(buf + 16, q);
    buf[20] = (uint8_t)(i >> 8); buf[21] = (uint8_t)i;
    memcpy(buf + 22, skseed, 32);
    lc_sha256(buf, 54, out);
}

static int lmots_cksm(const uint8_t *q, int w, int p) {
    int sum = 0;
    int u = (32 * 8) / w;
    for (int i = 0; i < u; i++) sum += ((1 << w) - 1) - lmots_coef(q, i, w);
    (void)p;
    return sum << lmots_ls(w);
}

static void lmots_qcs(const uint8_t I[16], uint32_t q, const uint8_t *msg, size_t msglen,
                      const uint8_t C[32], int w, int p, uint8_t out[34]) {
    uint8_t *buf = (uint8_t *)malloc(16 + 4 + 2 + 32 + msglen);
    memcpy(buf, I, 16);
    u32be(buf + 16, q);
    buf[20] = 0x81; buf[21] = 0x81;
    memcpy(buf + 22, C, 32);
    memcpy(buf + 54, msg, msglen);
    uint8_t Q[32];
    lc_sha256(buf, 54 + msglen, Q);
    free(buf);
    memcpy(out, Q, 32);
    int cs = lmots_cksm(Q, w, p);
    out[32] = (uint8_t)(cs >> 8);
    out[33] = (uint8_t)cs;
}

void lc_lmots_pkgen(int w, const uint8_t *skseed, const uint8_t I[16], uint32_t q, uint8_t pk[32]) {
    int p = lc_lmots_p(w);
    uint8_t *y = (uint8_t *)malloc((size_t)p * 32);
    uint8_t tmp[32], buf[16 + 4 + 2 + 1 + 32];
    for (int i = 0; i < p; i++) {
        lmots_x(skseed, I, q, i, tmp);
        for (int j = 0; j < (1 << w) - 1; j++) {
            memcpy(buf, I, 16);
            u32be(buf + 16, q);
            buf[20] = (uint8_t)(i >> 8); buf[21] = (uint8_t)i;
            buf[22] = (uint8_t)j;
            memcpy(buf + 23, tmp, 32);
            lc_sha256(buf, 55, tmp);
        }
        memcpy(y + (size_t)i * 32, tmp, 32);
    }
    uint8_t *pb = (uint8_t *)malloc(22 + (size_t)p * 32);
    memcpy(pb, I, 16);
    u32be(pb + 16, q);
    pb[20] = 0x80; pb[21] = 0x80;
    memcpy(pb + 22, y, (size_t)p * 32);
    lc_sha256(pb, 22 + (size_t)p * 32, pk);
    free(pb);
    free(y);
}

void lc_lmots_sign(int w, const uint8_t *skseed, const uint8_t I[16], uint32_t q,
                   const uint8_t *msg, size_t msglen, uint8_t *sig, int *siglen) {
    int p = lc_lmots_p(w);
    uint8_t C[32], qcs[34], tmp[32], buf[16 + 4 + 2 + 1 + 32];
    memset(C, 0x5a, 32);
    lmots_x(skseed, I, q, 0xffff, C);
    lmots_qcs(I, q, msg, msglen, C, w, p, qcs);
    memcpy(sig, C, 32);
    for (int i = 0; i < p; i++) {
        int a = lmots_coef(qcs, i, w);
        lmots_x(skseed, I, q, i, tmp);
        for (int j = 0; j < a; j++) {
            memcpy(buf, I, 16);
            u32be(buf + 16, q);
            buf[20] = (uint8_t)(i >> 8); buf[21] = (uint8_t)i;
            buf[22] = (uint8_t)j;
            memcpy(buf + 23, tmp, 32);
            lc_sha256(buf, 55, tmp);
        }
        memcpy(sig + 32 + (size_t)i * 32, tmp, 32);
    }
    *siglen = 32 + p * 32;
}

int lc_lmots_pk_from_sig(int w, const uint8_t I[16], uint32_t q, const uint8_t *msg,
                         size_t msglen, const uint8_t *sig, uint8_t pk[32]) {
    int p = lc_lmots_p(w);
    uint8_t qcs[34], tmp[32], buf[16 + 4 + 2 + 1 + 32];
    lmots_qcs(I, q, msg, msglen, sig, w, p, qcs);
    uint8_t *y = (uint8_t *)malloc((size_t)p * 32);
    for (int i = 0; i < p; i++) {
        int a = lmots_coef(qcs, i, w);
        memcpy(tmp, sig + 32 + (size_t)i * 32, 32);
        for (int j = a; j < (1 << w) - 1; j++) {
            memcpy(buf, I, 16);
            u32be(buf + 16, q);
            buf[20] = (uint8_t)(i >> 8); buf[21] = (uint8_t)i;
            buf[22] = (uint8_t)j;
            memcpy(buf + 23, tmp, 32);
            lc_sha256(buf, 55, tmp);
        }
        memcpy(y + (size_t)i * 32, tmp, 32);
    }
    uint8_t *pb = (uint8_t *)malloc(22 + (size_t)p * 32);
    memcpy(pb, I, 16);
    u32be(pb + 16, q);
    pb[20] = 0x80; pb[21] = 0x80;
    memcpy(pb + 22, y, (size_t)p * 32);
    lc_sha256(pb, 22 + (size_t)p * 32, pk);
    free(pb);
    free(y);
    return 0;
}

static void lms_leaf(const uint8_t I[16], uint32_t r, const uint8_t K[32], uint8_t out[32]) {
    uint8_t buf[16 + 4 + 2 + 32];
    memcpy(buf, I, 16);
    u32be(buf + 16, r);
    buf[20] = 0x82; buf[21] = 0x82;
    memcpy(buf + 22, K, 32);
    lc_sha256(buf, 54, out);
}

static void lms_intr(const uint8_t I[16], uint32_t r, const uint8_t l[32], const uint8_t rr[32],
                     uint8_t out[32]) {
    uint8_t buf[16 + 4 + 2 + 64];
    memcpy(buf, I, 16);
    u32be(buf + 16, r);
    buf[20] = 0x83; buf[21] = 0x83;
    memcpy(buf + 22, l, 32);
    memcpy(buf + 54, rr, 32);
    lc_sha256(buf, 86, out);
}

static void lms_build(int w, int h, const uint8_t *skseed, const uint8_t I[16], uint8_t *tree) {
    uint32_t n = 1u << h;
    if (h == 0) return;
    uint8_t K[32];
    for (uint32_t i = 0; i < n; i++) {
        lc_lmots_pkgen(w, skseed, I, i, K);
        lms_leaf(I, n + i, K, tree + (size_t)(n + i) * 32);
    }
    for (uint32_t r = n - 1; r >= 1; r--)
        lms_intr(I, r, tree + (size_t)(2*r) * 32, tree + (size_t)(2*r+1) * 32, tree + (size_t)r * 32);
}

void lc_lms_build(int w, int h, const uint8_t *skseed, const uint8_t I[16], uint8_t *tree) {
    lms_build(w, h, skseed, I, tree);
}

void lc_lms_keygen(int w, int h, const uint8_t *skseed, const uint8_t I[16], uint8_t root[32]) {
    uint32_t n = 1u << h;
    uint8_t *tree = (uint8_t *)malloc((size_t)(2 * n) * 32);
    lms_build(w, h, skseed, I, tree);
    memcpy(root, tree + 32, 32);
    free(tree);
}

int lc_lms_sign_t(int w, int h, const uint8_t *skseed, const uint8_t I[16], uint32_t q,
                  const uint8_t *msg, size_t msglen, const uint8_t *tree, uint8_t *sig) {
    int olen = 0;
    uint32_t n = 1u << h;
    u32be(sig, q);
    lc_lmots_sign(w, skseed, I, q, msg, msglen, sig + 4, &olen);
    uint32_t r = n + q;
    for (int i = 0; i < h; i++)
        memcpy(sig + 4 + olen + (size_t)i * 32, tree + (size_t)((r >> i) ^ 1u) * 32, 32);
    return 4 + olen + h * 32;
}

int lc_lms_sign(int w, int h, const uint8_t *skseed, const uint8_t I[16], uint32_t q,
                const uint8_t *msg, size_t msglen, uint8_t *sig) {
    uint32_t n = 1u << h;
    uint8_t *tree = (uint8_t *)malloc((size_t)(2 * n) * 32);
    lms_build(w, h, skseed, I, tree);
    int r = lc_lms_sign_t(w, h, skseed, I, q, msg, msglen, tree, sig);
    free(tree);
    return r;
}

int lc_lms_verify(int w, int h, const uint8_t I[16], uint32_t q, const uint8_t *msg,
                  size_t msglen, const uint8_t *sig, const uint8_t root[32]) {
    int p = lc_lmots_p(w);
    uint8_t K[32], node[32];
    lc_lmots_pk_from_sig(w, I, q, msg, msglen, sig + 4, K);
    uint32_t n = 1u << h;
    uint32_t r = n + q;
    lms_leaf(I, r, K, node);
    const uint8_t *path = sig + 4 + 32 + (size_t)p * 32;
    for (int i = 0; i < h; i++) {
        if (r & 1u) lms_intr(I, r >> 1, path + (size_t)i * 32, node, node);
        else lms_intr(I, r >> 1, node, path + (size_t)i * 32, node);
        r >>= 1;
    }
    return memcmp(node, root, 32) == 0;
}


#ifdef LC_USE_OPENSSL

int lc_ec_available(void) { return 1; }

static EVP_PKEY *ec_gen(int curve) {
    EVP_PKEY *k = NULL;
    EVP_PKEY_CTX *c;
    if (curve == 2) {
        c = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
        if (!c) return NULL;
        if (EVP_PKEY_keygen_init(c) <= 0 || EVP_PKEY_keygen(c, &k) <= 0) k = NULL;
        EVP_PKEY_CTX_free(c);
        return k;
    }
    c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!c) return NULL;
    int nid = (curve == 0) ? NID_X9_62_prime256v1 : NID_secp384r1;
    if (EVP_PKEY_keygen_init(c) <= 0
        || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, nid) <= 0
        || EVP_PKEY_keygen(c, &k) <= 0) k = NULL;
    EVP_PKEY_CTX_free(c);
    return k;
}

int lc_ec_keygen(int curve, uint8_t *sk, int *sklen, uint8_t *pk, int *pklen) {
    EVP_PKEY *k = ec_gen(curve);
    if (!k) return -1;
    uint8_t *p = sk;
    int n = i2d_PrivateKey(k, &p);
    if (n <= 0) { EVP_PKEY_free(k); return -1; }
    *sklen = n;
    p = pk;
    n = i2d_PUBKEY(k, &p);
    if (n <= 0) { EVP_PKEY_free(k); return -1; }
    *pklen = n;
    EVP_PKEY_free(k);
    return 0;
}

int lc_ec_sign(int curve, const uint8_t *sk, int sklen, const uint8_t *msg, size_t mlen,
               uint8_t *sig, int *siglen) {
    const uint8_t *p = sk;
    int type = (curve == 2) ? EVP_PKEY_ED25519 : EVP_PKEY_EC;
    EVP_PKEY *k = d2i_PrivateKey(type, NULL, &p, sklen);
    if (!k) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    size_t sl = 512;
    int rc = -1;
    const EVP_MD *md = (curve == 2) ? NULL : ((curve == 0) ? EVP_sha256() : EVP_sha384());
    if (EVP_DigestSignInit(ctx, NULL, md, NULL, k) > 0
        && EVP_DigestSign(ctx, sig, &sl, msg, mlen) > 0) {
        *siglen = (int)sl;
        rc = 0;
    }
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(k);
    return rc;
}

int lc_ec_verify(int curve, const uint8_t *pk, int pklen, const uint8_t *msg, size_t mlen,
                 const uint8_t *sig, int siglen) {
    const uint8_t *p = pk;
    EVP_PKEY *k = d2i_PUBKEY(NULL, &p, pklen);
    if (!k) return 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = (curve == 2) ? NULL : ((curve == 0) ? EVP_sha256() : EVP_sha384());
    int rc = 0;
    if (EVP_DigestVerifyInit(ctx, NULL, md, NULL, k) > 0)
        rc = (EVP_DigestVerify(ctx, sig, (size_t)siglen, msg, mlen) == 1);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(k);
    return rc;
}

#else

int lc_ec_available(void) { return 0; }
int lc_ec_keygen(int curve, uint8_t *sk, int *sklen, uint8_t *pk, int *pklen) {
    (void)curve; (void)sk; (void)sklen; (void)pk; (void)pklen; return -1;
}
int lc_ec_sign(int curve, const uint8_t *sk, int sklen, const uint8_t *msg, size_t mlen,
               uint8_t *sig, int *siglen) {
    (void)curve; (void)sk; (void)sklen; (void)msg; (void)mlen; (void)sig; (void)siglen;
    return -1;
}
int lc_ec_verify(int curve, const uint8_t *pk, int pklen, const uint8_t *msg, size_t mlen,
                 const uint8_t *sig, int siglen) {
    (void)curve; (void)pk; (void)pklen; (void)msg; (void)mlen; (void)sig; (void)siglen;
    return 0;
}

#endif
