#ifndef LATCHCORE_H
#define LATCHCORE_H

#include <stddef.h>
#include <stdint.h>

#define LC_ADRS_BYTES 22
#define LC_MAX_LEN 128
#define LC_MAX_HEIGHT 64

typedef struct {
    int n;
    int w;
    int logw;
    int len1;
    int len2;
    int len;
} lc_params;

int lc_params_init(lc_params *p, int n, int w);

void lc_sha256(const uint8_t *in, size_t inlen, uint8_t out[32]);

void lc_thash(const lc_params *p, const uint8_t *pubseed, const uint8_t adrs[LC_ADRS_BYTES],
              const uint8_t *msg, size_t msglen, uint8_t *out);

void lc_wots_pkgen(const lc_params *p, const uint8_t *skseed, const uint8_t *pubseed,
                   const uint8_t adrs[LC_ADRS_BYTES], uint8_t *pk);

void lc_wots_sign(const lc_params *p, const uint8_t *skseed, const uint8_t *pubseed,
                  const uint8_t adrs[LC_ADRS_BYTES], const uint8_t *digest, uint8_t *sig);

void lc_wots_pk_from_sig(const lc_params *p, const uint8_t *sig, const uint8_t *digest,
                         const uint8_t *pubseed, const uint8_t adrs[LC_ADRS_BYTES], uint8_t *pk);

void lc_mt_leaf(const uint8_t *data, size_t len, uint8_t out[32]);
void lc_mt_root(const uint8_t *leaves, size_t m, uint8_t out[32]);
int lc_mt_path(const uint8_t *leaves, size_t m, size_t idx, uint8_t *path);
int lc_mt_all_paths(const uint8_t *leaves, size_t m, uint8_t *paths, int *plens,
                    uint8_t root[32]);
int lc_mt_verify(const uint8_t leaf[32], size_t idx, size_t m, const uint8_t *path,
                 int plen, const uint8_t root[32]);

void lc_lmots_pkgen(int w, const uint8_t *skseed, const uint8_t I[16], uint32_t q, uint8_t pk[32]);
void lc_lmots_sign(int w, const uint8_t *skseed, const uint8_t I[16], uint32_t q,
                   const uint8_t *msg, size_t msglen, uint8_t *sig, int *siglen);
int lc_lmots_pk_from_sig(int w, const uint8_t I[16], uint32_t q, const uint8_t *msg,
                         size_t msglen, const uint8_t *sig, uint8_t pk[32]);
int lc_lmots_p(int w);

void lc_lms_build(int w, int h, const uint8_t *skseed, const uint8_t I[16], uint8_t *tree);
void lc_lms_keygen(int w, int h, const uint8_t *skseed, const uint8_t I[16], uint8_t root[32]);
int lc_lms_sign_t(int w, int h, const uint8_t *skseed, const uint8_t I[16], uint32_t q,
                  const uint8_t *msg, size_t msglen, const uint8_t *tree, uint8_t *sig);
int lc_lms_sign(int w, int h, const uint8_t *skseed, const uint8_t I[16], uint32_t q,
                const uint8_t *msg, size_t msglen, uint8_t *sig);
int lc_lms_verify(int w, int h, const uint8_t I[16], uint32_t q, const uint8_t *msg,
                  size_t msglen, const uint8_t *sig, const uint8_t root[32]);

int lc_ec_available(void);
int lc_ec_keygen(int curve, uint8_t *sk, int *sklen, uint8_t *pk, int *pklen);
int lc_ec_sign(int curve, const uint8_t *sk, int sklen, const uint8_t *msg, size_t mlen,
               uint8_t *sig, int *siglen);
int lc_ec_verify(int curve, const uint8_t *pk, int pklen, const uint8_t *msg, size_t mlen,
                 const uint8_t *sig, int siglen);

uint64_t lc_hash_counter(void);
void lc_hash_counter_reset(void);

#endif
