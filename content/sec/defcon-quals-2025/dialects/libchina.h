#ifndef LIBCHINA_H
#define LIBCHINA_H

#include <stdint.h>

# define SM4_KEY_SCHEDULE  32

typedef struct SM4_KEY_st {
    uint32_t rk[SM4_KEY_SCHEDULE];
} SM4_KEY;

int ossl_sm4_set_key(const uint8_t *key, SM4_KEY *ks);
void ossl_sm4_encrypt(const uint8_t *in, uint8_t *out, const SM4_KEY *ks);

# define SM3_DIGEST_LENGTH 32
# define SM3_WORD unsigned int

# define SM3_CBLOCK      64
# define SM3_LBLOCK      (SM3_CBLOCK/4)

typedef struct SM3state_st {
   SM3_WORD A, B, C, D, E, F, G, H;
   SM3_WORD Nl, Nh;
   SM3_WORD data[SM3_LBLOCK];
   unsigned int num;
} SM3_CTX;

int ossl_sm3_init(SM3_CTX *c);
int ossl_sm3_update(SM3_CTX *c, const void *data, size_t len);
int ossl_sm3_final(unsigned char *md, SM3_CTX *c);

#endif
