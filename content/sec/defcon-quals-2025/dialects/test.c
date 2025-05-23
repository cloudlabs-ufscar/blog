#include <stdio.h>
#include "libchina.h"

void sm4_test() {
    printf("SM4\n");

    uint8_t key[16] = {};
    SM4_KEY ks;
    ossl_sm4_set_key(key, &ks);
    for (int i = 0; i < SM4_KEY_SCHEDULE; i++) {
        printf("ks.rk[%02d] = 0x%08x\n", i, ks.rk[i]);
    }

    uint8_t in[16] = {};
    uint8_t out[16] = {};
    ossl_sm4_encrypt(in, out, &ks);
    for (int i = 0; i < 16; i++) {
        printf("out[%02d] = 0x%02x\n", i, out[i]);
    }
    printf("\n");
}

char st[] = {
    0x20,0x20,0x20,0x0,0xf7,0x20,0x20,0x2a,0x20,0x20,0x20,0x20,0x13,0x20,0x20,0x20,0x63,0x94,0x65,0xd,0xf5,0x2c,0x84,0x41,0xf9,0x7d,0x3c,0xcc,0xc0,0x1c,0xac,0xb2
};

void sm3_test() {
    printf("SM3\n");

    SM3_CTX ctx;
    ossl_sm3_init(&ctx);
    ossl_sm3_update(&ctx, st, 32);

    uint8_t md[SM3_DIGEST_LENGTH];
    ossl_sm3_final(md, &ctx);

    for (int i = 0; i < SM3_DIGEST_LENGTH; i++) {
        printf("%02x", md[i]);
    }
    printf("\n");
}


int main() {
    sm4_test();
    sm3_test();

    return 0;
}
