#include <stdio.h>
#include "libchina.h"
#include <omp.h>
#include <string.h>
#include "sha512.h"
#include <stdlib.h>

char sha512_test(uint8_t *buffer) {
    uint8_t md[128];
    sha512_ctx ctx;

    sha512_init(&ctx);
    sha512_update(&ctx, buffer, 32);
    sha512_final(&ctx, md);

    return md[0] == 0x8d && md[1] == 0x36 && md[2] == 0;
}
char sm3_test(uint8_t *buffer) {
    SM3_CTX ctx;
    ossl_sm3_init(&ctx);
    ossl_sm3_update(&ctx, buffer, 32);

    uint8_t md[SM3_DIGEST_LENGTH];
    ossl_sm3_final(md, &ctx);

    return !(md[0] | md[1] | md[2]);
}


int main() {
    uint8_t gbl_buffer[32];

    puts("Algo: ");
    char nome[100];
    scanf("%s", nome);

    char sm3 = 0;
    if(nome[1] == 'm') {
        // sm3 
        sm3 = 1;
    }  // outro eh sha512

    puts("Buffer: ");
    for(int i = 0; i < 32; i++) scanf("%x", gbl_buffer + i);

    //memcpy(gbl_buffer, st, 32);

    //printf("\nLeu: ");
    //for(int i = 0; i < 32; i++) printf("%02x ", gbl_buffer[i]);
    //puts("");

    #pragma omp parallel for
    for(int i = 0; i < (1<<30); i++) {
        uint8_t buffer[32];

        memcpy(buffer, gbl_buffer, 32);
        buffer[4] = (i) & 0xff;
        buffer[7] = (i>>8) & 0xff;
        buffer[12] = (i >> 16) & 0xff;
        buffer[3] = (i >> 24) & 0xff;

        if((sm3 &&sm3_test(buffer)) || (!sm3 && sha512_test(buffer))) {
#pragma omp critical 
        {
            printf("Achou i = %d:", i);        
            for(int j = 0; j < 32; j++) printf("%02x", buffer[j]);
            puts("");
        }
        exit(0);
        }
    }

    return 0;
}
