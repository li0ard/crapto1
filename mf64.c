#include "crypto1/crapto1.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

int main (int argc, char *argv[]) {
    uint32_t uid;
	uint32_t tag_challenge;
	uint32_t reader_challenge;
	uint32_t reader_response;
	uint32_t tag_response;

    printf("crapto1 - (64-bit mode)\n");

    if (argc < 6) {
        printf("\nusage: %s <uid> <tag_challenge> <reader_challenge> <reader_response> <tag_response>\n\n", argv[0]);
        return 1;
    }

    int encc = argc - 6;
    int enclen[encc];
    uint8_t enc[encc][120];

    sscanf(argv[1], "%x", &uid);
    sscanf(argv[2], "%x", &tag_challenge);
    sscanf(argv[3], "%x", &reader_challenge);
    sscanf(argv[4], "%x", &reader_response);
    sscanf(argv[5], "%x", &tag_response);
    for (int i = 0; i < encc; i++) {
        enclen[i] = strlen(argv[i + 6]) / 2;
        for (int i2 = 0; i2 < enclen[i]; i2++) {
            sscanf(argv[i + 6] + i2 * 2, "%2hhx", &enc[i][i2]);
        }
    }

    printf("+---------------------+------+----------+\n");
    printf("| Input data          | alt. | Value    |\n");
    printf("+---------------------+------+----------+\n");
    printf("| UID                 |  --  | %08x |\n", uid);
    printf("| Tag challenge       |  nt  | %08x |\n", tag_challenge);
    printf("| Reader challenge    |  nr  | %08x |\n", reader_challenge);
    printf("| Reader response     |  ar  | %08x |\n", reader_response);
    printf("| Tag response        |  at  | %08x |\n", tag_response);
    printf("+---------------------+------+----------+\n");
    if(encc != 0) {
        printf("\nEncrypted communication:\n");
    }
    for (int i = 0; i < encc; i++) {
        printf("enc%d: ", i);
        for (int i2 = 0; i2 < enclen[i]; i2++) {
            printf("%02x", enc[i][i2]);
        }
        printf("\n");
    }

    struct Crypto1State *revstate;
	uint64_t key;
    uint32_t p64 = prng_successor(tag_challenge, 64);
    uint32_t ks2 = reader_response ^ p64;
	uint32_t ks3 = tag_response ^ prng_successor(tag_challenge, 96);

    printf("\nLFSR successors of the tag challenge:\n");
    printf(" nt': %08x\n", p64);
    printf(" nt'': %08x\n", prng_successor(p64, 32));
    printf("\nKeystream used to generate {ar} and {at}:\n");
    printf(" ks2: %08x\n", ks2);
    printf(" ks3: %08x\n", ks3);

	revstate = lfsr_recovery64(ks2, ks3);

    if (argc > 6) {
        printf("\nDecrypted communication:\n");
        uint8_t ks4;
        int rollb = 0;
        for (int i = 0; i < encc; i++) {
            printf("dec%d: ", i);
            for (int i2 = 0; i2 < enclen[i]; i2++) {
                ks4 = crypto1_byte(revstate, 0, 0);
                printf("%02x", ks4 ^ enc[i][i2]);
                rollb += 1;
            }
            printf("\n");
        }
        for (int i = 0; i < rollb; i++)
            lfsr_rollback_byte(revstate, 0, 0);
    }
 
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, reader_challenge, 1);
	lfsr_rollback_word(revstate, uid ^ tag_challenge, 0);
	crypto1_get_lfsr(revstate, &key);
    printf("\nKey: %012" PRIx64 "\n\n", key);
	crypto1_destroy(revstate);
}