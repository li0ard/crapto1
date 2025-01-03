#include "crypto1/crapto1.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

int main (int argc, char *argv[]) {
    uint32_t uid;
	uint32_t tag_challenge;
	uint32_t nr_enc;
	uint32_t reader_response;
	uint32_t tag_response;

    printf("crapto1 - (64-bit mode)\n");

    if (argc < 6) {
        printf("\nusage: %s <uid> <tag_challenge> <nr_enc> <reader_response> <tag_response>\n\n", argv[0]);
        return 1;
    }

    sscanf(argv[1], "%x", &uid);
    sscanf(argv[2], "%x", &tag_challenge);
    sscanf(argv[3], "%x", &nr_enc);
    sscanf(argv[4], "%x", &reader_response);
    sscanf(argv[5], "%x", &tag_response);

    struct Crypto1State *revstate;
	uint64_t key;
    uint32_t ks2 = reader_response ^ prng_successor(tag_challenge, 64);
	uint32_t ks3 = tag_response ^ prng_successor(tag_challenge, 96);

	revstate = lfsr_recovery64(ks2, ks3);
 
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, nr_enc, 1);
	lfsr_rollback_word(revstate, uid ^ tag_challenge, 0);
	crypto1_get_lfsr(revstate, &key);
    printf("\nKey: %012" PRIx64 "\n\n", key);
	crypto1_destroy(revstate);
}