#include "crypto1/crapto1.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

int main (int argc, char *argv[]) { 
    uint64_t key;
    uint32_t uid;
    uint32_t tag_challenge;
    uint32_t reader_challenge;
    uint32_t reader_response;
    uint32_t tag_challenge2;
    uint32_t reader_challenge2;
    uint32_t reader_response2;

    printf("crapto1 - (32-bit mode)\n");

    if (argc < 8) {
        printf("\nusage: %s <uid> <tag_challenge> <reader_challenge> <reader_response> <tag_challenge2> <reader_challenge2> <reader_response2>\n\n", argv[0]);
        return 1;
    }

    sscanf(argv[1], "%x", &uid);
    sscanf(argv[2], "%x", &tag_challenge);
    sscanf(argv[3], "%x", &reader_challenge);
    sscanf(argv[4], "%x", &reader_response);
    sscanf(argv[5], "%x", &tag_challenge2);
    sscanf(argv[6], "%x", &reader_challenge2);
    sscanf(argv[7], "%x", &reader_response2);

    struct Crypto1State *s = lfsr_recovery32(reader_response ^ prng_successor(tag_challenge, 64), 0), *t;
	for(t = s; t->odd | t->even; ++t) {
		lfsr_rollback_word(t, 0, 0);
		lfsr_rollback_word(t, reader_challenge, 1);
		lfsr_rollback_word(t, uid ^ tag_challenge, 0);
		crypto1_get_lfsr(t, &key);
		crypto1_word(t, uid ^ tag_challenge2, 0);
		crypto1_word(t, reader_challenge2, 1);
		if (reader_response2 == (crypto1_word(t, 0, 0) ^ prng_successor(tag_challenge2, 64))) {
			printf("\nKey: %012" PRIx64 "\n\n", key);
			break;
		}
	}
	
	free(s);


}