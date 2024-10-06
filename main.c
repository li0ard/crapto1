#include "crapto1.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

/**
 * One-log method
 * It is used to calculate the key when you have only 1 pair of tag challenge, nr_enc, reader response, tag response
*/
unsigned char* Onelog(uint32_t uid, uint32_t tag_challenge, uint32_t nr_enc, uint32_t reader_response, uint32_t tag_response) {
	struct Crypto1State *revstate;
	uint64_t lfsr;
	unsigned char* plfsr = (unsigned char*)&lfsr;
	uint32_t ks2 = reader_response ^ prng_successor(tag_challenge, 64);
	uint32_t ks3 = tag_response ^ prng_successor(tag_challenge, 96);

	revstate = lfsr_recovery64(ks2, ks3);
 
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, nr_enc, 1);
	lfsr_rollback_word(revstate, uid ^ tag_challenge, 0);
	crypto1_get_lfsr(revstate, &lfsr);

	return plfsr;
}

/**
 * One-log method
 * It is used to calculate the key when you have 2 pairs of reader challenge, reader response
*/
uint64_t Twolog(uint32_t uid, uint32_t chal, uint32_t rchal, uint32_t rresp, uint32_t chal2, uint32_t rchal2, uint32_t rresp2) {
	uint64_t key;

	struct Crypto1State *s = lfsr_recovery32(rresp ^ prng_successor(chal, 64), 0), *t;
	for(t = s; t->odd | t->even; ++t) {
		lfsr_rollback_word(t, 0, 0);
		lfsr_rollback_word(t, rchal, 1);
		lfsr_rollback_word(t, uid ^ chal, 0);
		crypto1_get_lfsr(t, &key);
		crypto1_word(t, uid ^ chal2, 0);
		crypto1_word(t, rchal2, 1);
		if (rresp2 == (crypto1_word(t, 0, 0) ^ prng_successor(chal2, 64))) {
			return key;
			break;
		}
	}
	
	free(s);

	return key;
}

int main (int argc, char *argv[]) {
	printf("One-log method:\n");
	// Onelog
	uint32_t uid             = 0xc108416a;
	uint32_t tag_challenge   = 0xABCD1949;
	uint32_t nr_enc          = 0x59D5920F;
	uint32_t reader_response = 0x15B9D553;
	uint32_t tag_response    = 0xA79A3FEE;
	unsigned char* plfsr = Onelog(uid, tag_challenge, nr_enc, reader_response, tag_response);
	printf("Key: %02x%02x%02x%02x%02x%02x\n",plfsr[5],plfsr[4],plfsr[3],plfsr[2],plfsr[1],plfsr[0]);

	printf("\nTwo-log method:\n");
	// Two log
	uid = 0x23A12659;
    uint32_t chal = 0x182c6685;
    uint32_t rchal = 0x3893952A;
    uint32_t rresp = 0x9613a859;
    uint32_t chal2 = 0xb3aac455;
    uint32_t rchal2 = 0xf05e18ac;
    uint32_t rresp2 = 0x2c479869;
	uint64_t key = Twolog(uid, chal, rchal, rresp, chal2, rchal2, rresp2);
	printf("Key: %llx\n", key);

	return 0;
}
