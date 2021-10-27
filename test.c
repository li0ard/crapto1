#include "crapto1.h"
#include <stdio.h>
#include <string.h>

int main (int argc, char *argv[]) {
	struct Crypto1State *revstate;
	uint64_t lfsr;
	unsigned char* plfsr = (unsigned char*)&lfsr;

	uint32_t uid                = 0xc108416a;
	uint32_t tag_challenge      = 0xABCD1949;
	uint32_t nr_enc             = 0x59D5920F;
	uint32_t reader_response    = 0x15B9D553;
	uint32_t tag_response       = 0xA79A3FEE;
	uint32_t ks2 = reader_response ^ prng_successor(tag_challenge, 64);
	uint32_t ks3 = tag_response ^ prng_successor(tag_challenge, 96);

	revstate = lfsr_recovery64(ks2, ks3);
 
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, nr_enc, 1);
	lfsr_rollback_word(revstate, uid ^ tag_challenge, 0);
	crypto1_get_lfsr(revstate, &lfsr);

	printf("Key: %02x%02x%02x%02x%02x%02x\n",plfsr[5],plfsr[4],plfsr[3],plfsr[2],plfsr[1],plfsr[0]);

	return 0;
}
