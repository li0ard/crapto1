#include "crypto1/crapto1.h"
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>

int main (int argc, char *argv[]) {
    struct Crypto1State *state;
	uint32_t pos, uid, nt, nr, rr, nr_diff;
	uint8_t bt, i, ks3x[8], par[8][8];
	uint64_t key_recovered;
	uint64_t par_info;
	uint64_t ks_info;
	nr = rr = 0;

    printf("crapto1 - (nonce2key mode)\n");

	if (argc < 5) {
		printf("\nusage: %s <uid> <nt> <par> <ks>\n\n",argv[0]);
		return 1;
	}
	sscanf(argv[1], "%08x", &uid);
	sscanf(argv[2], "%08x", &nt);
	sscanf(argv[3], "%016" SCNx64, &par_info);
	sscanf(argv[4], "%016" SCNx64, &ks_info);
  
	nr &= 0xffffff1f;

	for ( pos = 0; pos < 8; pos++ ) {
		ks3x[7-pos] = (ks_info >> (pos*8)) & 0x0f;
		bt = (par_info >> (pos*8)) & 0xff;

		for ( i = 0; i < 8; i++) {
			par[7-pos][i] = (bt >> i) & 0x01;
		}
	}

	for ( i = 0; i < 8; i++) {
		nr_diff = nr | i << 5;
	}
 
	state = lfsr_common_prefix(nr, rr, ks3x, par);
	lfsr_rollback_word(state, uid^nt, 0);
	crypto1_get_lfsr(state, &key_recovered);
    printf("\nKey: %012" PRIx64 "\n\n", key_recovered);
	crypto1_destroy(state);
	return 0;

}