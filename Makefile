build:
	gcc crypto1/crapto1.c crypto1/crapto1.h crypto1/crypto1.c mf32.c -o mf32
	gcc crypto1/crapto1.c crypto1/crapto1.h crypto1/crypto1.c mf64.c -o mf64
	gcc crypto1/crapto1.c crypto1/crapto1.h crypto1/crypto1.c n2k.c -o n2k
clean:
	rm mf32
	rm mf64
	rm n2k