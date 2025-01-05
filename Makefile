CC = gcc
CRAPTO1 = crypto1/crapto1.c crypto1/crapto1.h crypto1/crypto1.c

build:
	$(CC) $(CRAPTO1) mf32.c -o mf32
	$(CC) $(CRAPTO1) mf64.c -o mf64
	$(CC) $(CRAPTO1) n2k.c -o n2k
clean:
	rm mf32 mf64 n2k