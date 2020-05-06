CC 		  = /usr/bin/gcc
CFLAGS  = -Wall -Wextra -O3 -fomit-frame-pointer -lcrypto -march=native
CFLAGS2  = -Wall -Wextra -O3 -fomit-frame-pointer -march=native -std=c99
CFLAGS3  = -Wall -Wextra -O3 -fomit-frame-pointer -march=native
CLANG   = clang -march=native -O3 -fomit-frame-pointer -fwrapv -Qunused-arguments
RM 		  = /bin/rm
CC2=gcc
CFLAGS4=-Wall -Wextra -g -fomit-frame-pointer -march=native --pedantic
CFLAGS5=-Wall -Wextra -g -fomit-frame-pointer -march=native --pedantic -std=c99


all: test/PQCgenKAT_kem \
     test/test_kex \
     test/kem \
		 randClient2 \
		 randServer2 \
		 ratchettest \

SOURCES = pack_unpack.c poly.c rng.c fips202.c verify.c cbd.c SABER_indcpa.c kem.c
HEADERS = SABER_params.h pack_unpack.h poly.h rng.h fips202.h verify.h cbd.h SABER_indcpa.h kem.h


test/test_kex: $(SOURCES) $(HEADERS) test/test_kex.c
	$(CC) $(CFLAGS3) -o $@ $(SOURCES) test/test_kex.c -lcrypto

test/PQCgenKAT_kem: $(SOURCES) $(HEADERS) test/PQCgenKAT_kem.c
	$(CC) $(CFLAGS3) -o $@ $(SOURCES) test/PQCgenKAT_kem.c -lcrypto

test/kem: $(SOURCES) $(HEADERS) test/kem.c
	$(CC) $(CFLAGS3) -o $@ $(SOURCES) test/kem.c -lcrypto

rng.o: rng.c
	$(CC) $(CFLAGS2) -c rng.c -lcrypto -o $@

fips202.o: fips202.c
	$(CLANG) -c $^ -o $@

.PHONY: clean test

test:
	./test/test_kex
	./test/PQCgenKAT_kem
	./test/kem

common.o: common.c common.h
	$(CC) $(CFLAGS4) -c -o common.o common.c

randClient2: common.c dh.c ratchetEncrypt.c ratchetDecrypt.c $(SOURCES) common.h dh.h ratchetEncrypt.h ratchetDecrypt.h $(HEADERS) randClient2.c
	$(CC) $(CFLAGS4) -o $@ common.c dh.c ratchetEncrypt.c ratchetDecrypt.c $(SOURCES) randClient2.c -lcrypto -lsodium

randServer2: common.c dh.c ratchetEncrypt.c ratchetDecrypt.c $(SOURCES) common.h dh.h ratchetEncrypt.h ratchetDecrypt.h $(HEADERS) randServer2.c
	$(CC) $(CFLAGS4) -o $@ common.c dh.c ratchetEncrypt.c ratchetDecrypt.c $(SOURCES) randServer2.c -lcrypto -lsodium

ratchettest: common.c $(SOURCES) common.h $(HEADERS) ratchettest.c
	$(CC) $(CFLAGS4) -o $@ common.c $(SOURCES) ratchettest.c -lcrypto


clean:
	-$(RM) *.o
	-$(RM) -r test/test_kex
	-$(RM) -r test/kem
	-$(RM) -r test/PQCgenKAT_kem
	rm -rf *.o randClient2 randServer2 ratchettest dh
