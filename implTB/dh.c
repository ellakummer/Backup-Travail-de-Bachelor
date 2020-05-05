// The biggest 64bit prime
#define P 0xffffffffffffffc5ull
#define G 5

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

/* Performs the Diffie–Hellman key exchange */

/* https://gist.github.com/cloudwu/8838724 */

// calc a * b % p , avoid 64bit overflow
static inline uint64_t
mul_mod_p(uint64_t a, uint64_t b) {
	uint64_t m = 0;
	while(b) {
		if(b&1) {
			uint64_t t = P-a;
			if ( m >= t) {
				m -= t;
			} else {
				m += a;
			}
		}
		if (a >= P - a) {
			a = a * 2 - P;
		} else {
			a = a * 2;
		}
		b>>=1;
	}
	return m;
}

static inline uint64_t
pow_mod_p(uint64_t a, uint64_t b) {
	if (b==1) {
		return a;
	}
	uint64_t t = pow_mod_p(a, b>>1);
	t = mul_mod_p(t,t);
	if (b % 2) {
		t = mul_mod_p(t, a);
	}
	return t;
}

// calc a^b % p
uint64_t
powmodp(uint64_t a, uint64_t b) {
	if (a > P)
		a%=P;
	return pow_mod_p(a,b);
}

uint64_t
randomint64() {
	uint64_t a = rand();
	uint64_t b = rand();
	uint64_t c = rand();
	uint64_t d = rand();
	return a << 48 | b << 32 | c << 16 | d; // | bitwise inclusive OR, << left shift
}


uint64_t dh_computing(uint64_t a, uint64_t b){ // a, b : secret keys
	uint64_t A = powmodp(G, a); // Alice computes -> send to Bob
	uint64_t B = powmodp(G, b); // BOb computes -> send to Alice
	uint64_t secret1 = powmodp(B,a); // Alice computes
	uint64_t secret2 = powmodp(A,b); // Bob computes
	assert(secret1 == secret2);
	printf("a=%I64x b=%I64x s=%I64x\n", a,b,secret1);
	return secret1;
}
/*
int
main() {
	// test 1 :
	uint64_t a = randomint64();
	uint64_t b = randomint64();
	uint64_t testdh1 = dh_computing(a,b);
	printf("dh key derived : %I64x\n", testdh1);

	// test 2 :
	uint64_t a2 = randomint64();
	uint64_t b2 = randomint64();
	uint64_t testdh2 = dh_computing(a2,b2);
	printf("dh key derived : %I64x\n", testdh2);

	return 0;
}
*/
