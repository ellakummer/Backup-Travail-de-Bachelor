#include "../api.h"
#include "../poly.h"
#include "../rng.h"
#include "../SABER_indcpa.h"
#include "../kem.h"
//#include "../cpucycles.c"
#include "../verify.h"
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>



int test_kem_cca()
{


  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss_a[CRYPTO_BYTES], ss_b[CRYPTO_BYTES];

  unsigned char entropy_input[48];
  unsigned char seed[48];
  unsigned char seed2[48];
  unsigned char seed3[48];

  uint64_t i;

      for (i=0; i<48; i++)
          entropy_input[i] = i;
      randombytes_init_saber(entropy_input, NULL, 256);


      randombytes_saber(seed, SABER_SEEDBYTES);
      randombytes_init_saber(seed, NULL, 256);
      shake128(seed, SABER_SEEDBYTES, seed, SABER_SEEDBYTES);
      printf("before shake : \n");
      for(i=0; i<SABER_SEEDBYTES; i++) {
		      printf("%u , ", seed[i]);
	    }

      printf("\n");
      printf("---------------- --------------- \n");

      randombytes_saber(seed2, SABER_SEEDBYTES);
      randombytes_init_saber(seed2, NULL, 256);
      printf("before shake : \n");
      for(i=0; i<SABER_SEEDBYTES; i++) {
		      printf("%u , ", seed2[i]);
	    }
      printf("\n");
      printf("---------------- --------------- \n");

      randombytes_saber(seed3, SABER_SEEDBYTES);
      randombytes_init_saber(seed3, NULL, 256);
      printf("before shake : \n");
      for(i=0; i<SABER_SEEDBYTES; i++) {
          printf("%u , ", seed3[i]);
      }
      printf("\n");
      printf("---------------- --------------- \n");


/*
      // en plus  :
      randombytes_saber(entropy_input, 48);
    	randombytes_init_saber(entropy_input, NULL, 256);

*/


	    //Generation of secret key sk and public key pk pair
      // A : and pkA becomes public
	    crypto_kem_keypair(pk, sk);
      printf("pk1 = %u\n", *pk);
      //printf("sk1 = %u\n", *sk);
      /*
      printf("---------------- PK --------------- \n");
      for(i=0; i<CRYPTO_PUBLICKEYBYTES; i++) {
		      printf("%u , ", pk[i]);
	    }
      printf("\n");
      printf("---------------- SK --------------- \n");
      for(i=0; i<CRYPTO_PUBLICKEYBYTES; i++) {
		      printf("%u, ", sk[i]);
	    }
      printf("\n");
      */

      /*
      printf(pk);
      printf("size = %d\n", sizeof(pk));
      */

	    //Key-Encapsulation call; input: pk; output: ciphertext c, shared-secret ss_a;
      // ON ENCAPSULE AVEC SA CLE PUBLIQUE
      // Encrypt : B create the shared secret (en creant ses propres pkB et surtout skB) with pkA
      // --> ENCAPS
	    crypto_kem_enc(ct, ss_a, pk);
      //printf("ss_a = %u\n", *ss_a);
      //printf("ct = %u\n", ct);

	    //Key-Decapsulation call; input: sk, c; output: shared-secret ss_b;
      // ON DE-ENCAPSULE AVEC SA CLE PRIVEE
      //  Decrypt :  A with pkB
      // --> DECAPS
	    crypto_kem_dec(ss_b, ct, sk);
      //printf("ss_b = %u\n", ss_b);



	    // Functional verification: check if ss_a == ss_b?
	    for(i=0; i<SABER_KEYBYTES; i++)
	    {
		printf("%u \t %u\n", ss_a[i], ss_b[i]);
		if(ss_a[i] != ss_b[i])
		{
			printf(" ----- ERR CCA KEM ------\n");
			break;
		}
	    }


  	return 0;
}



int main()
{

	test_kem_cca();
	return 0;
}
