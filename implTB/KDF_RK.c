#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <sodium.h>


int KDF_RK(unsigned char *RK[crypto_auth_hmacsha256_BYTES], unsigned char *CK[crypto_auth_hmacsha256_KEYBYTES], const unsigned char sharedkey[crypto_generichash_BYTES])
{
  printf("-- START KDF_RK --  \n");
  // THESE CONSTANT CHANGE : ARGUMENT : DH(state.DHs, state.DHr))
  int return_hmac1 = 1;
  int return_hmac2 = 1;
  //const unsigned char* in1 = (const unsigned char*)"aaaaaaaa";
  //const unsigned char* in2 = (const unsigned char*)"zzzzzzzz";

  if (return_hmac1 = crypto_auth_hmacsha256(CK, sharedkey, strlen((char*)sharedkey), RK) != 0) {
    printf("error in hmac-sha256\n");
  }
  if (return_hmac2 = crypto_auth_hmacsha256(RK, sharedkey, strlen((char*)sharedkey), RK) != 0) {
    printf("error in hmac-sha256\n");
  }

 	return 0;
}
