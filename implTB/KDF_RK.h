#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>


#ifndef INDCPA_H
#define INDCPA_H

void KDF_RK(unsigned char RK[crypto_auth_hmacsha256_BYTES], unsigned char CK[crypto_auth_hmacsha256_KEYBYTES], const unsigned char sharedkey[crypto_generichash_BYTES]);

#endif
