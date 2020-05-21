#ifndef INDCPA_H
#define INDCPA_H

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>

#define MaxBuff 2306

#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 6


int KDF_CKs(unsigned char mk[crypto_auth_hmacsha256_BYTES], unsigned char CKs[crypto_auth_hmacsha256_KEYBYTES]);
int ENCRYPT(unsigned char mk[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], unsigned char plaintext[MaxBuff], unsigned char ciphertext[strlen((char*)plaintext) + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]);
//int RatchetEncrypt(unsigned char *mk[crypto_auth_hmacsha256_BYTES], unsigned char *CKs[crypto_auth_hmacsha256_KEYBYTES], unsigned char plaintext[MaxBuff], unsigned char *ciphertext[strlen((char*)plaintext) + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char *nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]);
//int RatchetEncrypt(unsigned char mk[crypto_auth_hmacsha256_BYTES], unsigned char CKs[crypto_auth_hmacsha256_KEYBYTES], unsigned char plaintext[MaxBuff], unsigned char ciphertext[strlen((char*)plaintext) + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]);
int RatchetEncrypt(unsigned char CKs[crypto_auth_hmacsha256_KEYBYTES], unsigned char plaintext[MaxBuff], unsigned char ciphertext[strlen((char*)plaintext) + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], int *state_Ns);

#endif
