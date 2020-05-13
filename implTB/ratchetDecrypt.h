#ifndef INDCPA_H
#define INDCPA_H

int KDF_CKr(unsigned char *mk[crypto_auth_hmacsha256_BYTES], unsigned char *CKr[crypto_auth_hmacsha256_KEYBYTES]);
int KDF_RK(unsigned char *RK[crypto_auth_hmacsha256_BYTES], unsigned char *CKr[crypto_auth_hmacsha256_KEYBYTES]);
int DECRYPT(unsigned char mk[crypto_auth_hmacsha256_BYTES], unsigned long long len_plain, unsigned char ciphertext[len_plain + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]);
int ratchetDecrypt(unsigned long long len_plain, unsigned char ciphertext[len_plain + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], unsigned char *CKr[crypto_auth_hmacsha256_KEYBYTES], int *state_Ns);
#endif
