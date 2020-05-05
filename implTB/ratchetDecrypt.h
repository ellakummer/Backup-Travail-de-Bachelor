#ifndef INDCPA_H
#define INDCPA_H

int DECRYPT(unsigned char mk[crypto_auth_hmacsha256_BYTES], unsigned long long len_plain, unsigned char ciphertext[len_plain + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES]);
#endif
