#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <sodium.h>

#define MaxBuff 2306

#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 6


/*
KDF_RK(rk, dh_out):
This function is recommended to be implemented using HKDF [3]
with SHA-256 or SHA-512 [8], using rk as HKDF salt, dh_out as HKDF input key material,
and an application-specific byte sequence as HKDF info.
The info value should be chosen to be distinct from other uses of HKDF in the application.
*/

/*
https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_kdf_hkdf_sha512.h
https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_kdf_hkdf_sha256.h
*/

//DECRYPT(mk, ciphertext, CONCAT(AD, header))
// https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction

int DECRYPT(unsigned char mk[crypto_auth_hmacsha256_BYTES], unsigned long long len_plain, unsigned char ciphertext[len_plain + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES])
{
  printf("cipher inside Decrypt  : %u\n", ciphertext);
  printf("nonce inside Decrypt : %u\n", nonce);
  printf("mk inside Decrypt : %u\n", mk);
  printf("*cipher inside Decrypt  : %u\n", *ciphertext);
  printf("*nonce inside Decrypt : %u\n", *nonce);
  printf("*mk inside Decrypt : %u\n", *mk);

  unsigned long long ciphertext_len = len_plain + crypto_aead_xchacha20poly1305_ietf_ABYTES;
  // decrypt (test for the moment):
  printf("Very Large Message : %lld \n", len_plain );
  unsigned char decrypted[len_plain];
  unsigned long long decrypted_len;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL, ciphertext, ciphertext_len, ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, nonce, mk) != 0) {
    printf("error decrypting ciphertext \n");
  } else {
    printf("cipher decrypted  : %s\n", decrypted);
  }

 	return 0;
}
