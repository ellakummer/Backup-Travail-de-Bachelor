#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <sodium.h>

#define MaxBuff 2306

#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 6

int KDF_CKr(unsigned char *mk[crypto_auth_hmacsha256_BYTES], unsigned char *CKr[crypto_auth_hmacsha256_KEYBYTES])
{
  int return_hmac1 = 1;
  int return_hmac2 = 1;
  const unsigned char* in1 = (const unsigned char*)"aaaaaaaa";
  const unsigned char* in2 = (const unsigned char*)"zzzzzzzz";

  if (return_hmac1 = crypto_auth_hmacsha256(mk, in1, strlen((char*)in1), CKr) != 0) {
    printf("error in hmac-sha256\n");
  }
  if (return_hmac2 = crypto_auth_hmacsha256(CKr, in2, strlen((char*)in2), CKr) != 0) {
    printf("error in hmac-sha256\n");
  }

 	return 0;
}

/*
KDF_RK(rk, dh_out):
This function is recommended to be implemented using HKDF [3]
with SHA-256 or SHA-512 [8], using rk as HKDF salt, dh_out as HKDF input key material,
and an application-specific byte sequence as HKDF info.
The info value should be chosen to be distinct from other uses of HKDF in the application.
*/

int KDF_RK(unsigned char *RK[crypto_auth_hmacsha256_BYTES], unsigned char *CKr[crypto_auth_hmacsha256_KEYBYTES])
{
  printf("-- START KDF_RK --  \n");
  // THESE CONSTANT CHANGE : ARGUMENT : DH(state.DHs, state.DHr))
  int return_hmac1 = 1;
  int return_hmac2 = 1;
  const unsigned char* in1 = (const unsigned char*)"aaaaaaaa";
  const unsigned char* in2 = (const unsigned char*)"zzzzzzzz";

  if (return_hmac1 = crypto_auth_hmacsha256(CKr, in1, strlen((char*)in1), CKr) != 0) {
    printf("error in hmac-sha256\n");
  }
  if (return_hmac2 = crypto_auth_hmacsha256(RK, in2, strlen((char*)in2), CKr) != 0) {
    printf("error in hmac-sha256\n");
  }

 	return 0;
}

/*
https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_kdf_hkdf_sha512.h
https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_kdf_hkdf_sha256.h
*/

//DECRYPT(mk, ciphertext, CONCAT(AD, header))
// https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction

int DECRYPT(unsigned char *mk[crypto_auth_hmacsha256_BYTES], unsigned long long length_plaintext, unsigned char ciphertext[length_plaintext + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES])
{
  printf("cipher inside Decrypt  : %u\n", ciphertext);
  printf("nonce inside Decrypt : %u\n", nonce);
  printf("mk inside Decrypt : %u\n", mk);
  printf("*cipher inside Decrypt  : %u\n", *ciphertext);
  printf("*nonce inside Decrypt : %u\n", *nonce);
  printf("*mk inside Decrypt : %u\n", *mk);

  unsigned long long ciphertext_len = length_plaintext + crypto_aead_xchacha20poly1305_ietf_ABYTES;
  //unsigned long long ciphertext_len = sizeof(ciphertext);

  //printf(" HERE crypto_aead_xchacha20poly1305_ietf_ABYTES LEN = %d\n", crypto_aead_xchacha20poly1305_ietf_ABYTES);
  //printf(" HERE CIPHERTEXT LEN = %d\n", ciphertext_len);
  //printf(" HERE CIPHERTEXT LEN SIZEOF = %d\n", sizeof(ciphertext));
  //length_plaintext = ciphertext_len - crypto_aead_xchacha20poly1305_ietf_ABYTES;

  // decrypt (test for the moment):
  printf("Very Large Message lenght_plaintext : %lld \n", length_plaintext );
  unsigned char decrypted[length_plaintext];
  unsigned long long decrypted_len;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL, ciphertext, ciphertext_len, ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, nonce, mk) != 0) {
    printf("error decrypting ciphertext \n");
  } else {
    printf("cipher decrypted  : %s\n", decrypted);
    printf("cipher decrypted size  : %u\n", sizeof(decrypted));
    printf("Very Large Message lenght_plaintext : %lld \n", decrypted_len );
  }

 	return 0;
}

//int ratchetDecrypt(unsigned long long len_plain, unsigned char ciphertext[len_plain + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], unsigned char *CKr[crypto_auth_hmacsha256_KEYBYTES])
//int ratchetDecrypt(unsigned char mk[crypto_auth_hmacsha256_BYTES], unsigned long long length_plaintext, unsigned char ciphertext[length_plaintext + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], unsigned char *CKr[crypto_auth_hmacsha256_KEYBYTES])
int ratchetDecrypt(unsigned long long length_plaintext, unsigned char ciphertext[length_plaintext + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], unsigned char *CKr[crypto_auth_hmacsha256_KEYBYTES])
{
  printf("!! INSIDE DECRYPT !! \n");

  if (sodium_init() < 0) {
        printf("libsodium not instancied.. \n");
  }
/*
  // PYTHON :
  state.CKr, mk = KDF_CK(state.CKr)

  def DHRatchet(state, header):
    state.PN = state.Ns
    state.Ns = 0
    state.Nr = 0
    state.DHr = header.dh
    state.RK, state.CKr = KDF_RK(state.RK, DH(state.DHs, state.DHr) : SABER)
    state.DHs = GENERATE_DH()
    state.RK, state.CKs = KDF_RK(state.RK, DH(state.DHs, state.DHr) : SABER )
*/

  unsigned char *mk[crypto_auth_hmacsha256_BYTES];
  KDF_CKr(mk, CKr);
  //printf("mk inter BEFORE DECRYPT: %u\n", mk);
  //printf("*mk inter BEFORE DECRYPT: %u\n", *mk);

  int safeReturn = DECRYPT(mk, length_plaintext, ciphertext, nonce);
  /*
  return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
  return DECRYPT(mk, ciphertext, CONCAT(AD, header))
  */

  return 0;
}
