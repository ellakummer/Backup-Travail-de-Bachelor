#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>

#define MaxBuff 2306

#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 6


/* called to encrypt messages */

/*
 This function performs a symmetric-key ratchet step,
 then encrypts the message with the resulting message key.

 In addition to the message's plaintext it
 takes an AD byte sequence which is prepended to the header to form the
 associated data for the underlying AEAD encryption
*/


/* KDF_CK(ck): Returns a pair (32-byte chain key, 32-byte message key) as the
output of applying a KDF keyed by a 32-byte chain key ck to some constant.

 HMAC [2] with SHA-256 or SHA-512 [8] is recommended,
 using ck as the HMAC key and using separate constants as input
 (e.g. a single byte 0x01 as input to produce the message key, and a single
  byte 0x02 as input to produce the next chain key).

  https://libsodium.gitbook.io/doc/advanced/hmac-sha2

*/
int KDF_CKs(unsigned char mk[crypto_auth_hmacsha256_BYTES], unsigned char CKs[crypto_auth_hmacsha256_KEYBYTES])
{

  int return_hmac1 = 1;
  int return_hmac2 = 1;
  const unsigned char* in1 = (const unsigned char*)"aaaaaaaa";
  const unsigned char* in2 = (const unsigned char*)"zzzzzzzz";

  if ((return_hmac1 = crypto_auth_hmacsha256(mk, in1, strlen((char*)in1), CKs)) != 0) {
    printf("error in hmac-sha256\n");
  }
  if ((return_hmac2 = crypto_auth_hmacsha256(CKs, in2, strlen((char*)in2), CKs)) != 0) {
    printf("error in hmac-sha256\n");
  }

 	return 0;
}


/* ENCRYPT(mk, plaintext, associated_data):
Returns an AEAD encryption of plaintext with message key mk [5].
+ (?later)
The associated_data is authenticated but is not included in the ciphertext.
Because each message key is only used once, the AEAD nonce may handled in
several ways: fixed to a constant; derived from mk alongside an independent
AEAD encryption key; derived as an additional output from KDF_CK(); or chosen randomly and transmitted.

This function is recommended to be implemented with an AEAD encryption
scheme based on either SIV or a composition of CBC with HMAC [5], [9]:
    HKDF is used with SHA-256 or SHA-512 to generate 80 bytes of output. The HKDF salt is set to a zero-filled byte sequence equal to the hash's output length. HKDF input key material is set to mk. HKDF info is set to an application-specific byte sequence distinct from other uses of HKDF in the application.

    The HKDF output is divided into a 32-byte encryption key, a 32-byte authentication key, and a 16-byte IV.

    The plaintext is encrypted using AES-256 in CBC mode with PKCS#7 padding, using the encryption key and IV from the previous step [10], [11].

    HMAC is calculated using the authentication key and the same hash function as above [2]. The HMAC input is the associated_data prepended to the ciphertext. The HMAC output is appended to the ciphertext.

*/

int ENCRYPT(unsigned char mk[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], unsigned char plaintext[MaxBuff], unsigned char ciphertext_inter[strlen((char*)plaintext) + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES])
{

  unsigned long long ciphertext_len;

  //printf("-VOIR POURQUOI DEVOIR L'AFFICHER- *mk inside Decrypt : %u\n", *mk);
  //printf("-VOIR POURQUOI DEVOIR L'AFFICHER \n");

  randombytes_buf(nonce, sizeof nonce);

  crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext_inter, &ciphertext_len, plaintext, strlen((char*)plaintext), ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, NULL, nonce, mk);

 	return 0;
}

int RatchetEncrypt(unsigned char CKs[crypto_auth_hmacsha256_KEYBYTES], unsigned char plaintext[MaxBuff], unsigned char ciphertext[strlen((char*)plaintext) + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], int *state_Ns)
{
  if (sodium_init() < 0) {
        printf("libsodium not instancied.. \n");
  }
  unsigned char mk[crypto_auth_hmacsha256_BYTES];
  KDF_CKs(mk, CKs);

  ENCRYPT(mk, plaintext, ciphertext, nonce);

  *state_Ns +=1;

	return 0;
}
