#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <sodium.h>

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

/* PHYTHON FUNCTION :
def RatchetEncrypt(state, plaintext, AD):
    state.CKs, mk = KDF_CK(state.CKs) // image section 2.2
    header = HEADER(state.DHs, state.PN, state.Ns)
    state.Ns += 1
    return header, ENCRYPT(mk, plaintext, CONCAT(AD, header))
*/


/* KDF_CK(ck): Returns a pair (32-byte chain key, 32-byte message key) as the
output of applying a KDF keyed by a 32-byte chain key ck to some constant.

 HMAC [2] with SHA-256 or SHA-512 [8] is recommended,
 using ck as the HMAC key and using separate constants as input
 (e.g. a single byte 0x01 as input to produce the message key, and a single
  byte 0x02 as input to produce the next chain key).

  https://libsodium.gitbook.io/doc/advanced/hmac-sha2

*/
int KDF_CK(unsigned char *mk[crypto_auth_hmacsha256_BYTES], unsigned char *CKs[crypto_auth_hmacsha256_KEYBYTES])
{
  printf("-- START LIBSODIUM USE2 --  \n");

  int return_hmac1 = 1;
  int return_hmac2 = 1;
  const unsigned char* in1 = (const unsigned char*)"aaaaaaaa";
  const unsigned char* in2 = (const unsigned char*)"zzzzzzzz";
  //unsigned long long inlen1 = strlen((char*)in1);
  //unsigned long long inlen2 = strlen((char*)in2);
  /*
  unsigned char hash_out1[crypto_auth_hmacsha256_BYTES];
  unsigned char hash_out2[crypto_auth_hmacsha256_BYTES];
  printf("test out1 hash before :%u\n", hash_out1);
  printf("test out2 hash before:%u\n", hash_out2);
  */
  printf("test inside before hash :%u\n", CKs);
  printf("test inside brefore hash :%u\n", mk);

  if (return_hmac1 = crypto_auth_hmacsha256(mk, in1, strlen((char*)in1), CKs) != 0) {
    printf("error in hmac-sha256\n");
  }
  if (return_hmac2 = crypto_auth_hmacsha256(CKs, in2, strlen((char*)in2), CKs) != 0) {
    printf("error in hmac-sha256\n");
  }

  printf("test inside after hash :%u\n", CKs);
  printf("test inside after hash :%u\n", mk);

  printf("-- END LIBSODIUM USE2 -- \n");

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

    https://libsodium.gitbook.io/doc/secret-key_cryptography/aead#tl-dr-which-one-should-i-use
    https://libsodium.gitbook.io/doc/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction
*/
//int ENCRYPT(unsigned char mk[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], unsigned char plaintext[MaxBuff])
int ENCRYPT(unsigned char mk[crypto_aead_xchacha20poly1305_ietf_KEYBYTES], unsigned char plaintext[MaxBuff], unsigned char *ciphertext_inter[strlen((char*)plaintext) + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char *nonce_inter[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES])
{
  printf("-- START LIBSODIUM AED USE -- \n");

  //unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  //unsigned char ciphertex_inter[strlen((char*)plaintext) + crypto_aead_xchacha20poly1305_ietf_ABYTES];
  unsigned long long ciphertext_len;


  randombytes_buf(nonce_inter, sizeof nonce_inter);
  printf("test NONCE : %u\n", nonce_inter);

  printf("*cipher inside Encrypt  : %u\n", *ciphertext_inter);
  printf("cipher inside Encrypt  : %u\n", ciphertext_inter);
  crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext_inter, &ciphertext_len, plaintext, strlen((char*)plaintext), ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, NULL, nonce_inter, mk);
  printf("*cipher inside Encrypt  : %u\n", *ciphertext_inter);
  printf("cipher inside Encrypt  : %u\n", ciphertext_inter);
  printf("DEDUCT * CHANGE \n");

  // decrypt (test for the moment):
  unsigned char decrypted[strlen((char*)plaintext)];
  unsigned long long decrypted_len;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL, ciphertext_inter, ciphertext_len, ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, nonce_inter, mk) != 0) {
    printf("error encrypting ciphertext");
  } else {
    printf("cipher decrypted  : %s\n", decrypted);
  }

  printf("-- END LIBSODIUM AED USE -- \n");

 	return 0;
}

int RatchetEncrypt(unsigned char *mk[crypto_auth_hmacsha256_BYTES], unsigned char *CKs[crypto_auth_hmacsha256_KEYBYTES], unsigned char plaintext[MaxBuff], unsigned char *ciphertext[strlen((char*)plaintext) + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char *nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES])
//int RatchetEncrypt(unsigned char CKs[crypto_auth_hmacsha256_KEYBYTES], unsigned char plaintext[MaxBuff])
{
  if (sodium_init() < 0) {
        printf("libsodium not instancied.. \n");
  }
  /*
  // test well received :
  int i;
  printf("CKs : \n");
  for(i=0; i<32; i++){
    printf("%u \t ", CKs[i]);
  }
  */
  printf("test mess RECEIVED TO ENCRYPT :%s\n", plaintext);
  printf("test mess RECEIVED CIPHERTEXT :%u\n", ciphertext);
  printf("test mess RECEIVED *CIPHERTEXT :%u\n", *ciphertext);

  printf("TEST ReturnKDF_CK : \n");
  /*
  unsigned char mk_inter[crypto_auth_hmacsha256_BYTES];
  unsigned char nonce_inter[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  unsigned char ciphertext_inter[strlen((char*)plaintext) + crypto_aead_xchacha20poly1305_ietf_ABYTES];
  */
  unsigned char CKs_inter[crypto_auth_hmacsha256_KEYBYTES];


  KDF_CK(mk, CKs);
  printf("test  returnKDF.CKs inside ratchetEncrypt : %u\n", CKs_inter);
  printf("test changed returnKDF Cks inside ratchetEncrypt : %u\n", CKs);
  printf("test changed returnKDF mk inside ratchetEncrypt : %u\n", mk);


  int safeReturn = ENCRYPT(mk, plaintext, ciphertext, nonce);

  printf("------------ for  AFTER CHANGE: \n");
  printf("test changed MY nonce inside ratchetEncrypt : %u\n", nonce);
  printf("test changed MY *ciphertext inside ratchetEncrypt : %u\n", *ciphertext);
  printf("test changed MY ciphertext inside ratchetEncrypt : %u\n", ciphertext);




  printf("TEST DECRYPT OUTSIDE FUNCTION WITH MY CIPHERTEXT: \n");
  unsigned char decrypted[strlen((char*)plaintext)];
  unsigned long long decrypted_len;
  unsigned long long ciphertext_len = strlen((char*)plaintext) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL, ciphertext, ciphertext_len, ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, nonce, mk) != 0) {
    printf("error encrypting ciphertext");
  } else {
    printf("cipher decrypted  : %s\n", decrypted);
  }


  printf("--------- END INSIDE FUNCTION ----------- \n");

	return 0;
}
