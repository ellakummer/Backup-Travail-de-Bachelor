#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>

#define MaxBuff 2306

#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 6


int KDF_CKr(unsigned char mk[crypto_auth_hmacsha256_BYTES], unsigned char CKr[crypto_auth_hmacsha256_KEYBYTES])
{
  int return_hmac1 = 1;
  int return_hmac2 = 1;
  const unsigned char* in1 = (const unsigned char*)"aaaaaaaa";
  const unsigned char* in2 = (const unsigned char*)"zzzzzzzz";

  if ((return_hmac1 = crypto_auth_hmacsha256(mk, in1, strlen((char*)in1), CKr)) != 0) {
    printf("error in hmac-sha256\n");
  }
  if ((return_hmac2 = crypto_auth_hmacsha256(CKr, in2, strlen((char*)in2), CKr)) != 0) {
    printf("error in hmac-sha256\n");
  }

 	return 0;
}

int DECRYPT(unsigned char mk[crypto_auth_hmacsha256_BYTES], unsigned long long length_plaintext, unsigned char ciphertext[length_plaintext + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES])
{

  unsigned long long ciphertext_len = length_plaintext + crypto_aead_xchacha20poly1305_ietf_ABYTES;

  unsigned char decrypted[length_plaintext];
  unsigned char decrypted2[length_plaintext];
  memcpy(decrypted, "", length_plaintext);
  unsigned long long decrypted_len;
  //printf("decrypted before   : %s\n", decrypted);

  if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL, ciphertext, ciphertext_len, ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, nonce, mk) != 0) {
    printf("error decrypting ciphertext \n");
  } else {
    int i = 0;
    while (decrypted[i] != '\0') {
      decrypted2[i] = decrypted[i];
      i += 1;
    }
    //printf("length text decrypted  : %d\n", decrypted_len);
    printf("Cipher decrypted  : %s\n", decrypted2);
  }
 	return 0;
}


int ratchetDecrypt(unsigned long long length_plaintext, unsigned char ciphertext[length_plaintext + crypto_aead_xchacha20poly1305_ietf_ABYTES], unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES], unsigned char CKr[crypto_auth_hmacsha256_KEYBYTES], int *state_Ns)
{

  if (sodium_init() < 0) {
        printf("libsodium not instancied.. \n");
  }

  unsigned char mk[crypto_auth_hmacsha256_BYTES];
  KDF_CKr(mk, CKr);

  DECRYPT(mk, length_plaintext, ciphertext, nonce);

  *state_Ns += 1;

  return 0;
}
