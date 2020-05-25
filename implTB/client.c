#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>

#include "common.h"

#include <sodium.h>

#include "api.h"
#include "poly.h"
#include "rng.h"
#include "SABER_indcpa.h"
#include "kem.h"
#include "verify.h"

#include "ratchetEncrypt.h"
#include "ratchetDecrypt.h"
#include "KDF_RK.h"


#define MaxConnectionsAttentes 2306
#define MaxBuff 2306
#define MaxChemin 2306
#define TBuffer 2306
#define TBuffer2 100


#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 6


/* Prépare l'adresse du serveur */
void prepare_address( struct sockaddr_in *address, const char *host, int port ) {
  size_t addrSize = sizeof( address );
  memset(address, 0, addrSize);
  address->sin_family = AF_INET;
  inet_pton( AF_INET, (char*) host, &(address->sin_addr) ); // créer ip valide
  address->sin_port = htons(port); // le port en big endian
}

/* Construit le socket client */
int makeSocket( const char *host, int port ) {
  struct sockaddr_in address;
  int sock = socket(PF_INET, SOCK_STREAM, 0); // SOCKSTREAM -> par flot, avec connection
  if( sock < 0 ) {
    die("Failed to create socket");
  }
  prepare_address( &address, host, port );
  if( connect(sock, (struct sockaddr *) &address, sizeof(address)) < 0) {
    die("Failed to connect with server");
  }
  return sock;
}

int main(int argc, char *argv[]) {
  int ServerSocket;    // Socket
  char *host;  // Adresse IP du serveur
  int port;    // Port du service
  ssize_t n=0;

  // Initialisation

  if (argc != 3) {
    fprintf(stderr, "USAGE: %s <host> <port> <iterations>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  host = argv[1];
  port = atoi(argv[2]);

  /* Connection */

  ServerSocket = makeSocket( host, port ); // fonctions du dessus


  printf("---------------- KEY AGREEMENT PROTOCOL : SABER -----------------\n");
  // SET PARAMETERS
  uint8_t pk_client[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk_client[CRYPTO_SECRETKEYBYTES];

  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t rootKey[CRYPTO_BYTES];

  uint8_t server_pk[CRYPTO_PUBLICKEYBYTES];

  //int read_server_pk;
  n = recv(ServerSocket, &server_pk ,MaxBuff, 0);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }
  printf("receive public key from the server \n");

  // ------- ENCAPS

  // received pk, so create its own pair pk, sk and will use to encode
  //Key-Encapsulation call; input: pk; output: ciphertext c, shared-secret ss_a;
  crypto_kem_enc(ct, rootKey, server_pk);

  send(ServerSocket, &ct, sizeof(ct), 0);
  printf("send to the server parameters needed to establish the shared secret \n");

  // receive confirmation of ct well received
  char *dataConf;
  dataConf = (char*) malloc( MaxBuff );
  n = recv(ServerSocket, dataConf ,MaxBuff, 0);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }

  send(ServerSocket, &rootKey, sizeof(rootKey), 0);

  // receive confirmation of ss_a/rootKey well received
  char *dataConf2;
  dataConf2 = (char*) malloc( MaxBuff );
  n = recv(ServerSocket, dataConf2 ,MaxBuff, 0);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }

  printf("-> our shared secret (ss_a, ss_b) becomes our rootkey \n");
  printf("\n");
  printf("---------------- DOUBLE RATCHET STEP W/ SABER -------------------\n");

  // KEY AND SECRET GENERATION

  uint8_t ss_a_client[CRYPTO_BYTES];

  n = recv(ServerSocket, &server_pk ,MaxBuff, 0);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }

  crypto_kem_enc(ct, ss_a_client, server_pk);

  send(ServerSocket, &ct, sizeof(ct), 0);

  printf("root key before KDF : %u \n", rootKey[1]);
  printf("shared secret before KDF : %u \n", ss_a_client[1]);

  // SYMMETRIC-KEY RATCHET

  uint8_t CK[CRYPTO_BYTES] = {0};
  printf("Ckr before KDF  : %u\n", *CK);
  //printf("SSA2 BEFORE KDF : %u \n", ss_a_client[0]); // shared secret

  //printf("sharedkey_by_server BEFORE KDF  : %u\n", sharedkey_by_server);
  //printf("*sharedkey_by_server BEFORE KDF  : %u\n", *sharedkey_by_server);
  KDF_RK(rootKey, CK, ss_a_client);
  // ROOTKEY (rootKey) IS MODIFIED
  printf("root key after KDF : %u \n", rootKey[1]);
  // CK IS MODIFIED
  printf("CKr after KDF: %u\n", *CK);
  // NOT ss_a_client
  printf("shared scret after KDF : %u \n", ss_a_client[1]);
  //printf("sharedkey_by_server AFTER KDF: %u\n", sharedkey_by_server);
  //printf("*sharedkey_by_server AFTER KDF: %u\n", *sharedkey_by_server);

  printf("\n");
  printf("---------------------- START DISCUSSION -------------------------\n");
  // client starts : he initiated the connection
  int state_Ns = 0;
  n = -1;
  int counter = 0;
  while(1) {

    if (counter == 4) {
      printf("\n");
      printf("--------- UPDATE KEYS IN MIDDLE OF THE DISCUSSION ---------- \n");

      n = recv(ServerSocket, &server_pk ,MaxBuff, 0);
      if( n  < 0 ) {
        die( "Problem encountered Cannot receive message" );
      }

      crypto_kem_enc(ct, ss_a_client, server_pk);

      send(ServerSocket, &ct, sizeof(ct), 0);

      printf("root key before KDF : %u \n", rootKey[1]);
      printf("shared secret before KDF : %u \n", ss_a_client[1]);

      // SYMMETRIC-KEY RATCHET

      //uint8_t CK[CRYPTO_BYTES] = {0};
      printf("Ckr before KDF  : %u\n", *CK);

      KDF_RK(rootKey, CK, ss_a_client);
      // ROOTKEY (rootKey) IS MODIFIED
      printf("root key after KDF : %u \n", rootKey[1]);
      // CK IS MODIFIED
      printf("CKr after KDF: %u\n", *CK);
      // NOT ss_a_client
      printf("shared secret after KDF : %u \n", ss_a_client[1]);

      counter = 0;
      printf("--------------------- END UPDATE KEYS ----------------------- \n");
      printf("\n");
    }

    // RECEIVE

    clock_t begin = clock();
    char *plaintext_length_recv;
    plaintext_length_recv = (char*) malloc( 1 );
    if (recv( ServerSocket, plaintext_length_recv, 1, 0) < 0){
      printf("soucis in receiving plaintext_length \n");
    }

    unsigned long long length_plaintext_recv = plaintext_length_recv[0];

    unsigned char *ciphertext_recv[length_plaintext_recv + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned char *nonce_recv[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    if (recv( ServerSocket, ciphertext_recv, length_plaintext_recv + crypto_aead_xchacha20poly1305_ietf_ABYTES, 0) < 0) {
      printf("soucis in receiving ciphertext \n");
    }

    if (recv( ServerSocket, nonce_recv, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 0) < 0) {
      printf("soucis in receiving nonce \n");
    }

    //printf("SSA BEFORE DECRYPT : %u \n", rootKey[1]);
    //printf("STATE_NS before decrypt : %d\n", state_Ns);
    n = ratchetDecrypt(length_plaintext_recv, ciphertext_recv, nonce_recv, CK, &state_Ns);
    counter += 1;
    //printf("STATE_NS after decrypt : %d\n", state_Ns);
    //printf("SSA AFTER DECRYPT : %u \n", rootKey[1]);
    clock_t end = clock();
    double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    printf("time computation client side decrypt : %f [s] \n", time_spent);




    // SEND

    char mess_inter[MaxBuff] = "";
    printf("Write the message to encrypt :  ");
    fgets(mess_inter, MaxBuff, stdin);
    const unsigned char* mess = (const unsigned char*) mess_inter;
    //printf("message to encrypt : %s\n", mess);

    unsigned char ciphertext_send[strlen((char*)mess) + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned char nonce_send[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    //printf("SSA BEFORE ENCRYPT : %u \n", rootKey[1]);
    n = RatchetEncrypt(CK, mess, ciphertext_send, nonce_send, &state_Ns);
    counter += 1;
    //printf("STATE_NS after encrypt : %d\n", state_Ns);
    //printf("SSA AFTER ENCRYPT : %u \n", rootKey[1]);

    unsigned long long len_plain_send = strlen((char*)mess);
    //printf("L0ONGUER : %lld \n", len_plain_send );
    unsigned char plaintext_length_send[1] = {len_plain_send};
    send(ServerSocket,&plaintext_length_send,sizeof(plaintext_length_send), 0);
    send(ServerSocket, ciphertext_send, len_plain_send + crypto_aead_xchacha20poly1305_ietf_ABYTES, 0);
    send(ServerSocket, nonce_send,crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 0);

  }

  close(ServerSocket);

  exit(EXIT_SUCCESS);
}
