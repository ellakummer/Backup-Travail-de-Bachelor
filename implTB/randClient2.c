#include <stdio.h>
#include<stdint.h>
#include<stdlib.h>
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

#include "common.h"

#include <sodium.h>

#include "api.h"
#include "poly.h"
#include "rng.h"
#include "SABER_indcpa.h"
#include "kem.h"
#include "verify.h"

#include "dh.h"
#include "ratchetEncrypt.h"
#include "ratchetDecrypt.h"

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
  int ServerSocket;    /* Socket */
  char *host;  /* Adresse IP du serveur */
  int port;    /* Port du service */
  size_t numBytes; /* Nombre de bytes aléatoires demandés dans tests*/
  char *data; /* Buffer de reception */
  size_t rcvd=0; /* Bytes reçus */
  ssize_t n=0;

  /* Initialisation */


  if (argc != 4) {
    fprintf(stderr, "USAGE: %s <host> <port> <numBytes>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  host = argv[1];
  port = atoi(argv[2]);
  numBytes = atoi(argv[3]);

  /* Connection */

  ServerSocket = makeSocket( host, port ); // fonctions du dessus
  // --------- TEST -----------



  printf("---------------------------------------\n");
  // SET PARAMETERS
  uint8_t pk_client[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk_client[CRYPTO_SECRETKEYBYTES];

  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss_a_client[CRYPTO_BYTES], ss_b_server[CRYPTO_BYTES];

  unsigned char entropy_input_client[48];

  printf("SABER RECEVOIR CLE \n");
  /*
  printf("on va deja test de recevoir un uint8_t \n");
  uint8_t n_u; // try change type
  int lect_u;
  lect_u = recv(sock, &n_u ,MaxALire, NULL);
  printf("le uint8_t ->  %d\n", n_u);
  printf("ok le test uint8_t fonctionne \n");
  */
  // ---------- RECEIVE PK SABER
  printf("MAINTENANT LES CHOSES SERIEUSES : LA CLE (J'AI PEUR) \n");
  uint8_t server_pk[CRYPTO_PUBLICKEYBYTES];
  //int read_server_pk;
  n = recv(ServerSocket, &server_pk ,MaxBuff, NULL);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }
  printf("ichallah ce print se voit, ça veut dire que ça passe au client \n");
  printf("Client received size pk server = %ld\n ", sizeof(server_pk));

  // ------- ENCAPS

  printf("CLIENT ENCODE SSK \n");
  // received pk, so create its own pair pk, sk and will use to encode
  //Key-Encapsulation call; input: pk; output: ciphertext c, shared-secret ss_a;
  crypto_kem_enc(ct, ss_a_client, server_pk);

  printf("after encaps send c : \n");
  send(ServerSocket, &ct, sizeof(ct), NULL);
  printf("receive confirmation from server for c_t : \n");
  //int confirmation_ct;
  char *dataConf; /* Buffer de reception */
  dataConf = (char*) malloc( MaxBuff );
  n = recv(ServerSocket, dataConf ,MaxBuff, NULL);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }
  printf("%s \n", dataConf);

  printf("after encaps send ss_a : \n");
  send(ServerSocket, &ss_a_client, sizeof(ss_a_client), NULL);
  printf("receive confirmation from server for ss_a : \n");
  //int confirmation_ct2;
  char *dataConf2;
  dataConf2 = (char*) malloc( MaxBuff );
  n = recv(ServerSocket, dataConf2 ,MaxBuff, NULL);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }
  printf("%s \n", dataConf2);

  printf("DIS MOI QUE TU PRINT STP STP STP PLEIN D'AMOUR \n");


  printf("------------------------------------- \n");
  printf("----------- ECHANGE ENCRYPT (ICI DECRYPT) ------------------- \n");
  // CLIENT NEEDS : mk, len_plain, ciphertext, nonce
  int state_Ns = 0;

  char *plaintext_length_recv;
  plaintext_length_recv = (char*) malloc( 1 );
  if (recv( ServerSocket, plaintext_length_recv, 1, NULL) >= 0){
    printf( "Received: " );
    printf("%d\n", plaintext_length_recv[0] & 0xff );
  } else {
    printf("soucis in receiving plaintext_length \n");
  }
  unsigned long long length_plaintext_recv = plaintext_length_recv[0];

  //unsigned long long length_plaintext = 11;
  unsigned char *ciphertext_recv[length_plaintext_recv + crypto_aead_xchacha20poly1305_ietf_ABYTES];
  unsigned char *nonce_recv[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

  if (recv( ServerSocket, ciphertext_recv, length_plaintext_recv + crypto_aead_xchacha20poly1305_ietf_ABYTES, NULL) >= 0) {
    printf("ciphertext inside CLIENT: %u\n", ciphertext_recv);
    printf("*ciphertext inside CLIENT: %u\n", *ciphertext_recv);
  }  else {
    printf("soucis in receiving ciphertext \n");
  }

  if (recv( ServerSocket, nonce_recv, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, NULL) >= 0) {
    printf("nonce inside CLIENT: %u\n", nonce_recv);
    //printf("*nonce inside CLIENT: %u\n", *nonce);
  }  else {
    printf("soucis in receiving nonce \n");
  }


  //int safeReturn2 = ratchetDecrypt(mk, length_plaintext, ciphertext, nonce, ss_a_client);
  printf("SSA BEFORE DECRYPT : %u \n", ss_a_client[1]);
  printf("STATE_NS before decrypt : %d\n", state_Ns);
  int safeReturn = ratchetDecrypt(length_plaintext_recv, ciphertext_recv, nonce_recv, ss_a_client, &state_Ns);
  printf("STATE_NS after decrypt : %d\n", state_Ns);
  printf("SSA AFTER DECRYPT : %u \n", ss_a_client[1]);

  printf("------------------------------ \n");
  printf("----------- ECHANGE ENCRYPTE 2 ------------------- \n");

  const unsigned char* mess = (const unsigned char*) "affiches toi stp bis";
  unsigned char ciphertext_send[strlen((char*)mess) + crypto_aead_xchacha20poly1305_ietf_ABYTES];
  unsigned char nonce_send[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  printf("SSA BEFORE ENCRYPT : %u \n", ss_a_client[1]);
  safeReturn = RatchetEncrypt(ss_a_client, mess, ciphertext_send, nonce_send, &state_Ns);
  printf("STATE_NS after encrypt : %d\n", state_Ns);
  printf("SSA AFTER ENCRYPT : %u \n", ss_a_client[1]);

  unsigned long long len_plain_send = strlen((char*)mess);
  printf("L0ONGUER : %lld \n", len_plain_send );
  unsigned char plaintext_length_send[1] = {len_plain_send};
  send(ServerSocket,&plaintext_length_send,sizeof(plaintext_length_send), NULL);
  send(ServerSocket, ciphertext_send, len_plain_send + crypto_aead_xchacha20poly1305_ietf_ABYTES, NULL);
  send(ServerSocket, nonce_send,crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, NULL);

  // TESTS REPLACE
  /*
  const unsigned char ad[5];
  sprintf(ad, "%d", state_Ns);
  printf("itoa result : %s\n", ad);

  size_t s = strlen((const char) ad);
  */
  //printf("length s = %llu\n", s);

  printf("---------------- TEST GENERATE DH KEYPAIR + DH RATCHET STEP ----------------------- \n");
  // key pair based on the Curve25519 elliptic curves
  // PAIR 1
  unsigned char ed25519_pk[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char ed25519_skpk[crypto_sign_ed25519_SECRETKEYBYTES];
  unsigned char x25519_pk[crypto_scalarmult_curve25519_BYTES];
  unsigned char x25519_sk[crypto_scalarmult_curve25519_BYTES];

  crypto_sign_ed25519_keypair(ed25519_pk, ed25519_skpk);

  crypto_sign_ed25519_pk_to_curve25519(x25519_pk, ed25519_pk);
  crypto_sign_ed25519_sk_to_curve25519(x25519_sk, ed25519_skpk);

  // PAIR 2
  unsigned char ed25519_pk2[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char ed25519_skpk2[crypto_sign_ed25519_SECRETKEYBYTES];
  unsigned char x25519_pk2[crypto_scalarmult_curve25519_BYTES];
  unsigned char x25519_sk2[crypto_scalarmult_curve25519_BYTES];

  crypto_sign_ed25519_keypair(ed25519_pk2, ed25519_skpk2);

  crypto_sign_ed25519_pk_to_curve25519(x25519_pk2, ed25519_pk2);
  crypto_sign_ed25519_sk_to_curve25519(x25519_sk2, ed25519_skpk2);

  // TESTS SIZE :
  printf("curve25519 : crypto_scalarmult_curve25519_BYTES : %d\n", crypto_scalarmult_curve25519_BYTES);
  printf("crypto_box_PUBLICKEYBYTES PK : %d\n", crypto_box_PUBLICKEYBYTES);
  printf("crypto_box_SECRETKEYBYTES SK : %d\n", crypto_box_SECRETKEYBYTES);

  // DH RATCHET STEP
  // return the output from the X25519 function 
  unsigned char scalarmult_q_by_client[crypto_scalarmult_BYTES]; //
  unsigned char scalarmult_q_by_server[crypto_scalarmult_BYTES]; // 2
  unsigned char sharedkey_by_client[crypto_generichash_BYTES];
  unsigned char sharedkey_by_server[crypto_generichash_BYTES];
  crypto_generichash_state h;

  /* The client derives a shared key from its secret key and the server's public key */
  /* shared key = h(q ‖ client_publickey ‖ server_publickey) */
  if (crypto_scalarmult(scalarmult_q_by_client, x25519_sk, x25519_pk2) != 0) {
      printf("error deriving the shared secret key using DH, client's side");
  }
  crypto_generichash_init(&h, NULL, 0U, sizeof sharedkey_by_client);
  crypto_generichash_update(&h, scalarmult_q_by_client, sizeof scalarmult_q_by_client);
  crypto_generichash_update(&h, x25519_pk, sizeof x25519_pk);
  crypto_generichash_update(&h, x25519_pk2, sizeof x25519_pk2);
  crypto_generichash_final(&h, sharedkey_by_client, sizeof sharedkey_by_client);

  /* The server derives a shared key from its secret key and the client's public key */
  /* shared key = h(q ‖ client_publickey ‖ server_publickey) */
  if (crypto_scalarmult(scalarmult_q_by_server, x25519_sk2, x25519_pk) != 0) {
      printf("error deriving the shared secret key using DH, server's side");
  }
  crypto_generichash_init(&h, NULL, 0U, sizeof sharedkey_by_server);
  crypto_generichash_update(&h, scalarmult_q_by_server, sizeof scalarmult_q_by_server);
  crypto_generichash_update(&h, x25519_pk, sizeof x25519_pk);
  crypto_generichash_update(&h, x25519_pk2, sizeof x25519_pk2);
  crypto_generichash_final(&h, sharedkey_by_server, sizeof sharedkey_by_server);

  /* sharedkey_by_client and sharedkey_by_server are identical :  */
  printf("sharedkey_by_server : %d\n", *sharedkey_by_server);
  printf("sharedkey_by_client : %d\n", *sharedkey_by_client);

  // TESTS KDF:
  uint8_t CKr[CRYPTO_BYTES];
  printf("SSA BEFORE KDF : %u \n", ss_a_client[1]); // ROOT KEY
  printf("Ckr BEFORE KDF  : %u\n", *CKr);
  printf("sharedkey_by_server BEFORE KDF  : %u\n", sharedkey_by_server);
  printf("*sharedkey_by_server BEFORE KDF  : %u\n", *sharedkey_by_server);
  KDF_RK(ss_a_client, CKr, sharedkey_by_server);
  printf("SSA AFTER KDF : %u \n", ss_a_client[1]);
  printf("CKr AFTER KDF: %u\n", *CKr);
  printf("sharedkey_by_server AFTER KDF: %u\n", sharedkey_by_server);
  printf("*sharedkey_by_server AFTER KDF: %u\n", *sharedkey_by_server);

  printf("---------------- TEST DH EXCHANGE ----------------------- \n");
  uint8_t CKr2[CRYPTO_BYTES];
  strcpy(CKr2, CKr);
  const unsigned char* messTEST = (const unsigned char*) "lalala";
  int state_NsTEST = 2;
  safeReturn = RatchetEncrypt(CKr, messTEST, ciphertext_send, nonce_send, &state_NsTEST);
  //unsigned char plaintext_length[1] = {len_plain};
  //unsigned long long length_plaintext_recvTEST = plaintext_length_recv[0];
  state_NsTEST = state_NsTEST-1;
  safeReturn = ratchetDecrypt(6, ciphertext_send, nonce_send, CKr2, &state_NsTEST);


  printf("--------------------------------------- \n");
  printf("DEBUT TEST DISCUSION \n");
  // le client commence en terme de logique : lui se connecte
  n = -1;
  //fcntl(0, F_SETFL, O_NONBLOCK);
  while(1) {
    // MESSAGE ENVOYE

    // IF WANT TO SEND
/*
    char discussion[MaxBuff];
    printf("Entrez le message  :  ");
    fgets(discussion, MaxBuff, stdin);
    if(discussion[0] != '\0') {
      send(ServerSocket,&discussion,sizeof(discussion), NULL);
      discussion[0] = '\0';
    }

    // IF RECEIVE :

    char *dataMess;
    dataMess = (char*) malloc( MaxBuff );
    if (recv( ServerSocket, dataMess, MaxBuff, NULL) >= 0) {
      printf( "Received: " );
      printf("%s \n", dataMess);
      n = -1;
    }
*/

    char discussion[MaxBuff];
    printf("Entrez le message  :  ");
    fgets(discussion, MaxBuff, stdin);
    send(ServerSocket,&discussion,sizeof(discussion), NULL);

    // MESSAGE RECU :
    char *dataMess; // Buffer de reception
    dataMess = (char*) malloc( MaxBuff );
    n = recv( ServerSocket, dataMess, MaxBuff, NULL); // ICI CHANGE !! 12
    if( n  < 0 ) {
      die( "Problem encountered Cannot receive message" );
    }
    printf( "Received: " );
    printf("%s \n", dataMess);

  }

  // ---- FIN TEST MESSAGE ------------------

  /* Libération des resources */
  //free( data );
  close(ServerSocket);

  exit(EXIT_SUCCESS);
}
