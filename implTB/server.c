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

#include <sodium.h>

#include "common.h"

#include "api.h"
#include "poly.h"
#include "rng.h"
#include "SABER_indcpa.h"
#include "kem.h"
#include "verify.h"

#include "ratchetEncrypt.h"
#include "ratchetDecrypt.h"
#include "KDF_RK.h"


/*
#include "cpucycles.c"
*/

#define MaxConnectionsAttentes 2306
#define MaxBuff 2306
#define MaxChemin 2306
#define TBuffer 2306
#define TBuffer2 100

#define ADDITIONAL_DATA (const unsigned char *) "123456"
#define ADDITIONAL_DATA_LEN 6

int test_kem_cca()
{

  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk[CRYPTO_SECRETKEYBYTES];

  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss_a[CRYPTO_BYTES], ss_b[CRYPTO_BYTES];

  uint64_t i;

	    crypto_kem_keypair(pk, sk);

	    crypto_kem_enc(ct, ss_a, pk);

	    crypto_kem_dec(ss_b, ct, sk);

	    for(i=0; i<SABER_KEYBYTES; i++)
	    {
		printf("%u \t %u\n", ss_a[i], ss_b[i]);
		if(ss_a[i] != ss_b[i])
		{
			printf(" ----- ERR CCA KEM ------\n");
			break;
		}
	    }
  	return 0;
}


/* Prépare l'adresse du serveur */
void prepare_address( struct sockaddr_in *address, int port) {
  size_t addrSize = sizeof( address );
  memset(address, 0, addrSize); // mettre tout à 0
  address->sin_family = AF_INET; // IPv4
  address->sin_addr.s_addr = htonl(INADDR_ANY); // INADDR_ANY : pour affecter la socket à toutes les interfaces locales , htonl : obtenir adresse numérique valide
  address->sin_port = htons(port); // le port en big endian
}

/* Construit le socket serveur */
int makeSocket( int port) {
  struct sockaddr_in address; // créer la structure (contient : famille, port, adresse internet)
  int sock = socket(PF_INET, SOCK_STREAM, 0); // créer descripteur du socket  (SOCKSTREAM -> par flot, avec connection) (0 car par TCP)
  if( sock < 0 ) {
    die("Failed to create socket");
  }
  prepare_address( &address, port );

  // on va attacher le socket serveur à une adresse : BIND
  if (bind(sock, (struct sockaddr *) &address, sizeof(address)) < 0) {
  	die("Failed to bind the server socket");
  }

  // on va écouter le début d'une connection : LISTEN
  if(listen(sock, MaxConnectionsAttentes) < 0) {
  	die("Failed to listen on server socket");
  }

  return sock;
}



//void exchange( int ClientSocket, const char *chemin) {
void exchange( int ClientSocket) {

  ssize_t n=0;

  printf("\n");
  printf("--------------------- KEYS LENGTH FOR SABER : -------------------\n");
  printf("The integer CRYPTO_PUBLICKEYBYTES is: %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("The integer CRYPTO_SECRETKEYBYTES is: %d\n", CRYPTO_SECRETKEYBYTES);
  printf("The integer CRYPTO_CIPHERTEXTBYTES is: %d\n", CRYPTO_CIPHERTEXTBYTES);
  printf("The integer CRYPTO_BYTES is: %d\n", CRYPTO_BYTES);
  printf("\n");

  printf("---------------- KEY AGREEMENT PROTOCOL : SABER -----------------\n");
  clock_t begin = clock();

  uint8_t pk_server[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk_server[CRYPTO_SECRETKEYBYTES];

  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t rootKey[CRYPTO_BYTES], ss_b_client[CRYPTO_BYTES];

  uint64_t i;

  printf("start: verify both sides shared key is 0: \n");
  /*
  for(i=0; i<SABER_KEYBYTES; i++){
    printf("%u \t %u\n", rootKey[i], ss_b_client[i]);
    if(rootKey[i] != ss_b_client[i]) {
      printf(" ----- ERR CCA KEM ------\n");
      break;
    }
  }
  */
  printf("%u \t %u\n", rootKey[0], ss_b_client[0]);

  //Generation of secret key sk and public key pk pair
  crypto_kem_keypair(pk_server, sk_server);

  // ---------- SEND PK SABER
  printf("send public key to the client and wait \n");
  send(ClientSocket, &pk_server, sizeof(pk_server), 0);

  printf("receive from the client parameters needed to establish the shared secret \n");
  //int read_client_ct;
  n = recv(ClientSocket, &ct ,MaxBuff, 0);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }

  // send confirmation weel received ct
  unsigned char discussion[MaxBuff] = "okreceivedct";
  //printf("%s \n", discussion);
  send(ClientSocket, &discussion, sizeof(discussion), 0);

  //int read_client_ssb;
  n = recv(ClientSocket, &ss_b_client ,MaxBuff, 0);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }
  // send confirmation well received
  unsigned char discussion2[MaxBuff] = "okreceivedssa";
  send(ClientSocket, &discussion2, sizeof(discussion2), 0);

  // DECAPS
  printf("after decryption, verify both sides have same shared key : \n");
  //Key-Decapsulation call; input: sk, c; output: shared-secret ss_b (rootKey);
  crypto_kem_dec(rootKey, ct, sk_server);

  // Functional verification: check if ss_a == ss_b?
  for(i=0; i<SABER_KEYBYTES; i++){
    printf("%u \t %u\n", rootKey[i], ss_b_client[i]);
    if(rootKey[i] != ss_b_client[i]) {
      printf(" ----- ERR CCA KEM ------\n");
      break;
    }
  }

  clock_t end = clock();
  double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  printf("time computation KEM : %f [s] \n", time_spent);
  printf("-> our shared secret (ss_a, ss_b) becomes our rootkey \n");
  printf("\n");
  printf("time computation KEM : %f [s] \n", time_spent);
  printf("\n");
  printf("---------------- DOUBLE RATCHET STEP W/ SABER -------------------\n");

  begin = clock();
  uint8_t ss_a_server[CRYPTO_BYTES];
  // generate new key pair : key pair update
  crypto_kem_keypair(pk_server, sk_server);

  send(ClientSocket, &pk_server, sizeof(pk_server), 0);

  printf("receive c \n");
  n = recv(ClientSocket, &ct ,MaxBuff, 0);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }

  crypto_kem_dec(ss_a_server, ct, sk_server);
  printf("root key before KDF : %u \n", rootKey[1]);
  printf("shared secret before KDF : %u \n", ss_a_server[1]);

  // SYMMETRIC-KEY RATCHET

  uint8_t CK[CRYPTO_BYTES] = {0};
  printf("Ckr before KDF  : %u\n", *CK);

  KDF_RK(rootKey, CK, ss_a_server);
  // ROOTKEY (ss_a_client2) IS MODIFIED
  printf("root key after KDF : %u \n", rootKey[1]);
  // CK IS MODIFIED
  printf("CKr after KDF: %u\n", *CK);
  // NOT ss_a_client
  printf("shared secret after KDF : %u \n", ss_a_server[1]);
  printf("\n");

  end = clock();
  time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  printf("time computation double ratchet step : %f [s] \n", time_spent);

  printf("\n");
  printf("---------------------- START DISCUSSION -------------------------\n");

  int state_Ns = 0;
  n = -1;
  int counter = 0;
  while(1) {

    if (counter == 4) {
      // updates key :
      printf("--------- UPDATE KEYS IN MIDDLE OF THE DISCUSSION ---------- \n");

      begin = clock();

      crypto_kem_keypair(pk_server, sk_server);

      send(ClientSocket, &pk_server, sizeof(pk_server), 0);

      printf("receive c \n");
      n = recv(ClientSocket, &ct ,MaxBuff, 0);
      if( n  < 0 ) {
        die( "Problem encountered Cannot receive message" );
      }

      crypto_kem_dec(ss_a_server, ct, sk_server);
      printf("root key before KDF : %u \n", rootKey[1]);
      printf("shared secret before KDF : %u \n", ss_a_server[1]);

      // SYMMETRIC-KEY RATCHET
      //uint8_t CK[CRYPTO_BYTES] = {0};
      printf("Ckr before KDF  : %u\n", *CK);

      KDF_RK(rootKey, CK, ss_a_server);
      // ROOTKEY (ss_a_client2) IS MODIFIED
      printf("root key after KDF : %u \n", rootKey[1]);
      // CK IS MODIFIED
      printf("CKr after KDF: %u\n", *CK);
      // NOT ss_a_client
      printf("shared secret after KDF : %u \n", ss_a_server[1]);

      counter = 0;

      end = clock();
      double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
      printf("\n");
      printf("time computation KEM : %f [s] \n", time_spent);
      printf("\n");
      printf("--------------------- END UPDATE KEYS ----------------------- \n");
      printf("\n");
    }

    char mess_inter[MaxBuff] = "";
    printf("Write the message to encrypt :  ");
    fgets(mess_inter, MaxBuff, stdin);
    const unsigned char* mess = (const unsigned char*) mess_inter;
    //printf("message to encrypt : %s\n", mess);

    unsigned char ciphertext_send[strlen((char*)mess) + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned char nonce_send[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    begin = clock();
    n = RatchetEncrypt(CK, mess, ciphertext_send, nonce_send, &state_Ns);
    counter += 1;

    // DECRYPTION
    unsigned long long len_plain = strlen((char*)mess);

    // CLIENT NEEDS: mk, len_plain, ciphertext, nonce
    unsigned char plaintext_length[1] = {len_plain};
    send(ClientSocket,&plaintext_length,sizeof(plaintext_length), 0);
    send(ClientSocket, ciphertext_send, len_plain + crypto_aead_xchacha20poly1305_ietf_ABYTES, 0);
    send(ClientSocket, nonce_send,crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 0);
    end = clock();
    time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    printf("time computation server side encrypt : %f [s] \n", time_spent);


    // RECEIVE :

    char *plaintext_length_recv;
    plaintext_length_recv = (char*) malloc( 1 );
    if (recv( ClientSocket, plaintext_length_recv, 1, 0) < 0){
      printf("soucis in receiving plaintext_length \n");
    }

    unsigned long long length_plaintext_recv = plaintext_length_recv[0];
    unsigned char *ciphertext_recv[length_plaintext_recv + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned char *nonce_recv[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    if (recv( ClientSocket, ciphertext_recv, length_plaintext_recv + crypto_aead_xchacha20poly1305_ietf_ABYTES, 0) < 0) {
      printf("soucis in receiving ciphertext \n");
    }

    if (recv( ClientSocket, nonce_recv, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 0) < 0) {
      printf("soucis in receiving nonce \n");
    }
    n = ratchetDecrypt(length_plaintext_recv, ciphertext_recv, nonce_recv, CK, &state_Ns);
    counter += 1;

  }
}



/* accepter une connexion et obtenir un socket client */

//void StartExchange(int ServeurSocket, const char *chemin) { // a besoin d'une socket et d'une adresse
void StartExchange(int ServeurSocket) { // a besoin d'une socket et d'une adresse
  while(1) {
  	struct sockaddr_in clientAdress; // structure IPV4 continent 3 champs : la famille, le port, l'adresse internte
  	unsigned int clientLength = sizeof(clientAdress);
  	int clientSocket ;
	printf("Waiting for connections\n");

	clientSocket = accept(ServeurSocket, (struct sockaddr *) &clientAdress, &clientLength);
	if (clientSocket < 0) {
		die("Failed to accept client connection");
	}

  printf("connexion accepted \n");
// lecture, écriture à partir du socket client :
	printf("Client connected : %s\n", inet_ntoa(clientAdress.sin_addr)); // .sin_addr : on prend l'adresse ip en big endian de la structure adresse ---- inet_ntoa : converti l'adresse IPv4 en forme binaire
  //exchange(clientSocket, chemin);
  exchange(clientSocket);
  }
}




int main(int argc, char **argv) {
  int ServeurSocket;
  //char* chemin;
  int port;

  if (argc != 2) {
  	exit(EXIT_FAILURE);
  }

  if (sodium_init() < 0) {
        printf("libsodium not instancied.. \n");
  }
  printf("-----------------------------------------------------------------\n");


  port = atoi(argv[1]); // converti un sting en entier (int)

  // creer le socket
  ServeurSocket = makeSocket(port);

  //printf("Server running on port %d at dir '%s'\n", port, chemin);
  printf("Server running on port %d\n", port);

  // on va s'occuper de l'échange ( voir les fonctions)
  //StartExchange(ServeurSocket,chemin);
  StartExchange(ServeurSocket);


  close(ServeurSocket);






  return 0;
}
