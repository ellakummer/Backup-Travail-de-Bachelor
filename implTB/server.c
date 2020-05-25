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
#include <inttypes.h>

#include <sodium.h>

#include "api.h"
#include "poly.h"
#include "rng.h"
#include "SABER_indcpa.h"
#include "kem.h"
#include "verify.h"
#include "cpucycles.c"

#include "ratchetEncrypt.h"
#include "ratchetDecrypt.h"
#include "KDF_RK.h"
#include "common.h"


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


// Prepare server address
void prepare_address( struct sockaddr_in *address, int port) {
  size_t addrSize = sizeof( address );
  memset(address, 0, addrSize);
  address->sin_family = AF_INET;
  address->sin_addr.s_addr = htonl(INADDR_ANY);
  address->sin_port = htons(port);
}

// Build server socket
int makeSocket( int port) {
  struct sockaddr_in address;
  int sock = socket(PF_INET, SOCK_STREAM, 0);
  if( sock < 0 ) {
    die("Failed to create socket");
  }
  prepare_address( &address, port );

  // bind socket to adress
  if (bind(sock, (struct sockaddr *) &address, sizeof(address)) < 0) {
  	die("Failed to bind the server socket");
  }

  // listening and waiting for rhe start of a new connection :
  if(listen(sock, MaxConnectionsAttentes) < 0) {
  	die("Failed to listen on server socket");
  }

  return sock;
}



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
  uint64_t CLOCK1=cpucycles();

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
  n = recv(ClientSocket, &ct ,MaxBuff, 0);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }

  unsigned char discussion[MaxBuff] = "okreceivedct";
  send(ClientSocket, &discussion, sizeof(discussion), 0);

  n = recv(ClientSocket, &ss_b_client ,MaxBuff, 0);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }
  unsigned char discussion2[MaxBuff] = "okreceivedssa";
  send(ClientSocket, &discussion2, sizeof(discussion2), 0);

  // decapsulation
  printf("after decryption, verify both sides have same shared key : \n");
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
  uint64_t CLOCK2=cpucycles();
  uint64_t CLOCK_kem=CLOCK2-CLOCK1;
  double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  printf("time computation KEM : %f [s] \n", time_spent);
  printf("-> our shared secret (ss_a, ss_b) becomes our rootkey \n");
  printf("\n");
  printf("time computation KEM : %f [s] \n", time_spent);
  printf("cpu cycles computation KEM : %" PRIu64 "\n", CLOCK_kem);
  printf("\n");
  printf("---------------- DOUBLE RATCHET STEP W/ SABER -------------------\n");

  begin = clock();
  CLOCK1=cpucycles();

  uint8_t ss_a_server[CRYPTO_BYTES];

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
  CLOCK2=cpucycles();
  time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
  uint64_t CLOCK_double_ratchet=CLOCK2-CLOCK1;
  printf("time computation double ratchet step : %f [s] \n", time_spent);
  printf("cpu cycles double ratchet : %" PRIu64 "\n", CLOCK_double_ratchet);

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
      CLOCK1=cpucycles();

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
      // ss_a_client NOT MODIFIED
      printf("shared secret after KDF : %u \n", ss_a_server[1]);

      counter = 0;

      end = clock();
      CLOCK2=cpucycles();
      double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
      uint64_t CLOCK_update=CLOCK2-CLOCK1;
      printf("\n");
      printf("time computation KEM : %f [s] \n", time_spent);
      printf("cpu cycles updating keys : %" PRIu64 "\n", CLOCK_update);
      printf("\n");

      printf("--------------------- END UPDATE KEYS ----------------------- \n");
      printf("\n");
    }

    char mess_inter[MaxBuff] = "";
    printf("Write the message to encrypt :  ");
    fgets(mess_inter, MaxBuff, stdin);
    const unsigned char* mess = (const unsigned char*) mess_inter;

    unsigned char ciphertext_send[strlen((char*)mess) + crypto_aead_xchacha20poly1305_ietf_ABYTES];
    unsigned char nonce_send[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];

    begin = clock();
    CLOCK1=cpucycles();
    n = RatchetEncrypt(CK, mess, ciphertext_send, nonce_send, &state_Ns);
    counter += 1;

    // DECRYPTION
    unsigned long long len_plain = strlen((char*)mess);

    unsigned char plaintext_length[1] = {len_plain};
    send(ClientSocket,&plaintext_length,sizeof(plaintext_length), 0);
    send(ClientSocket, ciphertext_send, len_plain + crypto_aead_xchacha20poly1305_ietf_ABYTES, 0);
    send(ClientSocket, nonce_send,crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, 0);
    end = clock();
    CLOCK2=cpucycles();
    time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
    uint64_t CLOCK_encrypt=CLOCK2-CLOCK1;
    printf("time computation server side encrypt : %f [s] \n", time_spent);
    printf("cpu cycles encryption : %" PRIu64 "\n", CLOCK_encrypt);


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



// accepts connection and obtain client's socket

void StartExchange(int ServeurSocket) {
  while(1) {
  	struct sockaddr_in clientAdress; // IPV4 structure
  	unsigned int clientLength = sizeof(clientAdress);
  	int clientSocket ;
	printf("Waiting for connections\n");

	clientSocket = accept(ServeurSocket, (struct sockaddr *) &clientAdress, &clientLength);
	if (clientSocket < 0) {
		die("Failed to accept client connection");
	}

  printf("connexion accepted \n");
	printf("Client connected : %s\n", inet_ntoa(clientAdress.sin_addr)); // .sin_addr : on prend l'adresse ip en big endian de la structure adresse ---- inet_ntoa : converti l'adresse IPv4 en forme binaire
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

  printf("Server running on port %d\n", port);

  StartExchange(ServeurSocket);


  close(ServeurSocket);






  return 0;
}
