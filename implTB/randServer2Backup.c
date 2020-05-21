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
/*
#define MaxConnectionsAttentes 256
#define MaxALire 1024
#define MaxChemin 1024
#define TBuffer 2048
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

  unsigned char entropy_input[48];

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



/* lecture et écriture à partir du socket client (read/write) */
void exchange( int ClientSocket, const char *chemin) {

  printf("TEST SEND TO CLIENT START \n");


  // il va falloir réceptionner ( <-> lire) le nombre de bytes demandés
  int ask;
  int s = 0 ; // nombre de bytes déjà envoyés depuis buffer actuel
  ssize_t n=0; // nombres de bytes demandés par le client

  // ----- ADD FOR EXCHANGE KEY
  /*
  printf("TEST : INSIDE echange \n");

  uint8_t pk_e[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk_e[CRYPTO_SECRETKEYBYTES];

  uint8_t ct_e[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss_a_e[CRYPTO_BYTES], ss_b_e[CRYPTO_BYTES];

  unsigned char entropy_input_e[48];

  uint64_t i_e;
  */
  printf("KEX LENGTH TESTS FOR SABER : \n");
  printf("The integer CRYPTO_PUBLICKEYBYTES is: %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("The integer CRYPTO_SECRETKEYBYTES is: %d\n", CRYPTO_SECRETKEYBYTES);
  printf("The integer CRYPTO_CIPHERTEXTBYTES is: %d\n", CRYPTO_CIPHERTEXTBYTES);
  printf("The integer CRYPTO_BYTES is: %d\n", CRYPTO_BYTES);


  /*
  lect = read(ClientSocket, &n ,MaxALire ); // lecture = réception du nombre de bytes
  // ----------- TEST ------------------
  //printf("%d\n", n);
  //printf("%d\n", lect);
  */




  printf("---------------- KEY AGREEMENT PROTOCOL : SABER -----------------\n");

  uint8_t pk_server[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk_server[CRYPTO_SECRETKEYBYTES];

  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t rootKey[CRYPTO_BYTES], ss_b_client[CRYPTO_BYTES];

  unsigned char entropy_input[48];

  uint64_t i;

  // test 0
  for(i=0; i<SABER_KEYBYTES; i++){
    printf("%u \t %u\n", rootKey[i], ss_b_client[i]);
    if(rootKey[i] != ss_b_client[i]) {
      printf(" ----- ERR CCA KEM ------\n");
      break;
    }
  }

  /*
  printf("TEST KEM SABER START \n");
  test_kem_cca();
  printf("TEST KEM SABER END \n");
  */

  printf("TEST KEM SABER START \n");
/*
  for (i=0; i<48; i++) {
    entropy_input[i] = i;
  }

  randombytes_init(entropy_input, NULL, 256);

  unsigned char seed[48];
  randombytes(seed, 48);
  randombytes_init(seed, NULL, 256);
*/
  //Generation of secret key sk and public key pk pair
  crypto_kem_keypair(pk_server, sk_server);
  printf("check size pk = %ld\n ", sizeof(pk_server));

  printf("TEST ENVOI PK, PRAY \n");

  // ---------- SEND PK SABER
  printf("MAINTENANT LES CHOSES SERIEUSES : LA CLE (J'AI PEUR) \n");
  send(ClientSocket, &pk_server, sizeof(pk_server), NULL);
  printf("ichallah ce print se voit, ça veut dire que ça passe au serveur \n");

  // RECEIVE ENCAPS
  printf("SERVER WAITS UNTIL CLIENT ENCODE MESSAGE \n ");
  printf("receive the encrypted encaps ... \n");

  printf("receive ct, ");
  //int read_client_ct;
  n = recv(ClientSocket, &ct ,MaxBuff, NULL);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }

  printf("send confirmation well received c_t \n");
  unsigned char discussion[MaxBuff] = "okreceivedct";
  //printf("%s \n", discussion);
  send(ClientSocket, &discussion, sizeof(discussion), NULL);

  printf("receive ss_a, ");
  //int read_client_ssb;
  n = recv(ClientSocket, &ss_b_client ,MaxBuff, NULL);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }

  printf("send confirmation well received ssa  \n");
  unsigned char discussion2[MaxBuff] = "okreceivedssa";
  //printf("%s \n", discussion2);
  send(ClientSocket, &discussion2, sizeof(discussion2), NULL);

  printf("TEST WELL RECEIVED SSB : ");
  for(i=0; i<SABER_KEYBYTES; i++){
    printf("%u \t %u\n", rootKey[i], ss_b_client[i]);
    if(rootKey[i] != ss_b_client[i]) {
      printf(" ----- ERR CCA KEM ------\n");
      break;
    }
  }

  // DECAPS
  printf("SERVER DECRYPT : \n");
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

  printf("------------------------------ \n");
  printf("OUR SHARED SECRET (ss_a, ss_b) IS OUR ROOTKEY \n");

  printf("---------------- DOUBLE RATCHET : SABER -----------------\n");

  uint8_t ss_a_server[CRYPTO_BYTES];
  // generate new key pair : key pair update
  crypto_kem_keypair(pk_server, sk_server);

  printf( "test public key server[0] : %d\n", pk_server[0]);
  send(ClientSocket, &pk_server, sizeof(pk_server), NULL);

  printf("receive c \n");
  n = recv(ClientSocket, &ct ,MaxBuff, NULL);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }
  printf( "test ct 0 : %d\n", ct[0]);

  crypto_kem_dec(ss_a_server, ct, sk_server);
  printf( "test ss 0 : %d\n", rootKey[0]);
  printf( "test ss2 0 : %d\n", ss_a_server[0]);

  // SYMMETRIC-KEY RATCHET

  uint8_t CKr[CRYPTO_BYTES];
  printf("Ckr BEFORE KDF  : %u\n", *CKr);

  KDF_RK(rootKey, CKr, ss_a_server);
  // ROOTKEY (ss_a_client2) IS MODIFIED
  printf("SSA AFTER KDF : %u \n", rootKey[0]);
  // CK IS MODIFIED
  printf("CKr AFTER KDF: %u\n", *CKr);
  // NOT ss_a_client
  printf("SSA2 AFTER KDF : %u \n", ss_a_server[0]);



  printf("-------------------------------------------------------------\n");
  printf("DEBUT TEST RATCHET ENCRYPT \n");
  printf("------------------------------------------------------------- \n");
  printf("----------- ECHANGE ENCRYPTE 1 ------------------- \n");

  printf("tests LENGTHS (check same size : perfect): \n");
  printf("libsodium : crypto_auth_hmacsha256_BYTES for kdf: %d\n", crypto_auth_hmacsha256_BYTES);
  printf("libsodium : crypto_auth_hmacsha256_KEYBYTES for kdf: %d\n", crypto_auth_hmacsha256_KEYBYTES);
  printf("libsodium : crypto_aead_xchacha20poly1305_ietf_KEYBYTES for kdf: %d\n", crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  printf("saber : CRYPTO_BYTES for ss  : %d\n", CRYPTO_BYTES);
  // uint8_t VS unsigned char ok

  // KEY SEE HOW !! -> same size as SABER YES can use rootKey
  //testKDF = RatchetEncrypt(rootKey);
  unsigned char *key_CKs[crypto_auth_hmacsha256_KEYBYTES];
  unsigned char *key_CKr[crypto_auth_hmacsha256_KEYBYTES];
  crypto_auth_hmacsha256_keygen(key_CKs);
  printf("*CKs inside SERVER BEFORE:%u\n", *key_CKs);
  printf("CKs inside SERVER BREFORE:%u\n", key_CKs);
  *key_CKr = *key_CKs;
  printf("*CKr inside SERVER BEFORE:%u\n", *key_CKr);
  printf("CKr inside SERVER BREFORE:%u\n", key_CKr);

  // MESSAGE TO ENCRYPT
  //const unsigned char* mess = (const unsigned char*) "teet go y croyt";
  const unsigned char* mess = (const unsigned char*) "affiches toi stp <3";
  /*
  char mess_inter[MaxBuff];
  printf("Write the message to encrypt :  ");
  fgets(mess_inter, MaxBuff, stdin);
  const unsigned char* mess = (const unsigned char*) mess_inter;
  */


  // ENCRYTPION
  /*
  unsigned char *ciphertext[strlen((char*)mess) + crypto_aead_xchacha20poly1305_ietf_ABYTES];
  unsigned char *mk[crypto_auth_hmacsha256_BYTES];
  unsigned char *nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  */
  int state_Ns = 0;
  int safeReturn = 0;
  unsigned char ciphertext_send[strlen((char*)mess) + crypto_aead_xchacha20poly1305_ietf_ABYTES];
  unsigned char nonce_send[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  printf("*cipher inside SERVER BEFORE:%u\n", *ciphertext_send);
  printf("cipher inside SERVER BEFORE:%u\n", ciphertext_send);
  printf("------- \n");

  printf("SSA BEFORE ENCRYPT : %u \n", rootKey[1]);
  printf("STATE_NS before encrypt : %d\n", state_Ns);
  safeReturn = RatchetEncrypt(rootKey, mess, ciphertext_send, nonce_send, &state_Ns);
  printf("STATE_NS after encrypt : %d\n", state_Ns);
  printf("SSA AFTER ENCRYPT : %u \n", rootKey[1]);

  printf("---- \n");
  printf("*CKs inside SERVER AFTER:%u\n", *key_CKs);
  printf("CKs inside SERVER AFTER:%u\n", key_CKs);
  printf("*CKr inside SERVER AFTER:%u\n", *key_CKr);
  printf("CKr inside SERVER AFTER:%u\n", key_CKr);
  printf("*cipher inside SERVER AFTER:%u\n", *ciphertext_send);
  printf("cipher inside SERVER  AFTER: %u\n", ciphertext_send);
  printf("nonce inside SERVER AFTER: %u\n", nonce_send);
  //printf("*nonce inside SERVER AFTER: %u\n", *nonce);

  // DECRYPTION
  unsigned long long len_plain = strlen((char*)mess);
  printf("Very Large Message : %lld \n", len_plain );

  // LE CLIENT A BESOIN DE : mk, len_plain, ciphertext, nonce

  unsigned char plaintext_length[1] = {len_plain};
  send(ClientSocket,&plaintext_length,sizeof(plaintext_length), NULL);

  printf("ciphertext inside SERVER AFTER: %u\n", ciphertext_send);
  printf("*ciphertext inside SERVER AFTER: %u\n", *ciphertext_send);
  send(ClientSocket, ciphertext_send, len_plain + crypto_aead_xchacha20poly1305_ietf_ABYTES, NULL);

  printf("nonce inside SERVER AFTER: %u\n", nonce_send);
  printf("*nonce inside SERVER AFTER: %u\n", *nonce_send);
  send(ClientSocket, nonce_send,crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, NULL);


  printf("------------------------------ \n");
  printf("----------- ECHANGE ENCRYPTE 2 ------------------- \n");

  char *plaintext_length_recv;
  plaintext_length_recv = (char*) malloc( 1 );
  if (recv( ClientSocket, plaintext_length_recv, 1, NULL) >= 0){
    printf( "Received: " );
    printf("%d\n", plaintext_length_recv[0] & 0xff );
  } else {
    printf("soucis in receiving plaintext_length \n");
  }
  unsigned long long length_plaintext_recv = plaintext_length_recv[0];
  unsigned char *ciphertext_recv[length_plaintext_recv + crypto_aead_xchacha20poly1305_ietf_ABYTES];
  unsigned char *nonce_recv[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  if (recv( ClientSocket, ciphertext_recv, length_plaintext_recv + crypto_aead_xchacha20poly1305_ietf_ABYTES, NULL) >= 0) {
    printf("ciphertext inside CLIENT: %u\n", ciphertext_recv);
  }  else {
    printf("soucis in receiving ciphertext \n");
  }
  if (recv( ClientSocket, nonce_recv, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, NULL) >= 0) {
    printf("nonce inside CLIENT: %u\n", nonce_recv);
  }  else {
    printf("soucis in receiving nonce \n");
  }

  printf("SSA BEFORE DECRYPT : %u \n", rootKey[1]);
  int safeReturn2 = ratchetDecrypt(length_plaintext_recv, ciphertext_recv, nonce_recv, rootKey, &state_Ns);
  printf("STATE_NS after decrypt : %d\n", state_Ns);
  printf("SSA AFTER DECRYPT : %u \n", rootKey[1]);



  printf("---------------------------------------\n");

  printf("DEBUT TEST DISCUSION \n");
  n = -1;
  //fcntl(0, F_SETFL, O_NONBLOCK);
  while(1) {

    /*
    char discussionTest[MaxBuff];
    printf("TEST BUFFER VIDE \n");
    printf("%s \n", discussionTest);
    if ((discussionTest[0] == '\0')) {
      printf("OK VIDE \n");
    } else {
      printf("non est pas vide \n");
    }
    */
/*
    // IF WANT TO RECEIVE
    char *dataMess;
    dataMess = (char*) malloc( MaxBuff );
    if (recv( ClientSocket, dataMess, MaxBuff, NULL) >= 0) {
      printf( "Received: " );
      printf("%s \n", dataMess);
      n = -1;
    }

    // IF WANT TO SEND
    char discussion[MaxBuff];
    printf("Entrez le message  :  ");
    fgets(discussion, MaxBuff, stdin);
    if(discussion[0] != '\0') {
      send(ClientSocket,&discussion,sizeof(discussion), NULL);
      discussion[0] = '\0';
    }
*/

    // SEND - RECEIVE -SEND - RECEIVE - ...

    // MESSAGE RECU :
    //ssize_t numberReceivedMess;
    char *dataMess; //Buffer de reception
    dataMess = (char*) malloc( MaxBuff );
    n = recv( ClientSocket, dataMess, MaxBuff, NULL); // ICI CHANGE !! 12
    if( n  < 0 ) {
      die( "Problem encountered Cannot receive message" );
    }
    printf( "Received: " );
    printf("%s \n", dataMess);

    // MESSAGE ENVOYE
    char discussion[MaxBuff];
    printf("Entrez le message  :  ");
    fgets(discussion, MaxBuff, stdin);
    send(ClientSocket,&discussion,sizeof(discussion), NULL);

  }

  //fclose(fp);
}



/* accepter une connexion et obtenir un socket client */

void DebutEchange(int ServeurSocket, const char *chemin) { // a besoin d'une socket et d'une adresse
  while(1) {
  	struct sockaddr_in clientAdress; // structure IPV4 continent 3 champs : la famille, le port, l'adresse internte
  	unsigned int clientLength = sizeof(clientAdress);
  	int clientSocket ;
	printf("Waiting for connections\n");

  // ------------ SABER ------------
  /*
  uint8_t pk_start[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk_start[CRYPTO_SECRETKEYBYTES];

  uint8_t ct_start[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss_a_start[CRYPTO_BYTES], ss_b_start[CRYPTO_BYTES];

  unsigned char entropy_input_start[48];

  uint64_t i_start;

  printf("TEST KEM SABER START \n");
  test_kem_cca();
  printf("TEST KEM SABER END \n");

  printf("TEST2 KEM SABER START \n");
  crypto_kem_keypair(pk_start, sk_start);
  printf("TEST2 KEM SABER END \n");
  */
  // ------------ SABER ------------

	clientSocket = accept(ServeurSocket, (struct sockaddr *) &clientAdress, &clientLength);
	if (clientSocket < 0) {
		die("Failed to accept client connection");
	}

  printf("TEST CONNEXION ACCEPTED \n");
// lecture, écriture à partir du socket client :
	printf("Client connected : %s\n", inet_ntoa(clientAdress.sin_addr)); // .sin_addr : on prend l'adresse ip en big endian de la structure adresse ---- inet_ntoa : converti l'adresse IPv4 en forme binaire
  printf("TEST : CLIENT CONNECTED \n");
  exchange(clientSocket, chemin);
  }
}




int main(int argc, char **argv) {
  int ServeurSocket;
  char* chemin;
  int port;

  if (argc != 2) {
  	exit(EXIT_FAILURE);
  }

  printf("---------------------------------------\n");
  printf("TEST LIBSODIUM \n");
  if (sodium_init() < 0) {
        printf("libsodium not instancied.. \n");
  } else {
    printf("libsodium check ok \n");
  }
  printf("---------------------------------------\n");


  port = atoi(argv[1]); // converti un sting en entier (int)

  // creer le socket
  ServeurSocket = makeSocket(port);

  printf("Server running on port %d at dir '%s'\n", port, chemin);
  //printf("Server running on port %d", port);

  /*
  printf("The integer CRYPTO_PUBLICKEYBYTES is: %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("The integer CRYPTO_SECRETKEYBYTES is: %d\n", CRYPTO_SECRETKEYBYTES);
  printf("The integer CRYPTO_CIPHERTEXTBYTES is: %d\n", CRYPTO_CIPHERTEXTBYTES);
  printf("The integer CRYPTO_BYTES is: %d\n", CRYPTO_BYTES);
  */

  /*
  uint8_t pk[CRYPTO_PUBLICKEYBYTES];
  //uint8_t testSK[1529];
  //uint8_t sk_2[CRYPTO_SECRETKEYBYTES];

  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];

  uint8_t ct1[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ct2[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ct3[CRYPTO_CIPHERTEXTBYTES];

  uint8_t ss_a[CRYPTO_BYTES], ss_b[CRYPTO_BYTES];
  unsigned char entropy_input[48];
  uint64_t i_e;
  */
  /*
  randombytes_init(entropy_input, NULL, 256);
  */

  //Generation of secret key sk and public key pk pair
  // A : and pkA becomes public
  //crypto_kem_keypair(pk, sk);

  // on va s'occuper de l'échange ( voir les fonctions)
  DebutEchange(ServeurSocket,chemin);


  close(ServeurSocket);






  return 0;
}
