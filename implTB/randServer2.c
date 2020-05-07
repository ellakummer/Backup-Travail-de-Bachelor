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

#include "dh.h"
#include "ratchetEncrypt.h"
#include "ratchetDecrypt.h"


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
  /*
  printf("echange, The integer CRYPTO_PUBLICKEYBYTES is: %d\n", CRYPTO_PUBLICKEYBYTES);
  printf("echange, TThe integer CRYPTO_SECRETKEYBYTES is: %d\n", CRYPTO_SECRETKEYBYTES);
  printf("echange, TThe integer CRYPTO_CIPHERTEXTBYTES is: %d\n", CRYPTO_CIPHERTEXTBYTES);
  printf("echange, TThe integer CRYPTO_BYTES is: %d\n", CRYPTO_BYTES);
  */

  /*
  lect = read(ClientSocket, &n ,MaxALire ); // lecture = réception du nombre de bytes
  // ----------- TEST ------------------
  //printf("%d\n", n);
  //printf("%d\n", lect);
  */




  printf("---------------------------------------\n");

  printf("SABER ENVOI CLE\n");

  uint8_t pk_server[CRYPTO_PUBLICKEYBYTES];
  uint8_t sk_server[CRYPTO_SECRETKEYBYTES];

  uint8_t ct[CRYPTO_CIPHERTEXTBYTES];
  uint8_t ss_a_server[CRYPTO_BYTES], ss_b_client[CRYPTO_BYTES];

  unsigned char entropy_input[48];

  uint64_t i;

  // test 0
  for(i=0; i<SABER_KEYBYTES; i++){
    printf("%u \t %u\n", ss_a_server[i], ss_b_client[i]);
    if(ss_a_server[i] != ss_b_client[i]) {
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
  /*
  printf("on va deja test d'envoyer un uint8_t \n"); // 8 bit integer type
  uint8_t num_u = 255;
  printf("le uint8_t cote server ->  %d\n", num_u);
  send(ClientSocket,&num_u,sizeof(num_u), NULL);
  printf("ok le test uint8_t fonctionne \n");
  */
  // ---------- SEND PK SABER
  printf("MAINTENANT LES CHOSES SERIEUSES : LA CLE (J'AI PEUR) \n");
  send(ClientSocket, &pk_server, sizeof(pk_server), NULL);
  printf("ichallah ce print se voit, ça veut dire que ça passe au serveur \n");

  // RECEIVE ENCAPS
  printf("SERVER WAITS UNTIL CLIENT ENCODE MESSAGE \n ");
  printf("receive the encrypted encaps ... \n");

  printf("receive c : \n");
  //int read_client_ct;
  n = recv(ClientSocket, &ct ,MaxBuff, NULL);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }
  printf("send confirmation well received c_t : \n");
  unsigned char discussion[MaxBuff] = "okreceivedct";
  printf("%s \n", discussion);
  send(ClientSocket, &discussion, sizeof(discussion), NULL);

  printf("receive ss_a : \n");
  //int read_client_ssb;
  n = recv(ClientSocket, &ss_b_client ,MaxBuff, NULL);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }
  printf("send confirmation well received ssa : \n");
  unsigned char discussion2[MaxBuff] = "okreceivedssa";
  printf("%s \n", discussion2);
  send(ClientSocket, &discussion2, sizeof(discussion2), NULL);

  printf("TEST WELL RECEIVED SSB : ");
  for(i=0; i<SABER_KEYBYTES; i++){
    printf("%u \t %u\n", ss_a_server[i], ss_b_client[i]);
    if(ss_a_server[i] != ss_b_client[i]) {
      printf(" ----- ERR CCA KEM ------\n");
      break;
    }
  }

  // DECAPS
  printf("SERVER DECRYPT : \n");
  //Key-Decapsulation call; input: sk, c; output: shared-secret ss_b (ss_a_server);
  crypto_kem_dec(ss_a_server, ct, sk_server);

  // Functional verification: check if ss_a == ss_b?
  for(i=0; i<SABER_KEYBYTES; i++){
    printf("%u \t %u\n", ss_a_server[i], ss_b_client[i]);
    if(ss_a_server[i] != ss_b_client[i]) {
      printf(" ----- ERR CCA KEM ------\n");
      break;
    }
  }

  printf("---------------------------------------\n");
  printf("DEBUT TEST DH \n");

  /*
  GENERATE_DH(): This function is recommended to generate a key pair based
  on the Curve25519 or Curve448 elliptic curves [7].

  DH(dh_pair, dh_pub): This function is recommended to return the output
  from the X25519 or X448 function as defined in [7]. There is no need to c
  heck for invalid public keys.

  https://github.com/jedisct1/libsodium/blob/master/src/libsodium/include/sodium/crypto_box_curve25519xchacha20poly1305.h

  */

  uint64_t a = randomint64();
	uint64_t b = randomint64();
  uint64_t testdh_64 = dh_computing(a,b);
	printf("uint64_t dh key derived : %I64x\n", testdh_64);

  uint32_t testdh_32 = (uint32_t) testdh_64;
  printf("uint32_t dh key derived : %I32x\n", testdh_32);

  // HOW WE GONNA DO IT : (ok later)
  // receive public_key_client (b)
  // create a our private_key_server
  // generate the DH output (! in our dh computes both which is not necessary)

  printf("---------------------------------------\n");
  printf("DEBUT TEST RATCHET ENCRYPT \n");

  int state_Ns = 0;

  printf("tests LENGTHS (check same size : perfect): \n");
  printf("libsodium : crypto_auth_hmacsha256_BYTES for kdf: %d\n", crypto_auth_hmacsha256_BYTES);
  printf("libsodium : crypto_auth_hmacsha256_KEYBYTES for kdf: %d\n", crypto_auth_hmacsha256_KEYBYTES);
  printf("libsodium : crypto_aead_xchacha20poly1305_ietf_KEYBYTES for kdf: %d\n", crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
  printf("saber : CRYPTO_BYTES for ss  : %d\n", CRYPTO_BYTES);
  // uint8_t VS unsigned char ok

  // KEY SEE HOW !! -> same size as SABER YES can use ss_a_server
  //testKDF = RatchetEncrypt(ss_a_server);
  unsigned char *key_CKs[crypto_auth_hmacsha256_KEYBYTES];
  unsigned char *key_CKr[crypto_auth_hmacsha256_KEYBYTES];
  crypto_auth_hmacsha256_keygen(key_CKs);
  printf("*CKs inside SERVER BEFORE:%u\n", *key_CKs);
  printf("CKs inside SERVER BREFORE:%u\n", key_CKs);
  *key_CKr = *key_CKs;
  printf("*CKr inside SERVER BEFORE:%u\n", *key_CKr);
  printf("CKr inside SERVER BREFORE:%u\n", key_CKr);

  // MESSAGE TO ENCRYPT
  const unsigned char* mess = (const unsigned char*) "test go y croit";
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
  unsigned char ciphertext[strlen((char*)mess) + crypto_aead_xchacha20poly1305_ietf_ABYTES];
  unsigned char mk[crypto_auth_hmacsha256_BYTES];
  unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
  printf("*cipher inside SERVER BEFORE:%u\n", *ciphertext);
  printf("cipher inside SERVER BEFORE:%u\n", ciphertext);
  printf("------- \n");
  int safeReturn = 0;
  safeReturn = RatchetEncrypt(mk, key_CKs, mess, ciphertext, nonce);
  state_Ns += 1;
  //int safeReturn = RatchetEncrypt(mk, &ss_a_server, mess, ciphertext, nonce);
  printf("---- \n");
  printf("*CKs inside SERVER AFTER:%u\n", *key_CKs);
  printf("CKs inside SERVER AFTER:%u\n", key_CKs);
  printf("*CKr inside SERVER AFTER:%u\n", *key_CKr);
  printf("CKr inside SERVER AFTER:%u\n", key_CKr);
  printf("*cipher inside SERVER AFTER:%u\n", *ciphertext);
  printf("cipher inside SERVER  AFTER: %u\n", ciphertext);
  printf("nonce inside SERVER AFTER: %u\n", nonce);
  //printf("*nonce inside SERVER AFTER: %u\n", *nonce);
  printf("mk inside SERVER AFTER: %u\n", mk);
  printf("*mk inside SERVER AFTER: %u\n", *mk);

  // DECRYPTION
  unsigned long long len_plain = strlen((char*)mess);
  printf("Very Large Message : %lld \n", len_plain );

  printf("TEST DECRYPT INSIDE SERVER: \n");
  unsigned char decrypted[strlen((char*)mess)];
  unsigned long long decrypted_len;
  unsigned long long ciphertext_len = strlen((char*)mess) + crypto_aead_xchacha20poly1305_ietf_ABYTES;
  if (crypto_aead_xchacha20poly1305_ietf_decrypt(decrypted, &decrypted_len, NULL, ciphertext, ciphertext_len, ADDITIONAL_DATA, ADDITIONAL_DATA_LEN, nonce, mk) != 0) {
    printf("error encrypting ciphertext \n");
  } else {
    printf("cipher decrypted  : %s\n", decrypted);
  }



  printf("------------------------------ \n");
  printf("----------- APPEL FONCTION RATCHET DECRYPT ------------------- \n");
  safeReturn = ratchetDecrypt(mk, len_plain, ciphertext, nonce, key_CKr);

  printf("------------------------------ \n");
  printf("----------- ECHANGE ENCRYPTE ------------------- \n");
  // LE CLIENT A BESOIN DE : mk, len_plain, ciphertext, nonce

  char *confirm2; /* Buffer de reception */
  confirm2 = (char*) malloc( MaxBuff );
  n = recv(ClientSocket, confirm2 ,MaxBuff, NULL);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
    printf( "Problem encountered Cannot receive message" );
  } else {
    printf("confirmation : %s \n", confirm2);
  }


/*
  printf("len_plain inside SERVER AFTER: %u\n", len_plain);
  send(ClientSocket,&len_plain,sizeof(len_plain), NULL);
*/

/*
  char *confirm;
  confirm = (char*) malloc( MaxBuff );
  n = recv(ClientSocket, confirm ,MaxBuff, NULL);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  } else {
    printf("confiramtion received by client : %s \n", confirm);
  }
*/

  unsigned char confirm[MaxBuff] = "confirm";
  printf("send : %s \n", confirm);
  send(ClientSocket, &confirm, sizeof(confirm), NULL);
  strcpy(confirm, "");
  printf("send : %s \n", confirm);
  send(ClientSocket, &confirm, sizeof(confirm), NULL);

  printf("mk inside SERVER AFTER: %u\n", mk);
  printf("*mk inside SERVER AFTER: %u\n", *mk);
  //printf("size mk : %d\n", crypto_auth_hmacsha256_BYTES);
  send(ClientSocket,mk,crypto_auth_hmacsha256_BYTES, NULL);
  //send(ClientSocket,&(*mk),sizeof(mk), NULL);


  printf("ciphertext inside SERVER AFTER: %u\n", ciphertext);
  printf("*ciphertext inside SERVER AFTER: %u\n", *ciphertext);
  send(ClientSocket, ciphertext, 15 + crypto_aead_xchacha20poly1305_ietf_ABYTES, NULL);
  //send(ClientSocket,&(*ciphertext),sizeof(ciphertext), NULL);


  printf("nonce inside SERVER AFTER: %u\n", nonce);
  printf("*nonce inside SERVER AFTER: %u\n", *nonce);
  //send(ClientSocket,&(*nonce),sizeof(nonce), NULL);
  send(ClientSocket, nonce,crypto_aead_xchacha20poly1305_ietf_NPUBBYTES, NULL);

  printf(" $$$$$$$$$$$$ GO TESTS 2 \n");
  // TESTS :
  printf("mk : %u\n", mk);
  //mk[0] = 3;
  //printf("mk : %u\n", mk);
  safeReturn = ratchetDecrypt(mk, len_plain, ciphertext, nonce, key_CKr);
  printf(" $$$$$$$$$$$$ GO TESTS 2 \n");
  printf("mk : %u\n", mk);
  printf("ciphertext: %u\n", ciphertext);
  printf("nonce : %u\n", nonce);

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
