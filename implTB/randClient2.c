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

  printf("CLIENT ENCODE MESSAGE \n");
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
  // LE CLIENT A BESOIN DE : mk, len_plain, ciphertext, nonce
  char *mk;
  mk = (char*) malloc( MaxBuff );
  if (recv( ServerSocket, mk, MaxBuff, NULL) >= 0) {
    printf( "Received: " );
    printf("%s \n", mk);
    n = -1;
  }

  // Waiting
  unsigned char *key_CKr[crypto_auth_hmacsha256_KEYBYTES];
  crypto_auth_hmacsha256_keygen(key_CKr);
  /*
  safeReturn = ratchetDecrypt(mk, len_plain, ciphertext, nonce, key_CKr);
  */

  printf("--------------------------------------- \n");
  printf("DEBUT TEST DISCUSION \n");
  // le client commence en terme de logique : lui se connecte
  n = -1;
  //fcntl(0, F_SETFL, O_NONBLOCK);
  while(1) {
    // MESSAGE ENVOYE

    // IF WANT TO SEND

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

    /*
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
    */
  }

  // ---- FIN TEST MESSAGE ------------------

  /* Libération des resources */
  //free( data );
  close(ServerSocket);

  exit(EXIT_SUCCESS);
}
