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

#include "common.h"

#include "api.h"
#include "poly.h"
#include "rng.h"
#include "SABER_indcpa.h"
#include "kem.h"
#include "verify.h"
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
  printf("TEST : ENVOI DU NOMBRE ENTRE DANS LA CONSOLE \n");
  // RECUPERE COMBIEN ON VEUT
  char nbre[20] = {0};
  printf("Combient d'elements voulez vous ");
  //scanf("%s", nbre);
  fgets(nbre, MaxBuff, stdin);
  printf("Ah ! Vous vous appelez donc %s !\n\n", nbre);
  int val = atoi(nbre);

  // FIN RECUPERATION

  unsigned char buffer2[TBuffer2];
  FILE *fp2;
  fp2 = fopen("/dev/urandom", "r");

  fread(&buffer2, 1, TBuffer2, fp2);
  unsigned char buffenvoytest[val]; // ou on stock ceux que l'on va envoyer
  printf("le buffer a envoyer  ->  %ld\n", sizeof(buffenvoytest));
  for(int k=0; k < val; ++k) {
    buffenvoytest[k] = buffer2[k]; // (les s premiers du buffer déjà envoyés)
  }

  printf("ICI TEST BUFER !!! \n");
  for( int i=0; i < val; i++ ) {
    printf("%x\n", buffenvoytest[i] & 0xff );
  }

  //int buffenvoytest2 = 11;
  send(ClientSocket,&buffenvoytest,sizeof(buffenvoytest), NULL);

  printf("---------------------------------------\n");
  printf("TEST : ENVOI DU NOMBRE DEMANDE PAR CLIENT EN ARGUMENT \n");
  n = recv(ClientSocket, &ask ,MaxBuff, NULL);
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }
  printf("le client a demande combien d'elts ->  %d\n", ask);

  int resteAEnvoyer= ask; // la variable contiendra le nombre de bytes qui reste à envoyer ( utile s'il faut les envoyer en plusieurs fois à cause de la taille du buffer)
  // on va créer le buffer du serveur, avec 2048 nombres aléatoires à l'intérieur
  unsigned char buffer[TBuffer];
  FILE *fp;
  fp = fopen("/dev/urandom", "r");
  fread(&buffer, 1, TBuffer, fp);
  while(resteAEnvoyer > 0) {
	  if ( resteAEnvoyer <= TBuffer - s) { // 2048-s = nombre de bytes restants dans buffer -> ok assez à envoyer
  		// on va envoyer les bytes de Bs à Bs+resteaenvoyer
  		unsigned char buffenvoy[ask]; // ou on stock ceux que l'on va envoyer
  		for(int k=0; k < resteAEnvoyer; ++k) {
  			buffenvoy[k] = buffer[s+k]; // (les s premiers du buffer déjà envoyés)
  		}
  		// on "l'écrit" au client (= les envoyer)
  	  send(ClientSocket,&buffenvoy,sizeof(buffenvoy), NULL);
  		s = s + resteAEnvoyer; // on augmente le nombre de bytes du buffer utilisés
  		resteAEnvoyer = 0; // on a pu envoyer un nombre de bytes suffisants (condition du if)

	  } else if ( resteAEnvoyer > TBuffer - s) { // pas assez de nombre dans le buffer
  		// on va envoyer les bytes de Bs à B2048 (max pour ce coup ci)
  		unsigned char buffenvoy[ask];
  		for(int k=0; k < TBuffer-s; ++k) {
  			buffenvoy[k] = buffer[s+k];
  		}

  	  send(ClientSocket,&buffenvoy,sizeof(buffenvoy), NULL);
  		resteAEnvoyer = resteAEnvoyer - (TBuffer - s);
  		// puis on remplit le buffer
  	  fp = fopen("/dev/urandom", "r");
  	  fread(&buffer, 1, TBuffer, fp);
  		s = 0; // le buffer de nouveau plein, aucun bytes utilises
    }
  }

  printf("---------------------------------------\n");
  printf("DEBUT TEST MESSAGE TEXTE ");
  //ssize_t numberReceivedMess;
  char *dataMess; /* Buffer de reception */
  dataMess = (char*) malloc( MaxBuff );
  n = recv( ClientSocket, dataMess, MaxBuff, NULL); // ICI CHANGE !! 12
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }
  printf( "Received %ld bytes.\n", n );
  printf( "Received: " );
  printf("%s \n\n", dataMess);
  /*
  n = recv( ClientSocket, dataMess, MaxBuff, NULL); // ICI CHANGE !! 12
  if( n  < 0 ) {
    die( "Problem encountered Cannot receive message" );
  }
  printf( "Received %ld bytes.\n", n );
  printf( "Received: " );
  printf("%s \n\n", dataMess);
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
  printf("DEBUT TEST DISCUSION \n");
  n = -1;
  // fcntl(0, F_SETFL, O_NONBLOCK);
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

    /*
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
    */
  }

  fclose(fp);
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
