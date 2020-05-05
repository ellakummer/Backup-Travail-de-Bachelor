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

#include "common.h"

#include "api.h"
#include "poly.h"
#include "rng.h"
#include "SABER_indcpa.h"
#include "kem.h"
#include "verify.h"

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
  int sock;    /* Socket */
  char *host;  /* Adresse IP du serveur */
  int port;    /* Port du service */
  size_t numBytes; /* Nombre de bytes aléatoires demandés */
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

  sock = makeSocket( host, port ); // fonctions du dessus
  // --------- TEST -----------
  //printf("%d\n", sock);

  /* Envoie de la requête */

  // écrire les numBytes sur le descripteur sock : envoie nombre de bytes demandés
  if( write(sock,&numBytes,sizeof(numBytes)) < sizeof(numBytes) ) {
    die( "Cannot send the filename to retrieve" );
  }

  /* Reception de la réponse */

  data = (char*) malloc( numBytes );

  while( rcvd < numBytes ) {
    n = read( sock, data+rcvd, numBytes-rcvd );
    if( n  < 0 ) {
      die( "Cannot receive data" );
    }
    rcvd += n;
    printf( "Received %ld bytes.\n", n );
  }

  /* Décommenter pour afficher le résultats en hexadecimal */


  printf( "Received: " );
  for( int i=0; i < numBytes; i++ ) {
    printf("%x\n", data[i] & 0xff );
  }
  printf("\n");


  /* Libération des resources */
  free( data );
  close(sock);

  exit(EXIT_SUCCESS);
}
