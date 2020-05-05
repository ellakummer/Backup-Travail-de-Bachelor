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

#define MaxConnectionsAttentes 2306
#define MaxBuff 2306
#define MaxChemin 2306
#define TBuffer 2306
#define TBuffer2 100

struct ReturnKDFCK {
    int ck;
    int mk;
};

struct ReturnKDFCK testfunc(int a) {
  struct ReturnKDFCK b;
  b.ck = a;
  b.mk = 2*a;
  return b;
}

int main(int argc, char **argv) {

char message[] = "testMessageToEncrypt";
printf("message : %s\n", message);

struct ReturnKDFCK test;

test.ck = 1;
test.mk = 2;

printf("test go : %d\n", test.ck);
printf("test go : %d\n", test.mk);

test = testfunc(3);
printf("test after : %d\n", test.ck);
printf("test after : %d\n", test.mk);

uint8_t ss_shared_secret[CRYPTO_BYTES];


  return 0;
}
