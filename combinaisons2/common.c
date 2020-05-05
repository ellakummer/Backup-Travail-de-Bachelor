#include <stdio.h>
#include <stdlib.h>

void die(char *issue) {
  perror(issue); 
  exit(EXIT_FAILURE); 
}
