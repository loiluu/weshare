#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <pbc.h>
#include "bgw.h"

/*
generate random string of len size
 */
char *rand_string(char *str, size_t size)
{
   static int mySeed = 123456;
   srand(time(NULL) * size + ++mySeed);
   const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJK...";
   if (size) {
     --size;
     size_t n;
     for (n = 0; n < size; n++) {
         int key = rand() % (int) (sizeof charset - 1);
         str[n] = charset[key];
     }
     str[size] = '\0';
   }
   return str;
}


void log_pbc_element(element_t e, char* message){
  char* s = (char*) malloc(MAX_ELEMENT_LEN);
  int t; 
  t = element_snprint(s, MAX_ELEMENT_LEN, e);
  fprintf(stderr, " message: %s, Log: %s\n", message, s); 
  t = t+1;
  free(s);
}

char* from_element_to_str(element_t e){
  char* tmp = (char*) malloc(MAX_ELEMENT_LEN);
  element_snprint(tmp, MAX_ELEMENT_LEN, e);
  return tmp;
}