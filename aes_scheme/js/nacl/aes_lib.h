#ifndef AES_LIB_H
#define AES_LIB_H
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

char* call_aes_decrypt(unsigned char* M, char* key, int* len);
unsigned char* call_aes_encrypt(char* M, char* key, int* len);

#endif