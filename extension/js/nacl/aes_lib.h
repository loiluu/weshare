#ifndef AES_LIB_H
#define AES_LIB_H
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

unsigned char* call_aes_encrypt(char* M, unsigned char* key, int* len, int key_len);
char* call_aes_decrypt(unsigned char* M, unsigned char* key, int* len, int key_len);

#endif