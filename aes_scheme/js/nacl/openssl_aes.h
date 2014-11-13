#ifndef OPENSSL_AES_H_
#define OPENSSL_AES_H_

#include <string.h>
void do_encryption(char* content, unsigned char** aes_cipher, int* len, char* rsa_keys[], char* rsa_cipher[], int NS);
void do_decryption(unsigned char* main_content, int len, char* rsa_skey, char* aes_k, char** raw_main);
void do_revocation(char* content, char** aes_cipher, char* rsa_keys[], char* rsa_cipher[], int NS);
void do_update(char* content, char** aes_cipher, char* rsa_keys, char* rsa_cipher);
#endif