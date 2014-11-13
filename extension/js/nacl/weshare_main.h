#include <string.h>
#ifndef WESHARE_MAIN_H_
#define WESHARE_MAIN_H_

typedef struct ciphertext {
  char* C0;
  char* C1;  
}* cipher_pair;

void do_encryption(unsigned char** final_cipher, int* len_cipher, cipher_pair cp, char** product_str, char** t_str, char* content, int n_shared, unsigned char* gbs_header, unsigned char** k1);

void do_decryption (char** plaintext, unsigned char* headers, unsigned char* ciphertext, int len, char* C0, char* C1, char* OC0, char* OC1, char* di, int id, int NS, int ONS);

void do_revocation(unsigned char* headers, char* product, int n_shared, int n_revoked, cipher_pair new_cp, char** new_prod, char** new_t, unsigned char** k1);

void do_sharing(unsigned char* headers, char* prod, char* t, int NS, int n_new, char** new_prod, char** new_C1);

void do_setup(char* di[], char* rsa_new_recip[], int id_new_recip[], int NS, unsigned char* gbs_header);
#endif