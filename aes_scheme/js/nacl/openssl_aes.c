/**
  AES encryption/decryption demo program using OpenSSL EVP apis
  gcc -Wall openssl_aes.c -lcrypto

  this is public domain code.

  Saju Pillai (saju.pillai@gmail.com)
**/

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "utils.h"
#include "rsa.h"
#include "gettime.h"
#include "aes_lib.h"
#include "base64.h"

void do_encryption(char* content, unsigned char** aes_cipher, int* len, char* rsa_keys[], char* rsa_cipher[], int NS){

  /*
  generate new data key if it is encryption
   */
  char* key_data;
  int key_data_len;
  key_data_len = DEFAULT_KEY_DATA_LEN;
  key_data = (char*) malloc(key_data_len+1);
  rand_string (key_data, key_data_len);


  int clen = strlen(content);
  fprintf(stderr, "Content: %s\n", content);
  *aes_cipher = call_aes_encrypt(content, key_data, &clen);
  *len = clen;

  //encrypt the key by rsa
  int encrypted_key_len;
  unsigned char* key_cipher = (unsigned char*) malloc(4098) ;
  unsigned char* rsa_pkey;
  int i;
  for (i = 0; i < NS; i++){
    rsa_pkey = (unsigned char*) rsa_keys[i];
    encrypted_key_len = public_encrypt((unsigned char*) key_data, key_data_len, rsa_pkey, key_cipher);
    rsa_cipher[i] = base64Encode(key_cipher, encrypted_key_len);
  }

  free(key_cipher);
}


void do_decryption(unsigned char* main_content, int len, char* rsa_skey, char* aes_k,char** raw_main){

  int key_data_len;
  unsigned char *key_data;

  int raw_len;
  key_data = (unsigned char*) malloc(4098);
  unsigned char* aes_key;
  raw_len = base64Decode(aes_k, &aes_key);
  key_data_len = private_decrypt(aes_key, raw_len, (unsigned char*) rsa_skey, key_data);
  //fprintf(stderr, "Done RSA Decryption\n");
  if(key_data_len == -1)
      fprintf(stderr, "%s\n", "RSA Private Decryption failed");
  free(aes_key);

  //This is for main
  int clen=len;
  *raw_main = (char*) call_aes_decrypt(main_content, (char*) key_data, &clen);
}


void do_revocation(char* content, char** aes_cipher, char* rsa_keys[], char* rsa_cipher[], int NS){
  /*
  generate new data key if it is encryption
   */
  char* key_data;
  int key_data_len;
  key_data_len = DEFAULT_KEY_DATA_LEN;
  key_data = (char*) malloc(key_data_len+1);
  rand_string (key_data, key_data_len);

  //fprintf(stderr, "Finish rand_string, new AES key = %s\n", key_data);


  int k = 0;
  char** diffs = (char**) malloc(sizeof(char*));
  char* pch=strtok(content, SPLIT_PATTERN);

  while (pch != NULL && strlen(content)){
    diffs[k] = pch;
    diffs = (char**) realloc(diffs, sizeof(char*)*(k+2));
    k++;
    pch = strtok(NULL, SPLIT_PATTERN);
  }
  //fprintf(stderr, "Done PARSING for DIFF\n");

  int i=0;
  char* ret = malloc(1);
  strcpy(ret, "");
  char* ciphertext = NULL;
  for (i=0; i < k; i++){
    unsigned char *ciphertext;
    int len = strlen(diffs[i])+1;
    ciphertext = call_aes_encrypt(diffs[i], key_data, &len);
    char* tmp_aes_cipher = base64Encode(ciphertext, len);
    //fprintf(stderr, "New ciphertext for %d: %s\n", i, tmp_aes_cipher);
    ret = (char*) realloc(ret, strlen(ret) + strlen(tmp_aes_cipher) + strlen(SPLIT_PATTERN)+1);
    strcat(ret, tmp_aes_cipher);
    strcat(ret, SPLIT_PATTERN);
    free(tmp_aes_cipher);
  }
  *aes_cipher = ret;
  //fprintf(stderr, "Finish call_aes_encrypt\n");

  //encrypt the key by rsa
  // int i = 0;
  int encrypted_key_len;
  unsigned char* key_cipher = (unsigned char*) malloc(4098) ;
  unsigned char* rsa_pkey;

  for (i = 0; i < NS; i++){
    rsa_pkey = (unsigned char*) rsa_keys[i];
    //fprintf(stderr, "Working with user %d\n", i);
    encrypted_key_len = public_encrypt((unsigned char*) key_data, key_data_len, rsa_pkey, key_cipher);
    rsa_cipher[i] = base64Encode(key_cipher, encrypted_key_len);
    printf("New RSA encrypted AES key for %d: %s\n", i, rsa_cipher[i]);
  }

  free(ciphertext);
  free(key_cipher);
}


void do_update(char* content, char** aes_cipher, char* rsa_skey, char* rsa_cipher){

  /*
  generate new data key if it is encryption
   */
  int key_data_len;
  unsigned char *key_data = (unsigned char*) malloc(4098);

  //fprintf(stderr, "Preparing decoding key\n");
  unsigned char* diff_aes_key;
  int raw_len = base64Decode(rsa_cipher, &diff_aes_key);
  //fprintf(stderr, "Finish decoding key\n");
  key_data_len = private_decrypt(diff_aes_key, raw_len, (unsigned char*) rsa_skey, key_data);

  if(key_data_len == -1)
      //fprintf(stderr, "%s\n", "RSA Private Decryption failed");
  free(diff_aes_key);


  //fprintf(stderr, "Finish getting key\n");
  unsigned char *ciphertext;
  int len = strlen(content)+1;

  ciphertext = call_aes_encrypt(content, (char*) key_data, &len);
  *aes_cipher = base64Encode(ciphertext, len);

  //fprintf(stderr, "Finish call_aes_encrypt, cipher = %s\n", *aes_cipher);

  free(ciphertext);
}