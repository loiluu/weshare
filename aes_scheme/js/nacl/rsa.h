#ifndef RSA_H_
#define RSA_H_

int public_encrypt(unsigned char* data,int data_len, unsigned char* key, unsigned char *encrypted);
int private_decrypt(unsigned char* enc_data,int data_len, unsigned char* key, unsigned char *decrypted);

#endif
