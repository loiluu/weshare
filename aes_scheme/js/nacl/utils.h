#ifndef UTILS_H_
#define UTILS_H_

#define DEFAULT_KEY_DATA_LEN 20
#define SPLIT_PATTERN "-"

unsigned char* convert_string_to_ascii(char* ascii_cipher, int* ret_len);
char* convert_ascii_to_string(unsigned char* ciphertext, int len);

char *rand_string(char *str, size_t size);
unsigned char* get_private_key();
unsigned char* get_public_key();

#endif