#include <string.h>
#include "bgw.h"
#include "pbc.h"
#include "gmp.h"
#include "weshare_main.h"
#include <openssl/sha.h>
#include "aes_lib.h"
#include "utils.h"
#include "gettime.h"
// #include "rsa.h"

// void GT_to_G1( element_t GT, element_t G1)
// {
//   int length;
//   unsigned char* data;
//   length = element_length_in_bytes(GT);
//   data = pbc_malloc(length);
//   element_to_bytes(data, GT);
//   element_from_hash(G1, data, length);
// }

//convert ct_t to text to return to extension...
void get_text_from_ciphertext(cipher_pair cp, ct_t myCT){
  cp->C0 = (char*) malloc(MAX_ELEMENT_LEN);
  element_snprint(cp->C0, MAX_ELEMENT_LEN, myCT->C0);

  cp->C1 = (char*) malloc(MAX_ELEMENT_LEN);
  element_snprint(cp->C1, MAX_ELEMENT_LEN, myCT->C1);
}

//convert text from extension to ct_t
void get_ciphertext_from_text(global_broadcast_params_t gbp,
  ct_t cipher, char* C0, char* C1)
{
  element_init(cipher->C0, gbp->pairing->G1);
  element_init(cipher->C1, gbp->pairing->G1);
  int i;
  i=element_set_str(cipher->C0, C0, PBC_CONVERT_BASE);
  i=element_set_str(cipher->C1, C1, PBC_CONVERT_BASE);
}


unsigned char* encrypt_message(element_t key, char* content, int* clen, unsigned char** ret_k1){
  //Get string k from element_t key
  char* k = (char*) malloc(MAX_ELEMENT_LEN);
  element_snprint(k, MAX_ELEMENT_LEN, key);
  char* k0 = (char*) malloc(strlen(k)+2);
  sprintf(k0, "%s0", k);
  unsigned char k0hash[SHA_DIGEST_LENGTH];
  size_t length = strlen(k0);
  fprintf(stderr, "length = %d\n", length);
  SHA1((unsigned char*) k0, length, k0hash);
  //+1 to includes the \0 character also
  int len = strlen(content)+1;
  //encrypt the content
  start_t();
  unsigned char* aes_cipher = call_aes_encrypt(content, k0hash, &len, SHA_DIGEST_LENGTH);
  stop_t("Done aes");

  start_t();
  //now xor with each block...
  int ilen=0;
  char* k1 = (char*) malloc(strlen(k)+1);
  sprintf(k1, "%s1", k);
  unsigned char k1hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char*) k1, length, k1hash);
  *ret_k1 = (unsigned char*) malloc(SHA_DIGEST_LENGTH);
  memcpy(*ret_k1, k1hash, SHA_DIGEST_LENGTH);

  int i;
  for (i = 0; i < SHA_DIGEST_LENGTH; i++)
    fprintf(stderr, "%d-", k1hash[i]);
  fprintf(stderr, "\n");

  unsigned char k_hash[SHA_DIGEST_LENGTH+1];
  while (ilen < len){
    int working_size = SHA_DIGEST_LENGTH;
    if (ilen + SHA_DIGEST_LENGTH > len)
      working_size = len - ilen;
    memcpy(k_hash, k1hash, SHA_DIGEST_LENGTH);
    k_hash[SHA_DIGEST_LENGTH] = '1';
    length = sizeof(k_hash);
    fprintf(stderr, "k_hash size: %d\n", length);
    SHA1(k_hash, length, k1hash);
    int j;
    for (j=0; j < working_size; j++)
      aes_cipher[ilen+j] ^= k1hash[j];
    ilen += SHA_DIGEST_LENGTH;
  }
  *clen = len;
  stop_t("Done computing the xor..");
  fprintf(stderr, "Done everything.....\n");
  return aes_cipher;
}

char* decrypt_message(element_t key, element_t okey, unsigned char* aes_cipher, int len){
  //Get string k from element_t key
  char* k = (char*) malloc(MAX_ELEMENT_LEN);
  element_snprint(k, MAX_ELEMENT_LEN, key);
  //xor with each block...
  int ilen;
  char* k1 = (char*) malloc(strlen(k)+1);
  sprintf(k1, "%s1", k);
  unsigned char k1hash[SHA_DIGEST_LENGTH];
  size_t length = strlen(k1);
  SHA1((unsigned char*) k1, length, k1hash);

  for (ilen = 0; ilen < SHA_DIGEST_LENGTH; ilen++)
    fprintf(stderr, "%d-", k1hash[ilen]);
  fprintf(stderr, "\n");
  ilen=0;
  unsigned char k_hash[SHA_DIGEST_LENGTH+1];
  while (ilen < len){
    int working_size = SHA_DIGEST_LENGTH;
    if (ilen + SHA_DIGEST_LENGTH > len)
      working_size = len - ilen;
    memcpy(k_hash, k1hash, SHA_DIGEST_LENGTH);
    k_hash[SHA_DIGEST_LENGTH] = '1';
    length = sizeof(k_hash);
    SHA1(k_hash, length, k1hash);
    int j;
    for (j=0; j < working_size; j++)
      aes_cipher[ilen+j] ^= k1hash[j];
    ilen += SHA_DIGEST_LENGTH;
  }

  //now get k0 from original share and aes_decrypt it
  element_snprint(k, MAX_ELEMENT_LEN, okey);
  char* k0 = (char*) malloc(strlen(k)+2);
  sprintf(k0, "%s0", k);
  unsigned char k0hash[SHA_DIGEST_LENGTH];
  length = strlen(k0);
  SHA1((unsigned char*) k0, length, k0hash);
  //decrypt the content
  int plain_len = len;
  char* plaintext = call_aes_decrypt(aes_cipher, k0hash, &plain_len, SHA_DIGEST_LENGTH);
  return plaintext;
}
//di[]: all the di of new shared users
//rsa_new_recip[]: all the rsa public key
//id_new_recip[]: all the id of recipients
void do_setup(char* di[], char* rsa_new_recip[],
    int id_new_recip[], int NS, unsigned char* gbs_header){
  int i;
  global_broadcast_params_t gbs;

  //Global Setup
  setup_global_broadcast_params2(&gbs, gbs_header);
  fprintf(stderr, "Finish seting up...\n");

  //compute gz = g^z
  element_t gz;
  element_init_G1(gz, gbs->pairing);
  element_pow_zn(gz, gbs->g, gbs->z);
  //compute all the di that were not previously computed
  //di = g_i^gamma * g^z
  start_t();
  for (i = 0; i < NS; i++){
    int id = id_new_recip[i]-1;
    // log_pbc_element(gbs->gs[id], "gi before raising to gamma");
    element_pow_zn(gbs->gs[id], gbs->gs[id], gbs->gamma);
    // log_pbc_element(gbs->gs[id], "gi after raising to gamma");
    element_mul(gbs->gs[id], gbs->gs[id], gz);
    // log_pbc_element(gbs->gs[id], "gi after multiplying to g^z");
    char* s = (char*) malloc(MAX_ELEMENT_LEN);
    element_snprint(s, MAX_ELEMENT_LEN, gbs->gs[id]);
    di[i] = s;
  }
  stop_t("Computing d_i");
}

//return the final_ciphertext, len of it
//Cipher_pair: C0, C1
//di[]: all the di of new shared users
//product, t - stored by FO
//k1: send to server...
void do_encryption(unsigned char** final_cipher, int* len_cipher, cipher_pair cp, char** product_str, char** t_str, char* content, int n_shared, unsigned char* gbs_header, unsigned char** k1){

  global_broadcast_params_t gbs;
  //Global Setup
  setup_global_broadcast_params2(&gbs, gbs_header);
  fprintf(stderr, "Finish seting up...\n");

  ct_t myCT = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  element_t key, product, t;
  start_t();
  BroadcastKEM_using_product(gbs, n_shared, myCT, key, product, t);
  stop_t("Done computing key and everything...");

  //Done generating the K and other params
  //Now encrypt the message
  *final_cipher = encrypt_message(key, content, len_cipher, k1);

  get_text_from_ciphertext(cp, myCT);
  *product_str = from_element_to_str(product);
  *t_str = from_element_to_str(t);
}

void do_decryption (char** plaintext, unsigned char* headers, unsigned char* ciphertext, int len, char* C0, char* C1, char* OC0, char* OC1, char* di, int id, int NS, int ONS)
{
  int i;
  global_broadcast_params_t gbs;
  //Global Setup
  setup_global_broadcast_params2(&gbs, headers);
  fprintf(stderr, "Done setting up\n");

  ct_t cipher = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  ct_t ocipher = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  element_t key, okey, private_di;
  element_init_G1(private_di, gbs->pairing);
  i=element_set_str(private_di, di, PBC_CONVERT_BASE);
  get_ciphertext_from_text(gbs, cipher, C0, C1);
  get_ciphertext_from_text(gbs, ocipher, OC0, OC1);

  //get the new key for the second layer
  get_key(gbs, cipher, private_di, id, NS, key);
  log_pbc_element(key, "Current Key: ");
  //get the original key for the first layer
  get_key(gbs, ocipher, private_di, id, ONS, okey);

  *plaintext=decrypt_message(key, okey, ciphertext, len);
}


void do_revocation(unsigned char* headers, char* product, int n_shared, int n_revoked, cipher_pair new_cp, char** new_product, char** new_t, unsigned char** ret_k1)
{
  int i;
  global_broadcast_params_t gbs;
  //Global Setup
  setup_global_broadcast_params2(&gbs, headers);

  element_t prod;
  element_init_G1(prod, gbs->pairing);
  i=element_set_str(prod, product, PBC_CONVERT_BASE);

  ct_t cipher = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  element_t key, t;

  start_t();
  revoke_users_using_product(gbs, n_shared, n_revoked, prod, cipher, key, t);

  //compute the new k1 and send to server...
  char* k = (char*) malloc(MAX_ELEMENT_LEN);
  element_snprint(k, MAX_ELEMENT_LEN, key);
  fprintf(stderr, "new key: %s\n", k);
  char* k1 = (char*) malloc(strlen(k)+1);
  sprintf(k1, "%s1", k);
  unsigned char k1hash[SHA_DIGEST_LENGTH];
  size_t length = strlen(k1);

  SHA1((unsigned char*) k1, length, k1hash);
  *ret_k1 = (unsigned char*) malloc(SHA_DIGEST_LENGTH);
  memcpy(*ret_k1, k1hash, SHA_DIGEST_LENGTH);

  stop_t("Done revoking user");

  get_text_from_ciphertext(new_cp, cipher);
  *new_product = from_element_to_str(prod);
  *new_t = from_element_to_str(t);
}

void do_sharing(unsigned char* headers, char* product, char* t_chr, int NS, int n_new, char** new_prod, char** new_C1){
  int i;
  global_broadcast_params_t gbs;
  //Global Setup
  setup_global_broadcast_params2(&gbs, headers);

  element_t prod, t, C1;
  element_init_G1(prod, gbs->pairing);
  i=element_set_str(prod, product, PBC_CONVERT_BASE);

  element_init_Zr(t, gbs->pairing);
  i=element_set_str(t, t_chr, PBC_CONVERT_BASE);

  share_users_using_product(gbs, NS, n_new, prod, C1, t);
  *new_prod = from_element_to_str(prod);
  *new_C1 = from_element_to_str(C1);
}