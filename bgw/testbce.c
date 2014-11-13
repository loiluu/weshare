/* Implementation of Boneh-Gentry-Waters broadcast encryption scheme
   Code by:  Matt Steiner   MattS@cs.stanford.edu
   testbce.c
*/

#include <string.h>
#include "pbc_bce.h"

#define N 64
#define N_DIV_EIGHT  N/8


int main(void)
{
  int i;
  
  global_broadcast_params_t gbs;

  //Global Setup
  Setup_global_broadcast_params(&gbs, N, "a.param");
  
  if(1 && DEBUG) {
    printf("\ng = ");  
    element_out_str(stdout, 0, gbs->g);    
    for(i = 0; i < 1; i++) {
      printf("\nThe next element is %d------------------------------------",i);
      printf("\ngs[%d] = ", i);
      element_out_str(stdout, 0, gbs->gs[i]);
    }
    printf("\n");
  }
  
  //Broadcast System Setup
  broadcast_system_t sys;
  Gen_broadcast_system(gbs, &sys);
  
  struct single_priv_key_s mykey;
  struct single_priv_key_s mykey2;
    

  //What is recip here?? just don't get it
  char recip[N_DIV_EIGHT];
  for(i = 0; i < 1; i++) recip[i] = 255;
  for(i = 1; i < N_DIV_EIGHT; i++) recip[i] = 0;

  Gen_encr_prod_from_bitvec(gbs, sys, recip);

  //TESTING FOR SYSTEM LOAD AND STORE
  // global_broadcast_params_t gbp2;
  // broadcast_system_t sys2;
  
  StoreParams("system.stor", gbs, sys);
  //printf("\ndone storing!!!!!!!!!\n\n");
  // LoadParams("system.stor", &gbp2, &sys2);  


  Get_priv_key(gbs, sys, 2, &mykey2);
  Get_priv_key(gbs, sys, 1, &mykey);
  
  
  //int in_recip[5] = {4, 5, 6, 7, 8 };
  //int num_recip = 5;
  //int rems[3] = { 5, 6, 7 };
  //int N_rems = 3;
  //int adds[12] = { 2, 3, 5, 6, 7, 10, 11, 12, 13, 14, 15, 16 };
  //int N_adds = 12;
  // FINAL ELEMENTS IN PRODUCT SHOULD BE 2-8, & 10-16

  /*
  Gen_encr_prod_from_indicies(gbs, sys2, in_recip, num_recip);

  if(DEBUG) {
    PrintBitString(sys2->recipients,BSL);
    printf("\nsys2 encr_product = ");
    element_out_str(stdout, 0, sys2->encr_prod);
    printf("\n");
  }

  Change_encr_prod_indicies(gbs, sys2, adds, N_adds, rems, N_rems);
  if(DEBUG) {
    PrintBitString(sys2->recipients,BSL);
    printf("\nsys2 encr_product = ");
    element_out_str(stdout, 0, sys2->encr_prod);
    printf("\n");
  }
    

  if(DEBUG) {
    PrintBitString(sys->recipients,BSL);
    printf("\nsys1 encr_product = ");
    element_out_str(stdout, 0, sys->encr_prod);
  }  
  */
  
  Gen_decr_prod_from_bitvec(gbs, 1, recip, &mykey);
  Gen_decr_prod_from_bitvec(gbs, 2, recip, &mykey2);
  
  printf("\n");
  printf("mykey1 decr_product = ");
  element_out_str(stdout, 0, mykey.decr_prod);

  printf("\n");
  printf("mykey2 decr_product = ");
  element_out_str(stdout, 0, mykey2.decr_prod);
  printf("\n");


  //TESTING FOR SINGLE KEY LOAD AND STORE
  // priv_key_t load_key = (priv_key_t)pbc_malloc(sizeof(struct single_priv_key_s));

  // StorePrivKey("key2.stor", &mykey);
  // LoadPrivKey("key2.stor", &load_key, gbs);
  
  
  ct_t myCT = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  ct_t myCT2 = (ct_t) pbc_malloc(sizeof(struct ciphertext_s));
  element_t key1;
  element_t key2;
  element_t key3;
 
  BroadcastKEM_using_product(gbs, sys, myCT, key1);
  DecryptKEM_using_product(gbs, &mykey, key2, myCT);
  DecryptKEM_using_product(gbs, &mykey2, key3, myCT);

  printf("\nkey1 = ");
  element_out_str(stdout, 0, key1);
  printf("\n");
  printf("\nkey2 = ");
  element_out_str(stdout, 0, key2);
  printf("\n");
  printf("\nkey3 = ");
  element_out_str(stdout, 0, key3);
  printf("\n");


  FreeCT(myCT);
  FreeBCS(sys);
  FreeGBP(gbs);
  FreePK(&mykey);
  FreePK(&mykey2);
  return 0;
}