#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "bgw.h"
#include "utils.h"

void FreeCT(ct_t myct)
{
  if(!myct) {
    printf("error: null pointer passed to freeCT\n");
    return;
  }
  element_clear(myct->C0);
  element_clear(myct->C1);
  return;
}

void FreeBCS(broadcast_system_t bcs)
{
  if(!bcs) {
    printf("error: null pointer passed to freeBCS\n");
    return;
  }
  element_clear(bcs->encr_prod);
  element_clear(bcs->pub_key);
  element_clear(bcs->priv_key);
  return;
}

void FreeGBP(global_broadcast_params_t gbp)
{
  if(!gbp) {
    printf("error: null pointer passed to freeGBP\n");
    return;
  }
  //do something about the pairing
  element_clear(gbp->g);
  element_clear(gbp->z);
  element_clear(gbp->gamma);
  int i;
  for(i = 0; i < gbp->num_users; i++) {
    if(i == gbp->num_users) continue;
    element_clear(gbp->gs[i]);
  }
  pbc_free(gbp->gs);
  return;
}

void FreePK(priv_key_t key)
{
  if(!key) {
    printf("error: null pointer passed to freePK\n");
    return;
  }
  element_clear(key->g_i_gamma);
  element_clear(key->g_i);
  element_clear(key->decr_prod);
  return;
}


static inline void out(element_t elem, FILE *myfile)
{
  int sz = element_length_in_bytes(elem);
  fwrite(&sz, 4, 1, myfile);
  unsigned char* data = pbc_malloc(sz);
  if(!data) printf("DATA IS NULL\n");
  element_to_bytes(data, elem);
  fwrite(data, sz, 1, myfile);
  pbc_free(data);
}

static inline int in(element_t elem, unsigned char *my_feed) {
  int sz;
  // fprintf(stderr, "Prepare reading sz\n");
  memcpy(&sz, my_feed, 4);
  // fprintf(stderr, "Size of pbc element: %d\n", sz);
  unsigned char* data = pbc_malloc(sz);
  memcpy(data, my_feed+4, sz);
  element_from_bytes_compressed(elem, data);
  pbc_free(data);
  return sz+4;
}

void get_key(global_broadcast_params_t gbp, ct_t cipher, element_t di,
        int id, int NS, element_t key)
{
  element_t temp;
  element_t temp2;
  element_t temp3;
  element_t di_copy;

  element_init(temp, gbp->pairing->GT);
  element_init(temp2, gbp->pairing->GT);
  element_init(temp3, gbp->pairing->GT);
  element_init(di_copy, gbp->pairing->G1);
  element_set(di_copy, di);

  //Generate the numerator
  id = id-1;
  fprintf(stderr, "id = %d NS=%d\n", id, NS);
  element_pairing(temp, cipher->C1, gbp->gs[id]);
  //G1 element in denom
  int i, n = gbp->num_users;
  for (i=0; i<NS; i++)
    if (i != id)
      element_mul(di_copy, di_copy, gbp->gs[n-i+id]);
  //Generate the denominator
  element_pairing(temp2, di_copy, cipher->C0);
  //Invert the denominator
  element_invert(temp3, temp2);

  element_init(key, gbp->pairing->GT);
  //multiply the numerator by the inverted denominator
  element_mul(key, temp, temp3);
  element_clear(temp);
  element_clear(di_copy);
  element_clear(temp2);
  element_clear(temp3);
}



void BroadcastKEM_using_product(global_broadcast_params_t gbp, int NS,
				ct_t myct, element_t key, element_t product, element_t t)
{
  element_t tz, d_key;

  element_init_Zr(t, gbp->pairing);
  element_random(t);

  element_init(key, gbp->pairing->GT);
  element_init(d_key, gbp->pairing->GT);
  element_init(myct->C0, gbp->pairing->G2);
  element_init(myct->C1, gbp->pairing->G1);

  //COMPUTE K = e(g_n, g_1)^(t)/e(g, g)^(tz)
  element_init_Zr(tz, gbp->pairing);
  element_mul_zn(tz, gbp->z, t);
  element_pairing(key, gbp->gs[gbp->num_users-1], gbp->gs[0]);
  element_pow_zn(key, key, t);
  element_pairing(d_key, gbp->g, gbp->g);
  element_pow_zn(d_key, d_key, tz);
  element_div(key, key, d_key);


  //COMPUTE C0 = g^t
  element_pow_zn(myct->C0, gbp->g, t);

  //COMPUTE C1 as in (v* mul of all j \in S: g_(n+1-j)  )^t
  element_pow_zn(myct->C1, gbp->g, gbp->gamma);
  int n = gbp->num_users;
  //initially share with people from 1..NS
  int i;
  for(i = 0; i < NS; i++)
      element_mul(myct->C1, myct->C1, gbp->gs[n-i-1]);
  element_init_G1(product, gbp->pairing);
  element_set(product, myct->C1);
  element_pow_zn(myct->C1, myct->C1, t);

  element_clear(tz);
  element_clear(d_key);
}

//revoke users from n_shared-n_revoked+1..nshared-1
void revoke_users_using_product(global_broadcast_params_t gbp,
  int n_shared, int n_revoked, element_t prod, ct_t myct, element_t key, element_t t){
  element_t tz, d_key;
  //generate new t
  element_init_Zr(t, gbp->pairing);
  element_random(t);

  element_init(key, gbp->pairing->GT);
  element_init(d_key, gbp->pairing->GT);
  element_init(myct->C0, gbp->pairing->G1);
  element_init(myct->C1, gbp->pairing->G1);

  //COMPUTE K = e(g_n, g_1)^(t)/e(g, g)^(tz)
  element_init_Zr(tz, gbp->pairing);
  element_mul_zn(tz, gbp->z, t);
  element_pairing(key, gbp->gs[gbp->num_users-1], gbp->gs[0]);
  element_pow_zn(key, key, t);
  element_pairing(d_key, gbp->g, gbp->g);
  element_pow_zn(d_key, d_key, tz);
  element_div(key, key, d_key);

  //COMPUTE new C0 = g^t
  element_pow_zn(myct->C0, gbp->g, t);

  //COMPUTE C1 as in (v* mul of all j \in S: g_(n+1-j)  )^t
  element_pow_zn(myct->C1, gbp->g, gbp->gamma);
  int n = gbp->num_users;
  //initially share with people from 1..NS
  int i;
  for(i = 0; i < n_revoked; i++){
      int i_rv = n_shared-i-1;
      element_div(prod, prod, gbp->gs[n-i_rv-1]);
    }

  element_pow_zn(myct->C1, prod, t);

  element_clear(tz);
  element_clear(d_key);
}


//share users from n_shared..n_shared+n_new-1
void share_users_using_product(global_broadcast_params_t gbp,
  int n_shared, int n_new, element_t prod, element_t C1, element_t t){

  element_init_G1(C1, gbp->pairing);
  //compute new C1 and new product
  int n = gbp->num_users;
  int i;
  for(i = 0; i < n_new; i++){
    int i_share = n_shared+i;
    element_mul(prod, prod, gbp->gs[n-i_share-1]);
  }

  element_pow_zn(C1, prod, t);
}


void setup_global_broadcast_params2(global_broadcast_params_t *sys,
           unsigned char* gbs_header)
{
  global_broadcast_params_t gbs;
  gbs = pbc_malloc(sizeof(struct global_broadcast_params_s));
   // Setup curve in gbp
  size_t count = strlen(PBC_PAIRING_PARAMS);
  if (pairing_init_set_buf(gbs->pairing, PBC_PAIRING_PARAMS, count)) pbc_die("pairing init failed");

  int num_users;
  memcpy(&num_users, gbs_header, 4);
  // fprintf(stderr, "N = %d\n", num_users);
  gbs->num_users = num_users;
  gbs_header= gbs_header+4;
  // fprintf(stderr, "Done reading N \n");
  element_t *lgs;
  int i;
  lgs = pbc_malloc(2 * num_users * sizeof(element_t));

  //generate g
  element_init(gbs->g, gbs->pairing->G1);
  gbs_header += in(gbs->g, gbs_header);

  //Fill in the gs array
  for(i = 0; i < 2*num_users; i++) {
    element_init(lgs[i], gbs->pairing->G1);
    if(i == num_users)
      continue;
    gbs_header += in(lgs[i], gbs_header);
  }

  element_init_Zr(gbs->z, gbs->pairing);
  element_init_Zr(gbs->gamma, gbs->pairing);
  i=element_set_str(gbs->z, PRIVATE_Z, PBC_CONVERT_BASE);
  i=element_set_str(gbs->gamma, PRIVATE_GAMMA, PBC_CONVERT_BASE);

  //For simplicity & so code was easy to read
  gbs->gs = lgs;
  *sys = gbs;
}


void setup_global_broadcast_params(global_broadcast_params_t *sys,
				   char* gbs_header)
{
  global_broadcast_params_t gbs;
  gbs = pbc_malloc(sizeof(struct global_broadcast_params_s));

  // Setup curve in gbp
  size_t count = strlen(PBC_PAIRING_PARAMS);
  if (pairing_init_set_buf(gbs->pairing, PBC_PAIRING_PARAMS, count)) pbc_die("pairing init failed");


  char* ch;
  ch = strtok(gbs_header, "\n");
  int num_users = atoi(ch);
  gbs->num_users = num_users;
  element_t *lgs;
  int i, j;

  lgs = pbc_malloc(2 * num_users * sizeof(element_t));
  if(!(lgs)) {
    printf("\nMalloc Failed\n");
    printf("Didn't finish system setup\n\n");
  }

  //generate g
  element_init(gbs->g, gbs->pairing->G1);
  ch = strtok(NULL, "\n");
  i=element_set_str(gbs->g, ch, PBC_CONVERT_BASE);

  //Fill in the gs array
  for(i = 0; i < 2*num_users; i++) {
    element_init(lgs[i], gbs->pairing->G1);
    if(i == num_users)
      continue;
    ch = strtok(NULL, "\n");
    j=element_set_str(lgs[i], ch, PBC_CONVERT_BASE);
  }

  element_init_Zr(gbs->z, gbs->pairing);
  element_init_Zr(gbs->gamma, gbs->pairing);
  i=element_set_str(gbs->z, PRIVATE_Z, PBC_CONVERT_BASE);
  i=element_set_str(gbs->gamma, PRIVATE_GAMMA, PBC_CONVERT_BASE);

  //For simplicity & so code was easy to read
  gbs->gs = lgs;
  *sys = gbs;
}