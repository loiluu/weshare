#ifndef PBC_BCE_H_
#define PBC_BCE_H_

#include <string.h>
#include "pbc.h"


/* **********************************************************
   DEBUG having the debug flag turned on spews out lots of
   debugging output.
*********************************************************  */
#define DEBUG 0

/* **********************************************************
  PBC_PAIRING_PARAMS stores the content of pairing parameters,
  including all the types, etc..
  *********************************************************  */

#define MAX_ELEMENT_LEN 1000
#define MPZ_CONVERT_BASE 62
#define PBC_CONVERT_BASE 10
#define DEFAULT_KEY_DATA_LEN 20

#define PBC_PAIRING_PARAMS "type a\n \
  q 8780710799663312522437781984754049815806883199414208211028653399266475630880222957078625179422662221423155858769582317459277713367317481324925129998224791\n \
  h 12016012264891146079388821366740534204802954401251311822919615131047207289359704531102844802183906537786776\n \
  r 730750818665451621361119245571504901405976559617\n \
  exp2 159\n \
  exp1 107\n \
  sign1 1\n \
  sign0 1\n"
#define PUBLIC_G "[7998725336653383203658644639673805448553730986337128386926545744008381384348409264866333582258561179132241508936069720871865895053632019929236743348039021, 1993938860438750843589842757968313427718259534664174282914852335272086243792497573680387148722647412680490224484736059954284097163105446004304579443902885]"
/*
PRIVATE Z and GAMMA
*/
#define PRIVATE_GAMMA "514443474460839782450589865266227244330811833490"
#define PRIVATE_Z "338255145738080587048962862431137545843138978550"


/* **********************************************************
   PRIVATE KEY STRUCT
   This struct stores a single users' group elements and
   their private key.  It also contains the recipients
   currently in their product (a bit-vector representation),
   their decryption product (excluding their group element),
   and their index number.
********************************************************** */
typedef struct single_priv_key_s {
  element_t g_i_gamma;
  element_t g_i;
  element_t decr_prod;
  int index;
}* priv_key_t;


/* **********************************************************
   GLOBAL BROADCAST PARAMS--
   Stores the:
   curve info--PUBLIC
   group elements--PUBLIC
   num-users-PUBLIC
*********************************************************  */
typedef struct global_broadcast_params_s {
  pairing_t pairing;
  element_t g;
  element_t *gs;
  element_t z;
  element_t gamma;
  int num_users;
}* global_broadcast_params_t;

/* **********************************************************
   BROADCAST SYSTEM stores:
   encryption product - can be public
   public key - public g^gamma
   priv key - private gamma
*********************************************************  */
typedef struct broadcast_system_s {
  element_t encr_prod;
  element_t pub_key;
  element_t priv_key;
}* broadcast_system_t;

/* **********************************************************
   CIPHERTEXT STRUCT
   Contains two group elements HDR C0 and HDR C1
*********************************************************  */
typedef struct ciphertext_s {
  element_t C0;
  element_t C1;
}* ct_t;

/* **********************************************************
   These functions free the memory associated with various
   structures.  Note that the pointer you pass in will not
   be freed--you must free it manually to prevent freeing
   stack memory.
********************************************************** */

void FreeCT(ct_t myct);
void FreeBCS(broadcast_system_t bcs);
void FreeGBP(global_broadcast_params_t gbp);
void FreePK(priv_key_t key);


/* **********************************************************
   Sets up a global broadcast system by generating all of
   the gs, the hs, and their inverses.  Chooses random alpha
   for the exponent.  num_users must be a multiple of 8.
*********************************************************  */
void setup_global_broadcast_params(global_broadcast_params_t *gbp,
				   char* gbp_headers);

void setup_global_broadcast_params2(global_broadcast_params_t *gbp, unsigned char* gbp_headers);

/* **********************************************************
   Stores the global broadcast system parameters to a file.
   WARNING: FILE WILL BE LARGE for large numbers of users
*********************************************************  */
void StoreParams(char *systemFileName,
		 global_broadcast_params_t gbp,
		 broadcast_system_t sys);


/* **********************************************************
   Loads the global broadcast system paramters from a file.
*********************************************************  */
void LoadParams(char *systemFileName,
		global_broadcast_params_t *gbp,
		broadcast_system_t *sys);


/* **********************************************************
   Stores a single private key to a file.  The pairing file
   should be distributed with the private key file.
**********************************************************  */
void StorePrivKey(char *keyFileName, priv_key_t mykey);


/* **********************************************************
   Loads a single private key into a private key structure.
   Should be done after loading the pairing file.
**********************************************************  */
void LoadPrivKey(char *keyFileName, priv_key_t *mykey,
		 global_broadcast_params_t gbp);


/* **********************************************************
   This function generates a broadcast key and a cipher-text
   header, once the encryption product has been calculated.
*********************************************************  */
void BroadcastKEM_using_product(global_broadcast_params_t gbp,
				int NS, ct_t myct, element_t key, element_t product, element_t t);

void revoke_users_using_product(global_broadcast_params_t gbs,
  int n_shared, int n_revoked, element_t prod, ct_t myct, element_t key, element_t t);

void share_users_using_product(global_broadcast_params_t gbp, int n_shared, int n_new, element_t prod, element_t C1, element_t t);

void get_key(global_broadcast_params_t gbp, ct_t cipher, element_t di, int id, int NS, element_t key);

#endif