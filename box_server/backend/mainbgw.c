#include <string.h>
#include "bgw.h"

int main(int argc, char const *argv[])
{
  if (argc > 1){
    if (argc == 3 && !strcmp(argv[1], "setup")){ 
      global_broadcast_params_t gbs;
      //Global Setup
      int n = atoi(argv[2]);      
      setup_global_broadcast_params(&gbs, n);
      
      FILE * file;
      file = fopen("/tmp/gbs2.txt" , "w");
      int i = 0, t;

      //print n
      fprintf(file, "%d\n", n);  
      //print g
      fprintf(file, "%s\n", PUBLIC_G);
      //print gs[i]
      for (i=0; i < 2*n; i++){
        if (i==n)
          continue;
        char* s = (char*) malloc(MAX_ELEMENT_LEN);        
        t = element_snprint(s, MAX_ELEMENT_LEN, gbs->gs[i]);
        fprintf(file, "%s\n", s);
        free(s);
      }
      fclose(file);
      store_gbp_params("/tmp/gbs.txt", gbs);
      FreeGBP(gbs);
      return 0;
    }
    else if (argc == 2 && !strcmp(argv[1], "restore")){ 
      global_broadcast_params_t gbs;
      //Global Setup      
      restore_global_broadcast_params2(&gbs);      
      return 0;
    }
    else if (argc == 3 && !strcmp(argv[1], "revoke")){       
      update_after_revocation(argv[2]);      
      return 0;
    }    
  }
  fprintf(stderr, "Run with ./mainbgw [task] [Other parameter]\n");
  fprintf(stderr, "For example ./mainbgw setup 16\n");

  return 1;
}