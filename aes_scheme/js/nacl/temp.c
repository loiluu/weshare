#include "string.h"
#include "stdlib.h"
#include "stdio.h"
#include "openssl_aes.h"

int main(int argc, char const *argv[])
{  
  char data[] = "12312312312312300123123001231231200";
  printf("%s\n", do_aes(data));
  return 0;
}