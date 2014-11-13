#ifndef UTILS_H_
#define UTILS_H_

#include <pbc.h>

char *rand_string(char *str, size_t size);
void log_pbc_element(element_t e, char* message);
char* from_element_to_str(element_t e);
#endif