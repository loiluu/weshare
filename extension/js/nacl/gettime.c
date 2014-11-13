#include <sys/time.h>
#include <stdio.h>
#include "gettime.h"

struct timeval t1, t2;
double elapsedtime;

void start_t() 
{
 gettimeofday(&t1, NULL);
}

void stop_t(const char* p)
{
 gettimeofday(&t2, NULL);
 elapsedtime = (t2.tv_sec - t1.tv_sec) * 1000000.0;      // sec to us
 elapsedtime += (t2.tv_usec - t1.tv_usec) ;   // us
 fprintf(stderr, "%s \t %lf micro sec\n", p, elapsedtime);
 }
