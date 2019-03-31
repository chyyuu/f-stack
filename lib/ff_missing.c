#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>

#define NS_PER_S 1000

uint64_t
ff_get_tsc_ns()
{
//    uint64_t cur_tsc = rte_rdtsc();
//    uint64_t hz = rte_get_tsc_hz();
    uint64_t cur_tsc = 0;
    uint64_t hz = 0;
    return ((double)cur_tsc/(double)hz) * NS_PER_S;
}