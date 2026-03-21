/*
 * libspl.c — minimal SpitbolCLib for M-X64-S2/S3/S4 LOAD/UNLOAD testing.
 *
 * Matches snobol4dotnet SpitbolCLib test fixture (LoadSpecTests.cs oracle).
 *
 * LOAD ABI: lret_t fn(struct descr *retval, unsigned nargs, struct descr *args)
 *   = int fn(LA_ALIST)
 * Empirically verified from monitor_ipc.c (B-229): BCDFLD=64, DESCR_SZ=16.
 *
 * Build:
 *   gcc -shared -fPIC -O2 -Wall -o libspl.so libspl.c
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* -----------------------------------------------------------------------
 * ABI — matches CSNOBOL4 2.3.3 x86-64 NO_BITFIELDS, verified empirically.
 * ----------------------------------------------------------------------- */
typedef long      int_t;
typedef double    real_t;

struct descr {
    union { int_t i; real_t f; } a;
    char         f;
    unsigned int v;
};

#define DESCR_SZ  ((int)sizeof(struct descr))   /* 16 */
#define BCDFLD    (4 * DESCR_SZ)                /* 64 */

#define LOAD_PROTO  struct descr *retval, unsigned nargs, struct descr *args
typedef int lret_t;
#define TRUE  1
#define FALSE 0

/* Arg accessors */
#define LA_INT(N)     (args[(N)].a.i)
#define LA_REAL(N)    (args[(N)].a.f)
#define _blkptr(N)    ((void *)(args[(N)].a.i))
#define LA_STR_LEN(N) (_blkptr(N) ? (int)((struct descr *)_blkptr(N))->v : 0)
#define LA_STR_PTR(N) (_blkptr(N) ? (const char *)_blkptr(N) + BCDFLD : NULL)

/* Return macros */
#define RETINT(x)  do { retval->a.i = (int_t)(x); retval->f = 0; retval->v = 'I'; return TRUE; } while(0)
#define RETFAIL    return FALSE
#define RETNULL    do { retval->a.i = 0; retval->f = 0; retval->v = 'S'; return TRUE; } while(0)


/* -----------------------------------------------------------------------
 * spl_add(INTEGER, INTEGER) INTEGER
 * Oracle: LoadSpecTests.cs — spl_add(3,4) == 7
 * ----------------------------------------------------------------------- */
lret_t
spl_add(LOAD_PROTO)
{
    int_t a = LA_INT(0);
    int_t b = LA_INT(1);
    RETINT(a + b);
}

/* -----------------------------------------------------------------------
 * spl_strlen(STRING) INTEGER
 * Oracle: LoadSpecTests.cs — spl_strlen("hello") == 5
 * ----------------------------------------------------------------------- */
lret_t
spl_strlen(LOAD_PROTO)
{
    int len = LA_STR_LEN(0);
    RETINT(len);
}

