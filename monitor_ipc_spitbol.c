/*
 * monitor_ipc_spitbol.c — SPITBOL x64 LOAD()able IPC module for the 5-way monitor.
 *
 * Identical semantics to snobol4x/test/monitor/monitor_ipc.c (CSNOBOL4 ABI),
 * but uses SPITBOL's string block layout:
 *
 *   SPITBOL scblk: { word typ; word len; char str[]; }
 *   String arg N: args[N].a.i = (long)(scblk*); scblk->len = byte length; scblk->str = chars
 *
 * vs CSNOBOL4's:
 *   String arg N: args[N].a.i = (long)(descr_block*); block+64 = chars; block->v = len
 *
 * LOAD prototypes (same as CSNOBOL4 version):
 *   LOAD("MON_OPEN(STRING)STRING",        "./monitor_ipc_spitbol.so")
 *   LOAD("MON_SEND(STRING,STRING)STRING", "./monitor_ipc_spitbol.so")
 *   LOAD("MON_CLOSE()STRING",             "./monitor_ipc_spitbol.so")
 *
 * STRING return convention for SPITBOL callef():
 *   retval->v  = LDESCR_STR ('S')
 *   retval->a.i = (long)(char*) pointer to string bytes
 *   retval->f   = (char)length  [0..127 bytes, sufficient for paths/status]
 *
 * callef() in syslinux.c (B-233 fix) copies retval into ptscblk on LDESCR_STR.
 *
 * Build:
 *   gcc -shared -fPIC -O2 -Wall -o monitor_ipc_spitbol.so monitor_ipc_spitbol.c
 */

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>

/* -----------------------------------------------------------------------
 * ABI — SPITBOL x64 ldescr, empirically verified from syslinux.c B-232/B-233.
 * Matches struct ldescr in osint/syslinux.c.
 * ----------------------------------------------------------------------- */
typedef long      int_t;
typedef double    real_t;

struct ldescr {
    union { int_t i; real_t f; } a;
    char         f;      /* flags / string-length byte for return */
    unsigned int v;      /* type tag: 'I'=int, 'R'=real, 'S'=string */
};

/* SPITBOL scblk — string block layout from osint/spitblks.h */
struct spitblk_sc {
    long typ;   /* type word (b$scl) */
    long len;   /* string byte length */
    char str[]; /* string characters (NOT NUL-terminated) */
};

#define LOAD_PROTO  struct ldescr *retval, unsigned nargs, struct ldescr *args
#define LA_ALIST    LOAD_PROTO
typedef int lret_t;

#define LDESCR_INT  'I'
#define LDESCR_STR  'S'
#define TRUE  1
#define FALSE 0

/* Extract STRING arg N from SPITBOL ldescr array */
static inline struct spitblk_sc *_scblk(int n, struct ldescr *args) {
    return (struct spitblk_sc *)(uintptr_t)args[n].a.i;
}
static inline int _len(int n, struct ldescr *args) {
    struct spitblk_sc *sc = _scblk(n, args);
    return sc ? (int)sc->len : 0;
}
static inline const char *_ptr(int n, struct ldescr *args) {
    struct spitblk_sc *sc = _scblk(n, args);
    return sc ? sc->str : NULL;
}

/* Copy STRING arg N into NUL-terminated buf. Returns 0 ok, -1 overflow. */
static int copy_str_arg(int n, char *buf, int bufsz, struct ldescr *args) {
    int len       = _len(n, args);
    const char *p = _ptr(n, args);
    if(len < 0 || len >= bufsz) return -1;
    if(p && len > 0) memcpy(buf, p, (size_t)len);
    buf[len] = '\0';
    return 0;
}

/* STRING return: retval->v='S', retval->a.i=char* data, retval->f=(char)len */
#define RETSTR(CP, LEN) \
    do { retval->a.i = (int_t)(uintptr_t)(CP); \
         retval->f   = (char)(LEN); \
         retval->v   = LDESCR_STR; return TRUE; } while(0)

#define RETNULL \
    do { retval->a.i = 0; retval->f = 0; retval->v = LDESCR_STR; return TRUE; } while(0)

#define RETFAIL return FALSE

/* -----------------------------------------------------------------------
 * Module state
 * ----------------------------------------------------------------------- */
static int  mon_fd   = -1;
static char mon_path[4096];  /* keep path alive for RETSTR */

/* -----------------------------------------------------------------------
 * MON_OPEN(fifo_path) STRING
 * ----------------------------------------------------------------------- */
lret_t mon_open(LA_ALIST) {
    char path[4096];
    if(copy_str_arg(0, path, (int)sizeof(path), args) < 0) RETFAIL;
    if(!path[0]) RETFAIL;

    if(mon_fd >= 0) { close(mon_fd); mon_fd = -1; }

    mon_fd = open(path, O_WRONLY | O_NONBLOCK);
    if(mon_fd < 0) mon_fd = open(path, O_WRONLY);
    if(mon_fd < 0) RETFAIL;

    strncpy(mon_path, path, sizeof(mon_path) - 1);
    mon_path[sizeof(mon_path) - 1] = '\0';
    RETSTR(mon_path, (int)strlen(mon_path));
}

/* -----------------------------------------------------------------------
 * MON_SEND(kind, body) STRING
 * ----------------------------------------------------------------------- */
lret_t mon_send(LA_ALIST) {
    char kind[64];
    char body[3900];
    char line[4096];
    static char kind_copy[64];

    if(mon_fd < 0) RETNULL;

    if(copy_str_arg(0, kind, (int)sizeof(kind), args) < 0) RETFAIL;
    if(copy_str_arg(1, body, (int)sizeof(body), args) < 0) RETFAIL;

    int n = snprintf(line, sizeof(line), "%s %s\n", kind, body);
    if(n <= 0 || n >= (int)sizeof(line)) RETFAIL;

    ssize_t written = write(mon_fd, line, (size_t)n);
    if(written != (ssize_t)n) RETFAIL;

    strncpy(kind_copy, kind, sizeof(kind_copy) - 1);
    kind_copy[sizeof(kind_copy) - 1] = '\0';
    RETSTR(kind_copy, (int)strlen(kind_copy));
}

/* -----------------------------------------------------------------------
 * MON_CLOSE() STRING
 * ----------------------------------------------------------------------- */
lret_t mon_close(LA_ALIST) {
    if(mon_fd >= 0) { close(mon_fd); mon_fd = -1; }
    RETNULL;
}
