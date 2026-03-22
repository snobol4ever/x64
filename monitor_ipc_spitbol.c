/*
 * monitor_ipc_spitbol.c — SPITBOL x64 LOAD()able sync-step IPC module.
 *
 * Wire protocol — RS/US delimiters (ASCII 0x1E / 0x1F):
 *   KIND \x1E name \x1F value \x1E
 *   \x1E (RS) = record terminator; \x1F (US) = name/value separator
 *   Newlines and all bytes in values pass through unescaped.
 *
 * Two named pipes per participant:
 *   MONITOR_READY_PIPE — participant writes events, controller reads
 *   MONITOR_GO_PIPE    — controller writes GO/STOP, participant reads
 *
 * Barrier protocol:
 *   1. participant writes record to ready pipe
 *   2. participant blocks read() on go pipe
 *   3. controller reads one record from all 5 ready pipes
 *   4. consensus applied; controller writes 'G' or 'S' to each go pipe
 *   5. 'G' → mon_send returns; 'S' → mon_send returns FAIL → :F(END)
 *
 * SPITBOL function names are lowercase (callef() convention).
 * LOAD prototypes:
 *   LOAD("MON_OPEN(STRING,STRING)STRING",  "./monitor_ipc_spitbol.so")
 *   LOAD("MON_SEND(STRING,STRING)STRING",  "./monitor_ipc_spitbol.so")
 *   LOAD("MON_CLOSE()STRING",              "./monitor_ipc_spitbol.so")
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
#include <sys/uio.h>

#define RS "\x1e"
#define US "\x1f"

/* SPITBOL x64 ABI — ldescr and scblk from osint/syslinux.c */
typedef long   int_t;
typedef double real_t;

struct ldescr {
    union { int_t i; real_t f; } a;
    char         f;
    unsigned int v;
};

struct spitblk_sc {
    long typ;
    long len;
    char str[];
};

#define LOAD_PROTO  struct ldescr *retval, unsigned nargs, struct ldescr *args
#define LA_ALIST    LOAD_PROTO
typedef int lret_t;

#define LDESCR_STR  'S'
#define TRUE  1
#define FALSE 0

static inline struct spitblk_sc *_scblk(int n, struct ldescr *args) {
    return (struct spitblk_sc *)(uintptr_t)args[n].a.i;
}
static inline int _slen(int n, struct ldescr *args) {
    struct spitblk_sc *sc = _scblk(n, args);
    return sc ? (int)sc->len : 0;
}
static inline const char *_sptr(int n, struct ldescr *args) {
    struct spitblk_sc *sc = _scblk(n, args);
    return sc ? sc->str : NULL;
}

#define RETSTR(CP, LEN) \
    do { retval->a.i = (int_t)(uintptr_t)(CP); \
         retval->f   = (char)(LEN); \
         retval->v   = LDESCR_STR; return TRUE; } while(0)
#define RETNULL \
    do { retval->a.i = 0; retval->f = 0; retval->v = LDESCR_STR; return TRUE; } while(0)
#define RETFAIL return FALSE

/* Module state */
static int  mon_ready_fd = -1;
static int  mon_go_fd    = -1;
static char mon_ready_path[4096];

/*
 * mon_open(ready_pipe_path, go_pipe_path) STRING
 */
lret_t mon_open(LA_ALIST) {
    char ready_path[4096], go_path[4096];
    int rlen = _slen(0, args); const char *rptr = _sptr(0, args);
    int glen = _slen(1, args); const char *gptr = _sptr(1, args);

    if (rlen <= 0 || rlen >= (int)sizeof(ready_path)) RETFAIL;
    if (glen <= 0 || glen >= (int)sizeof(go_path))    RETFAIL;
    memcpy(ready_path, rptr, rlen); ready_path[rlen] = '\0';
    memcpy(go_path,    gptr, glen); go_path[glen]    = '\0';

    if (mon_ready_fd >= 0) { close(mon_ready_fd); mon_ready_fd = -1; }
    if (mon_go_fd    >= 0) { close(mon_go_fd);    mon_go_fd    = -1; }

    /* Ready pipe: write end */
    mon_ready_fd = open(ready_path, O_WRONLY | O_NONBLOCK);
    if (mon_ready_fd < 0) mon_ready_fd = open(ready_path, O_WRONLY);
    if (mon_ready_fd < 0) RETFAIL;

    /* Go pipe: read end — O_NONBLOCK to avoid deadlock, then clear */
    mon_go_fd = open(go_path, O_RDONLY | O_NONBLOCK);
    if (mon_go_fd < 0) { close(mon_ready_fd); mon_ready_fd = -1; RETFAIL; }
    { int fl = fcntl(mon_go_fd, F_GETFL);
      fcntl(mon_go_fd, F_SETFL, fl & ~O_NONBLOCK); }

    strncpy(mon_ready_path, ready_path, sizeof(mon_ready_path) - 1);
    RETSTR(mon_ready_path, rlen);
}

/*
 * mon_send(kind, body) STRING   — body = name US value
 * Writes KIND RS body RS to ready pipe, then blocks on go pipe for 'G'/'S'.
 */
lret_t mon_send(LA_ALIST) {
    if (mon_ready_fd < 0) RETNULL;

    const char *kptr = _sptr(0, args); int klen = _slen(0, args);
    const char *bptr = _sptr(1, args); int blen = _slen(1, args);
    if (!kptr) { kptr = ""; klen = 0; }
    if (!bptr) { bptr = ""; blen = 0; }

    struct iovec iov[4];
    iov[0].iov_base = (void*)kptr; iov[0].iov_len = (size_t)klen;
    iov[1].iov_base = RS;          iov[1].iov_len = 1;
    iov[2].iov_base = (void*)bptr; iov[2].iov_len = (size_t)blen;
    iov[3].iov_base = RS;          iov[3].iov_len = 1;
    ssize_t total = (ssize_t)(klen + 1 + blen + 1);
    if (writev(mon_ready_fd, iov, 4) != total) RETFAIL;

    if (mon_go_fd < 0) RETFAIL;
    char ack[1];
    if (read(mon_go_fd, ack, 1) != 1) RETFAIL;
    if (ack[0] == 'S') RETFAIL;

    /* Return kind as static buf — SPITBOL RETSTR needs stable pointer */
    static char kind_buf[64];
    int kl = klen < 63 ? klen : 63;
    memcpy(kind_buf, kptr, kl); kind_buf[kl] = '\0';
    RETSTR(kind_buf, kl);
}

/*
 * mon_close() STRING
 */
lret_t mon_close(LA_ALIST) {
    if (mon_ready_fd >= 0) { close(mon_ready_fd); mon_ready_fd = -1; }
    if (mon_go_fd    >= 0) { close(mon_go_fd);    mon_go_fd    = -1; }
    RETNULL;
}

/* Uppercase aliases — SPITBOL LOAD() passes function name verbatim from
 * the prototype string; no case conversion. LOAD('MON_OPEN(...)') → dlsym "MON_OPEN". */
lret_t MON_OPEN(LA_ALIST)  { return mon_open(retval, nargs, args); }
lret_t MON_SEND(LA_ALIST)  { return mon_send(retval, nargs, args); }
lret_t MON_CLOSE(LA_ALIST) { return mon_close(retval, nargs, args); }
