/*
 * monitor_ipc_bin_spl.c — SPITBOL x64 LOAD()able binary sync-step IPC module.
 *
 * Wire protocol: see scripts/monitor/monitor_wire.h (one4all repo).  All
 * records are pure binary; no string conversion happens on the runtime side.
 * The C code reads the descriptor's type tag and raw bytes directly from
 * the SCBLK / ICBLK / RCBLK structures.
 *
 * Two FIFOs per participant + one names sidecar:
 *   MONITOR_READY_PIPE     — runtime writes binary records, controller reads
 *   MONITOR_GO_PIPE        — controller writes 1-byte ack ('G' or 'S')
 *   MONITOR_NAMES_FILE     — names table, one name per line, read at MON_OPEN
 *
 * SPITBOL LOAD() symbol lookup is verbatim from the prototype string —
 * provide both UPPERCASE (canonical for SN-30 build) and lowercase aliases
 * to match SPITBOL's traditional callef() convention.
 *
 *   LOAD('MON_OPEN(STRING,STRING,STRING)INTEGER',  './monitor_ipc_bin_spl.so')
 *   LOAD('MON_PUT_VALUE(STRING,STRING)INTEGER',    './monitor_ipc_bin_spl.so')
 *   LOAD('MON_PUT_CALL(STRING)INTEGER',            './monitor_ipc_bin_spl.so')
 *   LOAD('MON_PUT_RETURN(STRING,STRING)INTEGER',   './monitor_ipc_bin_spl.so')
 *   LOAD('MON_CLOSE()INTEGER',                     './monitor_ipc_bin_spl.so')
 *
 * Build:
 *   gcc -shared -fPIC -O2 -Wall -o monitor_ipc_bin_spl.so monitor_ipc_bin_spl.c
 */

#include "monitor_wire.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <sys/uio.h>

/*============================================================================
 * SPITBOL x64 ABI — ldescr + spitblk_sc per osint/syslinux.c.
 *==========================================================================*/
typedef long   int_t;
typedef double real_t;

struct ldescr {
    union { int_t i; real_t f; } a;
    char         f;
    unsigned int v;
};

/* SPITBOL string control block — typ + len header, then bytes. */
struct spitblk_sc {
    long typ;
    long len;
    char str[];
};

#define LOAD_PROTO  struct ldescr *retval, unsigned nargs, struct ldescr *args
#define LA_ALIST    LOAD_PROTO
typedef int lret_t;

#define TRUE  1
#define FALSE 0

/* SPITBOL type tag codes — ASCII characters per syslinux.c.
 *   'S' = STRING       'I' = INTEGER     'R' = REAL
 *   'P' = PATTERN      'N' = NAME        'A' = ARRAY
 *   'T' = TABLE        'C' = CODE        'E' = EXPRESSION/EXTERNAL
 *
 * Some SPITBOL versions use 0 for NULL strings; tolerate that.
 */
#define SPL_T_STRING    'S'
#define SPL_T_INTEGER   'I'
#define SPL_T_REAL      'R'
#define SPL_T_PATTERN   'P'
#define SPL_T_NAME      'N'
#define SPL_T_ARRAY     'A'
#define SPL_T_TABLE     'T'
#define SPL_T_CODE      'C'
#define SPL_T_EXPR      'E'

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

#define RETINT(N)   do { retval->a.i = (int_t)(N); retval->f = 0; retval->v = SPL_T_INTEGER; return TRUE; } while (0)
#define RETFAIL     return FALSE

static int copy_str_arg(int n, char *buf, int bufsz, struct ldescr *args) {
    int len = _slen(n, args);
    const char *ptr = _sptr(n, args);
    if (len < 0 || len >= bufsz) return -1;
    if (ptr && len > 0) memcpy(buf, ptr, len);
    buf[len] = '\0';
    return 0;
}

/*============================================================================
 * Module state.
 *==========================================================================*/
static int    g_ready_fd  = -1;
static int    g_go_fd     = -1;
static char **g_names     = NULL;
static int   *g_name_lens = NULL;
static int    g_n_names   = 0;

/*============================================================================
 * Names file load — identical to CSN version.
 *==========================================================================*/
static int load_names_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    int   cap     = 64;
    char **names  = (char **)malloc(cap * sizeof(char *));
    int   *lens   = (int  *)malloc(cap * sizeof(int));
    if (!names || !lens) { fclose(f); free(names); free(lens); return -1; }

    int n = 0;
    char *line = NULL; size_t lcap = 0;
    ssize_t got;
    while ((got = getline(&line, &lcap, f)) >= 0) {
        if (got > 0 && line[got-1] == '\n') { line[got-1] = '\0'; got--; }
        if (got > 0 && line[got-1] == '\r') { line[got-1] = '\0'; got--; }
        if (n == cap) {
            cap *= 2;
            names = (char **)realloc(names, cap * sizeof(char *));
            lens  = (int  *)realloc(lens,  cap * sizeof(int));
            if (!names || !lens) { fclose(f); free(line); return -1; }
        }
        char *copy = (char *)malloc((size_t)got + 1);
        if (!copy) { fclose(f); free(line); return -1; }
        memcpy(copy, line, (size_t)got + 1);
        names[n] = copy;
        lens[n]  = (int)got;
        n++;
    }
    free(line);
    fclose(f);

    g_names     = names;
    g_name_lens = lens;
    g_n_names   = n;
    return 0;
}

static uint32_t lookup_name_id(const char *p, int len) {
    if (!g_names) return MW_NAME_ID_NONE;
    for (int i = 0; i < g_n_names; i++) {
        if (g_name_lens[i] == len && memcmp(g_names[i], p, (size_t)len) == 0)
            return (uint32_t)i;
    }
    return MW_NAME_ID_NONE;
}

/*============================================================================
 * Type tag mapping: SPITBOL ASCII tag → wire type code.
 *==========================================================================*/
static uint8_t spl_tag_to_wire(unsigned int v) {
    switch (v) {
        case SPL_T_STRING:  return MWT_STRING;
        case SPL_T_INTEGER: return MWT_INTEGER;
        case SPL_T_REAL:    return MWT_REAL;
        case SPL_T_PATTERN: return MWT_PATTERN;
        case SPL_T_NAME:    return MWT_NAME;
        case SPL_T_ARRAY:   return MWT_ARRAY;
        case SPL_T_TABLE:   return MWT_TABLE;
        case SPL_T_CODE:    return MWT_CODE;
        case SPL_T_EXPR:    return MWT_EXPRESSION;
        case 0:             return MWT_NULL;
        default:            return MWT_UNKNOWN;
    }
}

/*============================================================================
 * Block-and-ack: returns 1 on 'G', 0 on 'S' or error.
 *==========================================================================*/
static int wait_ack(void) {
    if (g_go_fd < 0) return 0;
    char ack;
    ssize_t r = read(g_go_fd, &ack, 1);
    if (r != 1) return 0;
    return (ack != 'S');
}

/*============================================================================
 * Emit record: header + value bytes, then block on ack.
 *==========================================================================*/
static int emit_record(uint32_t kind, uint32_t name_id, uint8_t type,
                       const void *value, uint32_t value_len)
{
    if (g_ready_fd < 0) return 0;
    unsigned char hdr[MW_HDR_BYTES];
    mw_pack_hdr(hdr, kind, name_id, type, value_len);

    struct iovec iov[2];
    int niov = 1;
    iov[0].iov_base = hdr;
    iov[0].iov_len  = MW_HDR_BYTES;
    if (value_len > 0 && value) {
        iov[1].iov_base = (void *)value;
        iov[1].iov_len  = (size_t)value_len;
        niov = 2;
    }

    ssize_t total = (ssize_t)MW_HDR_BYTES + (ssize_t)value_len;
    ssize_t got   = writev(g_ready_fd, iov, niov);
    if (got != total) return 0;
    return wait_ack();
}

/*============================================================================
 * Inspect arg n and emit a record with its raw bytes.
 *==========================================================================*/
static int emit_value(uint32_t kind, uint32_t name_id, struct ldescr *args, int idx)
{
    unsigned int v = args[idx].v;
    uint8_t type   = spl_tag_to_wire(v);

    const void *vp  = NULL;
    uint32_t    vlen = 0;
    int_t  i_buf;
    real_t r_buf;

    switch (type) {
        case MWT_STRING:
        case MWT_NAME:
            vp   = _sptr(idx, args);
            vlen = (uint32_t)_slen(idx, args);
            if (vlen == 0) vp = NULL;
            break;
        case MWT_INTEGER: {
            int_t iv = args[idx].a.i;
            unsigned char *p = (unsigned char *)&i_buf;
            for (int k = 0; k < 8; k++) p[k] = (unsigned char)((iv >> (k*8)) & 0xff);
            vp = &i_buf; vlen = 8;
            break;
        }
        case MWT_REAL: {
            real_t rv = args[idx].a.f;
            memcpy(&r_buf, &rv, sizeof(r_buf));
            vp = &r_buf; vlen = 8;
            break;
        }
        default:
            break;
    }
    return emit_record(kind, name_id, type, vp, vlen);
}

/*============================================================================
 * Lowercase entry points (callef() convention).
 *==========================================================================*/
lret_t mon_open(LA_ALIST) {
    char ready_path[4096];
    char go_path[4096];
    char names_path[4096];

    (void)nargs;
    if (copy_str_arg(0, ready_path, sizeof(ready_path), args) < 0) RETFAIL;
    if (copy_str_arg(1, go_path,    sizeof(go_path),    args) < 0) RETFAIL;
    if (copy_str_arg(2, names_path, sizeof(names_path), args) < 0) RETFAIL;
    if (!ready_path[0] || !go_path[0] || !names_path[0]) RETFAIL;

    if (g_ready_fd >= 0) { close(g_ready_fd); g_ready_fd = -1; }
    if (g_go_fd    >= 0) { close(g_go_fd);    g_go_fd    = -1; }
    if (g_names) {
        for (int i = 0; i < g_n_names; i++) free(g_names[i]);
        free(g_names); free(g_name_lens);
        g_names = NULL; g_name_lens = NULL; g_n_names = 0;
    }

    if (load_names_file(names_path) < 0) RETFAIL;

    g_ready_fd = open(ready_path, O_WRONLY | O_NONBLOCK);
    if (g_ready_fd < 0) g_ready_fd = open(ready_path, O_WRONLY);
    if (g_ready_fd < 0) RETFAIL;

    g_go_fd = open(go_path, O_RDONLY | O_NONBLOCK);
    if (g_go_fd < 0) { close(g_ready_fd); g_ready_fd = -1; RETFAIL; }
    { int fl = fcntl(g_go_fd, F_GETFL);
      fcntl(g_go_fd, F_SETFL, fl & ~O_NONBLOCK); }

    RETINT(0);
}

lret_t mon_put_value(LA_ALIST) {
    (void)nargs;
    int    nlen = _slen(0, args);
    const char *nptr = _sptr(0, args);
    if (!nptr) RETFAIL;

    uint32_t name_id = lookup_name_id(nptr, nlen);
    if (name_id == MW_NAME_ID_NONE) RETFAIL;

    if (!emit_value(MWK_VALUE, name_id, args, 1)) RETFAIL;
    RETINT(0);
}

lret_t mon_put_call(LA_ALIST) {
    (void)nargs;
    int    nlen = _slen(0, args);
    const char *nptr = _sptr(0, args);
    if (!nptr) RETFAIL;

    uint32_t name_id = lookup_name_id(nptr, nlen);
    if (name_id == MW_NAME_ID_NONE) RETFAIL;

    if (!emit_record(MWK_CALL, name_id, MWT_NULL, NULL, 0)) RETFAIL;
    RETINT(0);
}

lret_t mon_put_return(LA_ALIST) {
    (void)nargs;
    int    nlen = _slen(0, args);
    const char *nptr = _sptr(0, args);
    if (!nptr) RETFAIL;

    uint32_t name_id = lookup_name_id(nptr, nlen);
    if (name_id == MW_NAME_ID_NONE) RETFAIL;

    if (!emit_value(MWK_RETURN, name_id, args, 1)) RETFAIL;
    RETINT(0);
}

lret_t mon_close(LA_ALIST) {
    (void)nargs; (void)args;
    if (g_ready_fd >= 0) {
        emit_record(MWK_END, MW_NAME_ID_NONE, MWT_NULL, NULL, 0);
        close(g_ready_fd); g_ready_fd = -1;
    }
    if (g_go_fd >= 0) { close(g_go_fd); g_go_fd = -1; }
    if (g_names) {
        for (int i = 0; i < g_n_names; i++) free(g_names[i]);
        free(g_names); free(g_name_lens);
        g_names = NULL; g_name_lens = NULL; g_n_names = 0;
    }
    RETINT(0);
}

/*============================================================================
 * UPPERCASE aliases — SPITBOL LOAD() looks up symbol verbatim from prototype.
 *==========================================================================*/
lret_t MON_OPEN(LA_ALIST)       { return mon_open(retval, nargs, args); }
lret_t MON_PUT_VALUE(LA_ALIST)  { return mon_put_value(retval, nargs, args); }
lret_t MON_PUT_CALL(LA_ALIST)   { return mon_put_call(retval, nargs, args); }
lret_t MON_PUT_RETURN(LA_ALIST) { return mon_put_return(retval, nargs, args); }
lret_t MON_CLOSE(LA_ALIST)      { return mon_close(retval, nargs, args); }
