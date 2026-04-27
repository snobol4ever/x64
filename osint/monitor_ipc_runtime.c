/*
 * monitor_ipc_runtime.c — SPITBOL x64 statically-linked sync-step monitor bridge.
 *
 * Wire protocol: see ../../one4all/scripts/monitor/monitor_wire.h (constants
 * inlined below to avoid dep on one4all tree).  Identical wire protocol to
 * csnobol4/monitor_ipc_runtime.c — lets a single controller compare the two
 * runtimes byte-for-byte.
 *
 * Design (SN-26-spl-bridge-a/-b, 2026-04-27):
 *   - Statically linked into sbl (object listed in osint Makefile).
 *   - No SNOBOL4 LOAD() involvement.  zysmv/zysmc/zysmr are the C-side
 *     implementations of three new MINIMAL externs sysmv/sysmc/sysmr,
 *     called from b_vrs / bpf09 / rtn03 fire-points in sbl.min.
 *   - Lazy init on first emit: reads MONITOR_READY_PIPE / MONITOR_GO_PIPE.
 *     If unset, emits become silent no-ops.
 *   - Auto-interns names into a growing in-memory table (no static
 *     MONITOR_NAMES_FILE input).  At process exit (atexit handler), the
 *     table is dumped to MONITOR_NAMES_OUT — matches the per-participant
 *     names sidecar architecture used by csnobol4 + scrip.
 *   - End record (MWK_END) emitted at exit before the names sidecar is
 *     written, so the controller sees a clean wire close.
 *
 * SPITBOL ABI specifics (differ from CSNOBOL4):
 *   - Variable identity is held in a vrblk (struct vrblk in spitblks.h).
 *     Name length at vrlen field; characters at vrchs[] flexible array.
 *     System variables have vrlen=0 — name lives in svblk via vrsvp; we
 *     report system variables under a synthetic name ("&KEYWORD" style)
 *     reconstructed from the variable kind, but for now report empty.
 *   - Values are pointers to typed blocks: scblk / icblk / rcblk / nmblk /
 *     ptblk / atblk / tbblk / efblk / cdblk.  First word of each block is
 *     a "type code pointer" comparing against b_scl / b_icl / b_rcl etc.
 *     We dereference and compare against the externs from osint.h.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/uio.h>
#include <sys/stat.h>

#include "port.h"

/*============================================================================
 * Wire protocol — inline copy of monitor_wire.h to avoid dep on one4all tree.
 *==========================================================================*/
#define MWK_VALUE       1u
#define MWK_CALL        2u
#define MWK_RETURN      3u
#define MWK_END         4u
#define MWK_LABEL       5u

#define MWT_NULL        0
#define MWT_STRING      1
#define MWT_INTEGER     2
#define MWT_REAL        3
#define MWT_NAME        4
#define MWT_PATTERN     5
#define MWT_EXPRESSION  6
#define MWT_ARRAY       7
#define MWT_TABLE       8
#define MWT_CODE        9
#define MWT_DATA       10
#define MWT_FILE       11
#define MWT_UNKNOWN   255

#define MW_HDR_BYTES    13
#define MW_NAME_ID_NONE 0xffffffffu

static inline void mw_pack_hdr(unsigned char hdr[MW_HDR_BYTES],
                               uint32_t kind, uint32_t name_id,
                               uint8_t  type, uint32_t value_len)
{
    hdr[0]  = (unsigned char)( kind        & 0xff);
    hdr[1]  = (unsigned char)((kind  >>  8)& 0xff);
    hdr[2]  = (unsigned char)((kind  >> 16)& 0xff);
    hdr[3]  = (unsigned char)((kind  >> 24)& 0xff);
    hdr[4]  = (unsigned char)( name_id      & 0xff);
    hdr[5]  = (unsigned char)((name_id>>  8)& 0xff);
    hdr[6]  = (unsigned char)((name_id>> 16)& 0xff);
    hdr[7]  = (unsigned char)((name_id>> 24)& 0xff);
    hdr[8]  = type;
    hdr[9]  = (unsigned char)( value_len      & 0xff);
    hdr[10] = (unsigned char)((value_len>>  8)& 0xff);
    hdr[11] = (unsigned char)((value_len>> 16)& 0xff);
    hdr[12] = (unsigned char)((value_len>> 24)& 0xff);
}

/*============================================================================
 * Module state.
 *==========================================================================*/
static int   g_ready_fd       = -1;
static int   g_go_fd          = -1;
static int   g_init_attempted = 0;
static int   g_init_ok        = 0;
static int   g_atexit_done    = 0;

static char    **g_names      = NULL;
static int     *g_name_lens   = NULL;
static int      g_n_names     = 0;
static int      g_names_cap   = 0;

static char    *g_names_out_path = NULL;

/*============================================================================
 * atexit: emit MWK_END and dump names sidecar.
 *==========================================================================*/
static void emit_record_raw(uint32_t kind, uint32_t name_id, uint8_t type,
                            const void *value, uint32_t value_len);

static void monitor_atexit(void) {
    if (g_atexit_done) return;
    g_atexit_done = 1;

    if (g_init_ok && g_ready_fd >= 0) {
        emit_record_raw(MWK_END, MW_NAME_ID_NONE, MWT_NULL, NULL, 0);
    }
    if (g_names_out_path && g_names) {
        FILE *f = fopen(g_names_out_path, "w");
        if (f) {
            for (int i = 0; i < g_n_names; i++) {
                fwrite(g_names[i], 1, (size_t)g_name_lens[i], f);
                fputc('\n', f);
            }
            fclose(f);
        }
    }
    if (g_ready_fd >= 0) { close(g_ready_fd); g_ready_fd = -1; }
    if (g_go_fd    >= 0) { close(g_go_fd);    g_go_fd    = -1; }
}

/*============================================================================
 * Lazy init.  Returns 1 on success, 0 if env vars unset / FIFOs unopenable.
 *==========================================================================*/
static int monitor_init(void) {
    if (g_init_attempted) return g_init_ok;
    g_init_attempted = 1;

    const char *ready_path = getenv("MONITOR_READY_PIPE");
    const char *go_path    = getenv("MONITOR_GO_PIPE");
    const char *names_path = getenv("MONITOR_NAMES_OUT");
    if (!ready_path || !*ready_path) return 0;
    if (!go_path    || !*go_path)    return 0;

    int rfd = open(ready_path, O_WRONLY | O_NONBLOCK);
    if (rfd < 0) rfd = open(ready_path, O_WRONLY);
    if (rfd < 0) return 0;
    /* clear non-blocking flag if set */
    int rfl = fcntl(rfd, F_GETFL, 0);
    if (rfl >= 0) fcntl(rfd, F_SETFL, rfl & ~O_NONBLOCK);

    int gfd = open(go_path, O_RDONLY);
    if (gfd < 0) { close(rfd); return 0; }

    g_ready_fd = rfd;
    g_go_fd    = gfd;
    if (names_path && *names_path) {
        size_t n = strlen(names_path);
        g_names_out_path = (char *)malloc(n + 1);
        if (g_names_out_path) memcpy(g_names_out_path, names_path, n + 1);
    }
    g_init_ok = 1;
    atexit(monitor_atexit);
    return 1;
}

/*============================================================================
 * Name interning — linear scan, append on miss.  Returns name_id.
 *==========================================================================*/
static uint32_t intern_name(const char *p, int len) {
    if (!p || len < 0) return MW_NAME_ID_NONE;
    for (int i = 0; i < g_n_names; i++) {
        if (g_name_lens[i] == len &&
            (len == 0 || memcmp(g_names[i], p, (size_t)len) == 0))
            return (uint32_t)i;
    }
    if (g_n_names == g_names_cap) {
        int nc = g_names_cap ? g_names_cap * 2 : 64;
        char **nn = (char **)realloc(g_names,    nc * sizeof(char *));
        int   *nl = (int  *)realloc(g_name_lens, nc * sizeof(int));
        if (!nn || !nl) { free(nn); free(nl); return MW_NAME_ID_NONE; }
        g_names      = nn;
        g_name_lens  = nl;
        g_names_cap  = nc;
    }
    char *copy = (char *)malloc((size_t)len + 1);
    if (!copy) return MW_NAME_ID_NONE;
    if (len > 0) memcpy(copy, p, (size_t)len);
    copy[len] = '\0';
    g_names[g_n_names]     = copy;
    g_name_lens[g_n_names] = len;
    return (uint32_t)g_n_names++;
}

/*============================================================================
 * Wait for ack.  Returns 1 on 'G' (or anything not 'S'), 0 on 'S'/EOF.
 *==========================================================================*/
static int wait_ack(void) {
    if (g_go_fd < 0) return 0;
    char ack;
    ssize_t r = read(g_go_fd, &ack, 1);
    if (r != 1) return 0;
    return (ack != 'S');
}

/*============================================================================
 * Internal: emit a record (header + optional value bytes), then block on ack.
 *==========================================================================*/
static void emit_record_raw(uint32_t kind, uint32_t name_id, uint8_t type,
                            const void *value, uint32_t value_len)
{
    if (g_ready_fd < 0) return;

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
    if (got != total) return;
    if (kind != MWK_END) (void)wait_ack();
}

/*============================================================================
 * SPITBOL block discriminator.
 *
 * Every value-block in SPITBOL has a "type word" as its first word — a
 * pointer to a routine like b_scl / b_icl / b_rcl / b_xnt / b_xrt.  We
 * compare against the externs declared in osint.h.  Only a handful are
 * publicly exported; the rest fall through to MWT_UNKNOWN, which is fine
 * for a pure-observer protocol.
 *==========================================================================*/

/* Type discrimination on the value-block.  The "value" coming through
 * b_vrs's stack top is a pointer to one of these typed blocks. */
static uint8_t spl_block_to_wire(const void *v, const void **chars_out,
                                  uint32_t *vlen_out, word *iv_out,
                                  double *rv_out)
{
    *chars_out = NULL;
    *vlen_out  = 0;
    if (!v) return MWT_NULL;

    /* Read the type-word at offset 0. */
    word typ = ((const word *)v)[0];

    if (typ == TYPE_SCL) {
        const struct scblk *s = (const struct scblk *)v;
        *chars_out = s->str;
        *vlen_out  = (uint32_t)s->len;
        if (*vlen_out == 0) *chars_out = NULL;
        return MWT_STRING;
    }
    if (typ == TYPE_ICL) {
        const struct icblk *i = (const struct icblk *)v;
        *iv_out = (word)i->val;
        return MWT_INTEGER;
    }
    if (typ == TYPE_RCL) {
        const struct rcblk *r = (const struct rcblk *)v;
        *rv_out = r->rcval;
        return MWT_REAL;
    }
    /* No public extern for nmblk, ptblk, atblk, tbblk, cdblk, efblk —
     * report UNKNOWN so the wire still records *something*.  Future
     * work: export their b_xxx symbols or compare via TYPE_XNT/XRT. */
    return MWT_UNKNOWN;
}

/*============================================================================
 * Extract name from a vrblk.
 *
 * For natural variables, vrlen > 0 and vrchs[] holds the name (LJRZ).
 * For system variables, vrlen == 0 and vrsvp points to an svblk; we
 * report empty string — caller can synthesize the keyword name from
 * context if desired.
 *==========================================================================*/
static int spl_vrblk_name(const struct vrblk *vr, const char **np, int *nl) {
    if (!vr) { *np = ""; *nl = 0; return 0; }
    word len = vr->vrlen;
    if (len <= 0 || len > 255) {
        *np = "";
        *nl = 0;
        return 1;
    }
    /* Validate name as printable ASCII identifier bytes (0x20..0x7e).
     * For asign/asinp fire-points (SN-26-bridge-coverage-b), array-element
     * and table-slot stores reach this code with a fake vrblk synthesized
     * from xl - vrsto_offset where xl is mid-arblk/mid-tbblk.  vrlen then
     * reads whatever the previous slot held; could be a positive integer.
     * Mirrors CSN's lvalue_name_id() — fall through to caller's <lval>
     * sentinel on validation failure. */
    const char *p = vr->vrchs;
    for (int i = 0; i < (int)len; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c < 0x20 || c >= 0x7f) {
            *np = "";
            *nl = 0;
            return 1;
        }
    }
    *np = p;
    *nl = (int)len;
    return 1;
}

/*============================================================================
 * Public C entry points — called from sbl.min via int.asm syscall thunks.
 *
 * MINIMAL register conventions (after syscall_init has saved registers):
 *   reg_xr ← MINIMAL xr at call site
 *   reg_xl ← MINIMAL xl at call site
 *   reg_wa, reg_wb, reg_wc ← scratch regs
 *
 * Each zys* function returns -1 (negative) for "normal return" — MINIMAL
 * resumes immediately past the jsr.  See syscall_exit in int.asm.
 *==========================================================================*/

/*  zysmv — VALUE event from b_vrs (universal store path).
 *
 *  Call site (sbl.min line 11043, b_vrs):
 *     b_vrs  ent
 *            jsr  sysmv          ; <-- new: emit value-trace
 *            mov  vrvlo(xr),(xs) ; original: store value
 *            ...
 *
 *  At entry:
 *     xr = pointer to vrsto field of vrblk  (subtract vrsto*cfp_b for vrblk)
 *     (xs) = the value being stored (pointer to typed block)
 */
int zysmv(void) {
    if (!monitor_init()) return -1;

    /* xr points to vrsto field of vrblk.  Offset of vrsto inside vrblk is
     * 1 word (offsetof: vrsto is 2nd field after vrget).  Use offsetof for
     * portability. */
    char *vrsto_field = XR(char *);
    if (!vrsto_field) return -1;
    struct vrblk *vr = (struct vrblk *)
        (vrsto_field - (long)((char*)&((struct vrblk*)0)->vrsto - (char*)0));

    /* Top of MINIMAL stack: reg_xs is the SPITBOL stack pointer.
     * Note: the syscall thunk does `mov [reg_xs],rsp` BEFORE the syscall
     * macro's `pop rax` of the return address.  So the return address is
     * still at *(word*)reg_xs at this point — the actual SPITBOL value-
     * stack top is one word above.  Cf. sysex.c which does the same skip.
     */
    word *spl_stack = XS(word *);
    if (!spl_stack) return -1;
    void *value_block = (void *)(spl_stack[1]);   /* +1 = skip return addr */

    const char *np = NULL;
    int         nl = 0;
    spl_vrblk_name(vr, &np, &nl);
    /* Empty name → array element / table slot / system variable.  Use a
     * stable sentinel so the wire stream stays well-formed and the
     * CSNOBOL4 and SPITBOL bridges emit byte-identical records on the
     * same statement (CSN's lvalue_name_id() does the same).
     * SN-26-bridge-coverage-a: catch-all symmetry. */
    if (nl == 0) {
        np = "<lval>";
        nl = 6;
    }

    uint32_t name_id = intern_name(np, nl);
    if (name_id == MW_NAME_ID_NONE) return -1;

    const void *chars = NULL;
    uint32_t    vlen  = 0;
    word       iv    = 0;
    double      rv    = 0.0;
    word       i_buf;
    double      r_buf;
    uint8_t type = spl_block_to_wire(value_block, &chars, &vlen, &iv, &rv);

    const void *vp = chars;
    if (type == MWT_INTEGER) {
        /* Pack integer little-endian, 8 bytes. */
        unsigned char *p = (unsigned char *)&i_buf;
        for (int k = 0; k < 8; k++) p[k] = (unsigned char)(((uint64_t)iv >> (k*8)) & 0xff);
        vp = &i_buf; vlen = 8;
    } else if (type == MWT_REAL) {
        memcpy(&r_buf, &rv, sizeof(r_buf));
        vp = &r_buf; vlen = 8;
    }

    emit_record_raw(MWK_VALUE, name_id, type, vp, vlen);
    return -1;
}

/*  zysmc — CALL event from bpf09 (function-call dispatch).
 *
 *  Call site (sbl.min line 10850 region, inside bpf09 just after
 *  the existing trace check completes successfully):
 *      jsr  sysmc            ; <-- new: emit call-trace
 *
 *  At entry: xl points to pfblk (program-defined function block).
 *  pfvbl(xl) is the vrblk for the function name.
 *
 *  In SPITBOL pfblk layout (line 4781 of sbl.min), pfvbl is the
 *  field at offset = pfvbl word offset * cfp_b.  We use the C-side
 *  struct pfblk... actually pfblk isn't declared in spitblks.h, so
 *  we read it as raw words.  pfvbl is offset 1 word from start of pfblk
 *  per `pfvbl equ pfcod-1` (need to verify).  For now we expect the
 *  caller to load vrblk pointer into xr before jsr-ing us — the fire
 *  point in sbl.min will do `mov xr,pfvbl(xl); jsr sysmc`.
 */
int zysmc(void) {
    if (!monitor_init()) return -1;

    struct vrblk *vr = XR(struct vrblk *);
    const char *np = NULL;
    int         nl = 0;
    spl_vrblk_name(vr, &np, &nl);
    if (nl == 0) return -1;

    uint32_t name_id = intern_name(np, nl);
    if (name_id == MW_NAME_ID_NONE) return -1;

    emit_record_raw(MWK_CALL, name_id, MWT_NULL, NULL, 0);
    return -1;
}

/*  zysmr — RETURN event from rtn03/return path.
 *
 *  Call site (sbl.min line 16337 region):
 *      jsr  sysmr            ; <-- new: emit return-trace
 *
 *  At entry:
 *     xr = pfblk pointer (so xr->pfvbl is the vrblk for fn name)
 *     wa = return type string ("RETURN", "FRETURN", "NRETURN")
 *
 *  Per the CSNOBOL4 convention adopted in csn-bridge-b, the RETURN
 *  payload is the return *type* (RETURN/FRETURN/NRETURN), not the
 *  function's result value.  Result is delivered via the preceding
 *  VALUE record on the function-name variable (already emitted by
 *  zysmv when the body ran `<fn> = <expr>`).
 *
 *  In SPITBOL the return type string is in &RTNTYPE which is kvrtn.
 *  We pass the rtntype through wa (already set in retrn at line 16332).
 *  wa is reg_wa post-syscall_init; it carries the address of an scblk
 *  whose len/str give the kind name.
 */
int zysmr(void) {
    if (!monitor_init()) return -1;

    /* xr = pfblk ptr.  pfblk's pfvbl field gives the function vrblk.
     * For now, we expect the SIL site to have already loaded the
     * vrblk into xr before calling us — the sbl.min fire-point
     * will do `mov xl,pfvbl(xr); mov xr,xl; jsr sysmr`. */
    struct vrblk *vr = XR(struct vrblk *);
    const char *np = NULL;
    int         nl = 0;
    spl_vrblk_name(vr, &np, &nl);
    if (nl == 0) return -1;

    uint32_t name_id = intern_name(np, nl);
    if (name_id == MW_NAME_ID_NONE) return -1;

    /* wa carries the rtntype scblk pointer (e.g. "RETURN"). */
    void *rtype_blk = WA(void *);
    const void *chars = NULL;
    uint32_t    vlen  = 0;
    word       iv    = 0;
    double      rv    = 0.0;
    uint8_t type = spl_block_to_wire(rtype_blk, &chars, &vlen, &iv, &rv);

    emit_record_raw(MWK_RETURN, name_id, type, chars, vlen);
    return -1;
}

/*  zysml — LABEL event from stmgo / stgo3 (statement-advance path).
 *
 *  Call sites (sbl.min stmgo + stgo3, post-SN-26-bridge-coverage-f):
 *      mov  wa,kvstn         load stno into wa
 *      jsr  sysml            emit LABEL record on monitor wire
 *
 *  At entry:
 *     wa = &STNO (integer) of statement being entered
 *
 *  Wire payload is name_id=NONE, type=INTEGER, 8-byte LE STNO.  Mirrors
 *  csnobol4's monitor_emit_label semantics — see ../scripts/monitor/
 *  monitor_wire.h MWK_LABEL doc.
 */
int zysml(void) {
    if (!monitor_init()) return -1;

    /* WA macro reads reg_wa as the requested type.  kvstn is a word-sized
     * integer keyword, so we cast wa as word. */
    word stno = WA(word);

    unsigned char buf[8];
    for (int k = 0; k < 8; k++) buf[k] = (unsigned char)(((uint64_t)stno >> (k*8)) & 0xff);

    emit_record_raw(MWK_LABEL, MW_NAME_ID_NONE, MWT_INTEGER, buf, 8);
    return -1;
}

/* end of monitor_ipc_runtime.c */
