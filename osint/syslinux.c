
/*
Copyright 1987-2012 Robert B. K. Dewar and Mark Emmer.
Copyright 2012-2017 David Shields
*/

/************************************************************************\
*                                                                        *
*  syslinux - Unique Linux code for SPITBOL              *
*                                                                        *
\************************************************************************/

#define PRIVATEBLOCKS 1

/*#include <unistd.h> */
#include "port.h"
#include <fcntl.h>
#include <stdlib.h>
#undef brk  /* remove sproto redefinition */
#undef sbrk /* remove sproto redefinition */
#include <malloc.h>

/* Size and offset of fields of a structure.  Probably not portable. */
#define FIELDSIZE(str, fld) (sizeof(((str *)0)->fld))
#define FIELDOFFSET(str, fld) ((unsigned long)(char *)&(((str *)0)->fld))

#if EXTFUN
# include <dlfcn.h>

typedef struct xnblk XFNode, *pXFNode;
typedef mword (*PFN)(); /* pointer to function */

static union block *scanp;          /* used by scanef/nextef */
static pXFNode xnfree = (pXFNode)0; /* list of freed blocks */

extern long f_2_i(double ra);
extern double i_2_f(long ia);
extern double f_add(double arg, double ra);
extern double f_sub(double arg, double ra);
extern double f_mul(double arg, double ra);
extern double f_div(double arg, double ra);
extern double f_neg(double ra);
/* math.c provides these as void(void) using reg_ra global — cast to double(*)() in flttab */
extern void f_atn(void);
extern void f_chp(void);
extern void f_cos(void);
extern void f_etx(void);
extern void f_lnf(void);
extern void f_sin(void);
extern void f_sqr(void);
extern void f_tan(void);

static APDF flttab = {
    (double (*)())f_2_i, /* float to integer */
    i_2_f,               /* integer to float */
    f_add,               /* floating add */
    f_sub,               /* floating subtract */
    f_mul,               /* floating multiply */
    f_div,               /* floating divide */
    f_neg,               /* floating negage */
    f_atn,               /* arc tangent */
    f_chp,               /* chop */
    f_cos,               /* cosine */
    f_etx,               /* exponential */
    f_lnf,               /* natural log */
    f_sin,               /* sine */
    f_sqr,               /* square root */
    f_tan                /* tangent */
};

misc miscinfo = {
    0x105,                          /* internal version number */
    GCCi32 ? t_lnx8632 : t_lnx8664, /* environment */
    0,                              /* spare */
    0,                              /* number of arguments */
    0,                              /* pointer to type table */
    0,                              /* pointer to XNBLK */
    0,                              /* pointer to EFBLK */
    (APDF *)flttab,                 /* pointer to flttab */
};

/* Assembly-language helper needed for final linkage to function:
 */

/*
 * callef - procedure to call external function.
 *
 *    result = callef(efptr, xsp, nargs)
 *
 *       efptr    pointer to efblk
 *       xsp        pointer to arguments+4 (artifact of machines with return link on stack)
 *       nargs    number of arguments
 *       result     0 - function should fail
 *                -1 - insufficient memory to convert arg (not used)
 *                     or function not found.
 *                -2 - improper argument type (not used)
 *                other - block pointer to function result
 *
 * Called from sysex.c.
 *
 */
/*
 * LOAD function calling ABI (x64 Linux, System V AMD64):
 *
 *   int pfn(struct ldescr *retval, unsigned nargs, struct ldescr *args)
 *
 * struct ldescr — matches CSNOBOL4 load.h / libspl.c empirically verified ABI:
 *   a.i   integer value (long)
 *   a.f   real value (double, same storage)
 *   f     flags byte (0 for plain values)
 *   v     type tag: 'I'=integer, 'R'=real, 'S'=string (null)
 *
 * SPITBOL stack layout on entry to callef:
 *   sp[0] = last-pushed arg = arg nargs-1 (union block*)
 *   sp[nargs-1] = first arg = arg 0
 *   Each INTEGER arg is a union block* pointing to struct icblk {ictyp,icval}.
 *
 * callextfun (int.asm) is a pure trampoline: it receives the already-marshalled
 * (pfn, retval, nargs, cargs) and calls pfn(retval, nargs, cargs) after MINSAVE
 * has already saved Minimal register state.  That keeps the snapshot coherent
 * for any re-entrant MINIMAL() calls pfn might make (callback into SPITBOL).
 */

struct ldescr {
    union { long i; double f; } a;
    char         f;
    unsigned int v;
};
typedef int (*load_pfn_t)(struct ldescr *retval, unsigned nargs,
                          struct ldescr *args);
extern int callextfun(load_pfn_t pfn, struct ldescr *retval,
                      unsigned nargs, struct ldescr *cargs);

#define LDESCR_INT 'I'
#define LDESCR_REAL 'R'
#define LDESCR_STR 'S'
#define LOAD_MAX_ARGS 32

union block *
callef(struct efblk *efb, union block **sp, mword nargs)
{
    pXFNode    pnode;
    load_pfn_t pfn;
    struct ldescr cargs[LOAD_MAX_ARGS];
    struct ldescr retval;
    mword i;
    int   load_rc;

    pnode = (pXFNode)(efb->efcod);
    if(pnode == NULL)
        return (union block *)-1L;

    /* pfn at xnblk.xndta[1] (offset 24) — verified B-231 raw dump */
    pfn = (load_pfn_t)(uintptr_t)pnode->xnu.xndta[1];

    miscinfo.pefblk = efb;
    miscinfo.pxnblk = pnode;
    miscinfo.nargs  = nargs;

    /* xn1st/xnsave: provide 1 on first call, 0 on subsequent */
    if(pnode->xnu.ef.xn1st)  pnode->xnu.ef.xn1st--;
    if(pnode->xnu.ef.xnsave) pnode->xnu.ef.xnsave--;

    if(nargs > LOAD_MAX_ARGS)
        return (union block *)-1L;

    /*
     * Marshal SPITBOL stack args into ldescr[].
     * sp[0] = last-pushed = arg nargs-1; sp[nargs-1] = arg 0.
     * eftar[i]: 0=noconv, 1=string, 2=integer(conint), 3=real, 4=file.
     */
    for(i = 0; i < nargs; i++) {
        union block *blk = sp[nargs - 1 - i];
        cargs[i].f = 0;
        switch(efb->eftar[i]) {
        case conint: /* 2 — INTEGER */
            cargs[i].a.i = blk->icb.icval;
            cargs[i].v   = LDESCR_INT;
            break;
        default:
            /* future: string, real, noconv */
            cargs[i].a.i = blk->icb.icval;
            cargs[i].v   = LDESCR_INT;
            break;
        }
    }

    retval.a.i = 0;
    retval.f   = 0;
    retval.v   = 0;

    /*
     * MINSAVE() saves Minimal registers before the call so pfn can
     * safely call back into the SPITBOL runtime via MINIMAL() if needed.
     * callextfun is the trampoline that performs pfn(retval,nargs,cargs)
     * with correct SysV AMD64 register setup.
     */
    MINSAVE();
    load_rc = callextfun(pfn, &retval, (unsigned)nargs, cargs);
    MINRESTORE();

    if(!load_rc)
        return (union block *)0; /* FAIL */

    /* Pack integer return into ticblk (scratch block outside dynamic mem) */
    pticblk->ictyp = TYPE_ICL;
    pticblk->icval = retval.a.i;
    return (union block *)pticblk;
}

/* Attempt to load a DLL into memory using the name provided.
 *
 * The name may either be a fully-qualified pathname, or just a module
 * (function) name.
 *
 * If the DLL is found, its handle is returned as the function result.
 * Further, the function name provided is looked up in the DLL module,
 * and the address of the function is returned in *ppfnProcAddress.
 *
 * Returns -1 if module or function not found.
 *
 */
mword
loadDll(char *dllName, char *fcnName, PFN *ppfnProcAddress)
{
    void *handle;
    PFN pfn;

# ifdef RTLD_NOW
    handle = dlopen(dllName, RTLD_NOW);
# else
    handle = dlopen(dllName, RTLD_LAZY);
# endif
    if(!handle) {
        dlerror();
        return -1;
    }

    *ppfnProcAddress = (PFN)dlsym(handle, fcnName);
    if(!*ppfnProcAddress) {
        dlclose(handle);
        return -1;
    }

    return (mword)handle;
}

/*
 * loadef - load external function
 *
 *    result = loadef(handle, pfnc)
 *
 *    Input:
 *       handle    module handle of DLL (already in memory)
 *       pfnc        pointer to function entry point in module
 *    Output:
 *     result     0 - I/O error
 *            -1 - function doesn't exist (not used)
 *            -2 - insufficient memory
 *            other - pointer to XNBLK that points in turn
 *                    to the loaded code (here as void *).
 */
void *
loadef(mword fd, char *filename)
{
    void *handle = (void *)fd;
    PFN pfn = *(PFN *)filename;
    pXFNode pnode;

    if(xnfree) {        /* Are these any free nodes to use? */
        pnode = xnfree; /* Yes, seize one */
        xnfree = (pXFNode)(mword)pnode->xnu.xndta[1]; /* xndta[1] = free-list next */
    } else {
        MINSAVE(); /* No */
        SET_WA(sizeof(XFNode));
        MINIMAL(MINIMAL_ALOST); /* allocate from static region */
        pnode = XR(pXFNode);    /* get node to hold information */
        MINRESTORE();
    }

    pnode->xntyp = TYPE_XNT;       /* B_XNT type word */
    pnode->xnlen = sizeof(XFNode); /* length of this block */
    pnode->xnu.xndta[0] = (mword)(uintptr_t)handle; /* xndta[0] = DLL handle */
    pnode->xnu.xndta[1] = (mword)(uintptr_t)pfn;    /* xndta[1] = function entry point */
    pnode->xnu.ef.xn1st = 2;       /* flag first call to function */
    pnode->xnu.ef.xnsave = 0;      /* not reload from save file */
    pnode->xnu.ef.xncbp = (void far (*)())0; /* no callback  declared */
    return (void *)pnode; /* Return node to store in EFBLK */
}

/*
 * nextef - return next external function block.
 *
 *         length = nextef(.bufp, io);
 *
 * Input:
 * bufp = address of pointer to be loaded with block pointer
 * io = -1 = scanning memory
 *        0 if loading functions
 *        1 if saving functions or exiting SPITBOL
 *
 * Note that under SPARC, it is not possible to save or reload
 * functions from the Save file. The user must explicitly re-execute
 * the LOAD() function to reload the DLL.
 *
 * Output:
 *  for io = -1:
 *        length = pointer to XNBLK
 *                 0 if done
 *        bufp   = pointer to EFBLK.
 *
 *  for io = 0,1:
 *         length = length of function's memory block
 *                 0 if done
 *                 -1 if unable to allocate memory (io=0 only)
 *        bufp   = pointer to function body.
 *
 * When io = 1, we invoke any callback routine established by the
 * external function if it wants to be notified when SPITBOL is
 * shutting down.  xnsave set to -1 to preclude multiple callbacks.
 *
 * When io = 0, the routine will allocate the memory needed to
 * hold the function when it is read from a disk file.
 *
 * When io = -1, nextef takes no special action, and simple returns the
 * address of the next EFBLK found.
 *
 * The current scan point is in scanp, established by scanef.
 */
void *
nextef(unsigned char **bufp, int io)
{
    union block *dnamp;
    mword ef_type = GET_CODE_OFFSET(B_EFC, mword);
    void *result = 0;
    mword type, blksize;
    pXFNode pnode;

    MINSAVE();
    for(dnamp = GET_MIN_VALUE(dnamp, union block *); scanp < dnamp;
        scanp = ((union block *)(MP_OFF(scanp, muword) + blksize))) {
        type = scanp->scb.sctyp; /* any block type lets us access type word */
        SET_WA(type);
        SET_XR(scanp);
        MINIMAL(MINIMAL_BLKLN); /* get length of block in bytes */
        blksize = WA(mword);
        if(type != ef_type) /* keep searching if not EFBLK */
            continue;
        pnode =
            ((pXFNode)(scanp->efb
                           .efcod)); /* it's an EFBLK; get address of XNBLK */
        if(!pnode)                   /* keep searching if no longer in use */
            continue;

        switch(io) {
        case -1:
            result = (void *)pnode;         /* return pointer to XNBLK */
            *bufp = (unsigned char *)scanp; /* return pointer to EFBLK */
            break;
        case 0:
            result = (void *)-1; /* can't reload DLL */
            break;
        case 1:
            if(pnode->xnu.ef.xncbp) /* is there a callback routine? */
                if(pnode->xnu.ef.xnsave >= 0) {
                    (pnode->xnu.ef.xncbp)();
                    pnode->xnu.ef.xnsave = -1;
                }
            *bufp = (unsigned char *)(uintptr_t)pnode->xnu.xndta[1]; /* xndta[1] = pfn */
            result = (void *)1; /* phony non-zero size of code */
            break;
        }
        /* point to next block */
        scanp = ((union block *)(MP_OFF(scanp, muword) + blksize));
        break; /* break out of for loop */
    }
    MINRESTORE();
    return result;
}

/* Rename a file.  Return 0 if OK */
int
renames(char *oldname, char *newname)
{
    if(link(oldname, newname) == 0) {
        unlink(oldname);
        return 0;
    } else
        return -1;
}

/*
 * scanef - prepare to scan memory for external function blocks.
 */
void
scanef()
{
    scanp = GET_MIN_VALUE(dnamb, union block *);
}

/*
 * unldef - unload an external function
 */
void
unldef(struct efblk *efb)
{
    pXFNode pnode, pnode2;
    unsigned char *bufp;

    pnode = ((pXFNode)(efb->efcod));
    if(pnode == NULL)
        return;

    if(pnode->xnu.ef.xncbp) /* is there a callback routine? */
        if(pnode->xnu.ef.xnsave >= 0) {
            (pnode->xnu.ef.xncbp)();
            pnode->xnu.ef.xnsave = -1;
        }

    efb->efcod = 0;                /* remove pointer to XNBLK */
    dlclose((void *)(uintptr_t)pnode->xnu.xndta[0]); /* xndta[0] = DLL handle */

    pnode->xnu.xndta[1] = (mword)(uintptr_t)xnfree; /* put back on free list */
    xnfree = pnode;
}

#endif /* EXTFUN */

/* Open file "Name" for reading, writing, or updating.
 * Method is O_RDONLY, O_WRONLY, O_RDWR, O_CREAT, O_TRUNC.
 * Mode supplies the sharing modes (IO_DENY_XX), IO_PRIVATE and IO_EXECUTABLE flags.
 * Action consists of flags such as IO_FAIL_IF_EXISTS, IO_OPEN_IF_EXISTS, IO_REPLACE_IF_EXISTS,
 *  IO_FAIL_IF_NOT_EXISTS, IO_CREATE_IF_NOT_EXIST, IO_WRITE_THRU.
 */
#define MethodMask (O_RDONLY | O_WRONLY | O_RDWR)

/* Private flags used to convey sharing status when opening a file */
#define IO_COMPATIBILITY 0x00
#define IO_DENY_READWRITE 0x01
#define IO_DENY_WRITE 0x02
#define IO_DENY_READ 0x03
#define IO_DENY_NONE 0x04
#define IO_DENY_MASK 0x07  /* mask for above deny mode bits */
#define IO_EXECUTABLE 0x40 /* file to be marked executable */
#define IO_PRIVATE 0x80    /* file is private to current process */

/* Private flags used to convey file open actions */
#define IO_FAIL_IF_EXISTS 0x00
#define IO_OPEN_IF_EXISTS 0x01
#define IO_REPLACE_IF_EXISTS 0x02
#define IO_FAIL_IF_NOT_EXIST 0x00
#define IO_CREATE_IF_NOT_EXIST 0x10
#define IO_EXIST_ACTION_MASK 0x13 /* mask for above bits */
#define IO_WRITE_THRU 0x20        /* writes complete before return */

File_handle
spit_open(char *Name, Open_method Method, File_mode Mode, int Action)
{
    if((Method & MethodMask) == O_RDONLY) /* if opening for read only */
        Method &= ~(O_CREAT | O_TRUNC);   /* guarantee these bits off */
    else if(Action & IO_WRITE_THRU)       /* else must be a write */
        Method |= O_SYNC;

    if((Method & O_CREAT) & (Action & IO_FAIL_IF_EXISTS))
        Method |= O_EXCL;

    return open(Name, Method, (Mode & IO_EXECUTABLE) ? 0777 : 0666);
}

void *
sbrkx(long incr)
{
    static char *base = 0; /* base of the sbrk region */
    static char *endofmem;
    static char *curr;
    void *result;

    if(!base) { /* if need to initialize */
        char *first_base;
        unsigned long size;

        /* Allocate but do not commit a chunk of linear address space.
         * This allows dlopen and any loaded external functions to use
         * the system malloc and sbrk to obtain memory beyond SPITBOL's
         * heap.
         */
        size = databts;

        do {
            first_base = (char *)malloc(size);
            if(first_base != 0)
                break;

            size -= (1 * 1024 * 1024);
        } while(size >= (20 * maxsize)); /* arbitrary lower limit */

        if(!first_base)
            return (void *)-1;

        base = first_base;

        /* To satisfy SPITBOL's requirement that the heap begin at an address
         * numerically larger than the largest object size, we force base
         * up to that value.  Note three things:  Since Linux memory is a sparse
         * array, this doesn't waste any physical memory.  And if by some
         * chance the user has specified a different object size value on
         * the command line, there is no harm in doing this.  It also starts
         * the heap at a nice high address that isn't likely to change as
         * the size of the SPITBOL system changes.
         */
        if(base < (char *)maxsize)
            base = (char *)maxsize;

        curr = base;
        endofmem = first_base + size;
    }

    if(curr + incr > endofmem)
        return (void *)-1;

    result = curr;
    curr += incr;

    return result;
}

/*  brkx(addr) - set the break address to the given value.
 *  returns 0 if successful, -1 if not.
 */
int
brkx(void *addr)
{
    return sbrkx((char *)addr - (char *)sbrkx(0)) == (void *)-1 ? -1 : 0;
}

/*
 *-----------
 *
 *    makeexec - C callable make executable file function
 *
 *    Allows C function zysbx() to create executable files
 *    (a.out files) in response to user's -w command option.
 *
 *    SPITBOL performed a garbage collection prior to calling
 *    SYSBX, so there is no need to duplicate it here.
 *
 *    Then zysxi() is invoked directly to write the module.
 *
 *    int makeexec( struct scblk *scptr, int type);
 *
 *    Input:    scptr = Pointer to SCBLK for load module name.
 *            type = Type (+-3 or +-4)
 *    Output:    Result value <> 0 if error writing a.out.
 *        Result = 0 if type was |4| and no error.
 *        No return if type was |3| and file written successfully.
 *        When a.out is eventually loaded and executed, the restart
 *        code jumps directly to RESTART in the Minimal source.
 *        That is, makeexec is not resumed, since that would involve
 *        preserving the C stack and registers in the load module.
 *
 *        Upon resumption, the execution start time and garbage collect
 *        count are reset appropriately by restart().
 *
 */
int
makeexec(struct scblk *scptr, int type)
{
    word save_wa, save_wb, save_ia, save_xr;
    int result;

    /* save zysxi()'s argument registers (but not XL) */
    save_wa = reg_wa;
    save_wb = reg_wb;
    save_ia = reg_ia;
    save_xr = reg_xr;

    reg_wa = (word)scptr;
    reg_xl = 0;
    reg_ia = type;
    reg_wb = 0;
    reg_xr = GET_DATA_OFFSET(headv, word);

    /*  -1 is the normal return, so result >= 0 is an error */
    result = zysxi() + 1;

    reg_wa = save_wa;
    reg_wb = save_wb;
    reg_ia = save_ia;
    reg_xr = save_xr;
    return result;
}

/*  uppercase( word )
 *
 *  restricted upper case function.  Only acts on 'a' through 'z'.
 */
word
uppercase(word c)
{
    if(c >= 'a' && c <= 'z')
        c += 'A' - 'a';
    return c;
}
