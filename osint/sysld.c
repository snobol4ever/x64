/*
Copyright 1987-2012 Robert B. K. Dewar and Mark Emmer.
Copyright 2012-2017 David Shields
Copyright 2024 snobol4ever contributors
*/

/*    zysld - load external function */

/*    Parameters:
 *        XR - pointer to SCBLK containing function prototype ("name(types)")
 *        XL - pointer to SCBLK containing library (.so) path
 *    Returns:
 *        XR - pointer to XNBLK (stored in efblk.efcod)
 *    Exits:
 *        1 - function does not exist
 *        2 - I/O error loading function
 *        3 - insufficient memory
 *
 *    WARNING:  THIS FUNCTION CALLS A FUNCTION WHICH MAY INVOKE A GARBAGE
 *    COLLECTION.  STACK MUST REMAIN WORD ALIGNED AND COLLECTABLE.
 */

#include "port.h"
#include <stdio.h>
#include <dlfcn.h>
#include <string.h>

#if EXTFUN

/* Types and externs from syslinux.c */
typedef word (*PFN)();
extern word   loadDll(char *dllName, char *fcnName, PFN *ppfnProcAddress);
extern void  *loadef(word fd, char *filename);

int
zysld()
{
    struct scblk *lnscb = XL(struct scblk *);   /* library path SCBLK  */
    struct scblk *fnscb = XR(struct scblk *);   /* function prototype SCBLK */
    char libname[512], funcname[256];
    PFN pfn;
    word handle;
    void *result;
    word liblen, fnlen;
    word i;

    /* Null-terminate the library path */
    liblen = lnscb->len;
    if (liblen >= (word)sizeof(libname))
        liblen = (word)sizeof(libname) - 1;
    memcpy(libname, lnscb->str, (size_t)liblen);
    libname[liblen] = '\0';

    /* Extract function name from prototype — stop at '(' or space */
    fnlen = fnscb->len;
    for (i = 0; i < fnlen; i++) {
        char c = fnscb->str[i];
        if (c == '(' || c == ' ')
            break;
    }
    if (i >= (word)sizeof(funcname))
        i = (word)sizeof(funcname) - 1;
    memcpy(funcname, fnscb->str, (size_t)i);
    funcname[i] = '\0';


    /* Open the shared library and resolve the function symbol */
    handle = loadDll(libname, funcname, &pfn);
    if (handle == (word)-1)
        return EXIT_1;   /* library or symbol not found */

    /* Build an XNBLK to hold the handle and entry point */
    result = loadef(handle, (char *)&pfn);
    switch ((word)result) {
    case  (word) 0:  return EXIT_2;   /* I/O error */
    case (word)-1:   return EXIT_1;   /* doesn't exist */
    case (word)-2:   return EXIT_3;   /* insufficient memory */
    default:
        SET_XR(result);
        return NORMAL_RETURN;
    }
}

#else  /* EXTFUN */

int
zysld()
{
    return EXIT_1;
}

#endif /* EXTFUN */
