/*
 * debug.h
 */

#ifndef _DEBUG_H
#define _DEBUG_H

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

struct err_info_bt {
    int         errdes;
    const char  *file;
    int         line;
    char        **bt;
    int         len;
};

#define ERRDES_MIN 128

#define __LINESTR(line) #line
#define _LINESTR(line) __LINESTR(line)

#define _TRACE_SIGNATURE_0(line, sig, handler)
#define _TRACE_SIGNATURE_1(line, sig, handler) \
    do { \
        static uint64_t signature; \
        \
        fprintf(stderr, "DEBUGGING TRACE: " __FILE__ ":" _LINESTR(__LINE__) \
                        " [%s()]: %" PRIu64 "\n", \
                __func__, signature); \
        if ((sig) >= 0 && signature == (sig)) \
            handler(); \
        ++signature; \
    } while (0)

#define _TRACE_SIGNATURE(enabled, sig, handler) \
    _TRACE_SIGNATURE_##enabled(__LINE__, sig, trace_handler_##handler)

#define TRACE_SIGNATURE(enabled, sig, handler) \
    _TRACE_SIGNATURE(enabled, sig, handler)

#define trace_handler_0() raise(SIGTRAP)

#define LIST_TRACE_HANDLERS(X) \
    X(1) \
    X(2) \
    X(3) \
    X(4) \
    X(5) \
    X(6) \
    X(7) \
    X(8)

#define X(id) \
void trace_handler_##id(void);
LIST_TRACE_HANDLERS(X)
#undef X

#ifndef NO_ASSERT_MACROS
#ifndef ERRNO
static _Thread_local int asserttmp;

#define ERRNO (asserttmp = errno, assert(asserttmp > 0), asserttmp)
#define MINUS_ERRNO (asserttmp = -errno, assert(asserttmp < 0), asserttmp)
#endif

#define ERR_TAG(errn) (asserttmp = err_tag_bt(-(errn)), assert(asserttmp > 0), \
                       asserttmp)

#endif

#define err_tag_bt(errcode) _err_tag_bt(errcode, __FILE__, __LINE__)

int err_tag(int errcode, void *data);

void *err_get(int errdes, int *errcode);

int err_get_code(int errdes);

int err_clear(int errdes);

int err_foreach(int (*cb)(int, void *, void *), void *ctx);

int _err_tag_bt(int errcode, const char *file, int line);

struct err_info_bt *err_get_bt(int *err);

int err_info_free(struct err_info_bt *info, int freeall);

int err_print(FILE *f, int *err);

#endif

/* vi: set expandtab sw=4 ts=4: */
