/*
 * debug.h
 */

#ifndef _DEBUG_H
#define _DEBUG_H

#include <stdint.h>
#include <stdio.h>

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

#define TRACE_SIGNATURE(enabled, sig, handler) \
    _TRACE_SIGNATURE_##enabled(__LINE__, sig, trace_handler_##handler)

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

#endif

/* vi: set expandtab sw=4 ts=4: */
