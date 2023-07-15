/*
 * common.h
 */

#ifndef _COMMON_H
#define _COMMON_H

#include <assert.h>
#include <errno.h>

#define EXPORTED __attribute__((__visibility__("default")))

#ifndef NO_ASSERT_MACROS
static __thread int asserttmp;

#define ERRNO (asserttmp = errno, assert(asserttmp > 0), asserttmp)
#define MINUS_ERRNO (asserttmp = -errno, assert(asserttmp < 0), asserttmp)
#endif

#define _STR(x) #x
#define STR(x) _STR(x)

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define PL(val) PL_SUF(val, "", "s")
#define PL_SUF(val, s, p) val, (val) == 1 ? (s) : (p)

#endif

/* vi: set expandtab sw=4 ts=4: */
