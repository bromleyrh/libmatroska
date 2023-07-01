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

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define PLURAL(val, suffix) val, (val) == 1 ? "" : (suffix)

#endif

/* vi: set expandtab sw=4 ts=4: */
