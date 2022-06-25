/*
 * vint.c
 */

#include "common.h"
#include "util.h"
#include "vint.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

static int _u64_to_vint(uint64_t, char *, size_t);

static int
_u64_to_vint(uint64_t x, char *y, size_t bufsz)
{
    size_t i;
    uint64_t b, m;

    /* output VINT_MARKER and first octet of VINT_DATA */
    i = bufsz;
    m = 1 << (CHAR_BIT - i);
    --i;
    b = (x & 0xff << i * CHAR_BIT) >> i * CHAR_BIT;
    if (b >= m)
        return -ERANGE;
    y[0] = m | b;
    --bufsz;
    while (i > 0) {
        --i;
        y[bufsz-i] = (x & 0xff << i * CHAR_BIT) >> i * CHAR_BIT;
    }

    return 0;
}

EXPORTED int
vint_to_u64(const char *x, uint64_t *y, size_t *sz)
{
    size_t i, len;
    uint64_t ret;
    unsigned char d;

    /* find VINT_MARKER */
    if (*x == 0)
        return -EINVAL;

    d = (unsigned char)*x;

    /* determine VINT_WIDTH */
    len = CHAR_BIT + 1 - fls(d);
    if (sz != NULL)
        *sz = len;

    /* scan VINT_DATA */
    ret = d & 0xff >> len;
    ret <<= --len * CHAR_BIT;
    i = len;
    while (i > 0) {
        ++x;
        ret |= (unsigned char)*x << --i * CHAR_BIT;
    }

    *y = ret;
    return 0;
}

EXPORTED int
u64_to_vint(uint64_t x, char *y, size_t *bufsz)
{
    size_t len;
    uint64_t bnd;

    /* determine VINT_WIDTH */
    bnd = 1 << CHAR_BIT;
    len = 1;
    for (;;) {
        if (x < bnd)
            break;
        ++len;
        if (bnd == 1ull << (sizeof(x) - 1) * CHAR_BIT)
            break;
        bnd <<= CHAR_BIT;
    }
    if (*bufsz < len)
        return -EINVAL;
    *bufsz = len;

    return y == NULL ? 0 : _u64_to_vint(x, y, len);
}

EXPORTED int
u64_to_vint_l(uint64_t x, char *y, size_t bufsz)
{
    return _u64_to_vint(x, y, bufsz);
}

/* vi: set expandtab sw=4 ts=4: */
