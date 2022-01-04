/*
 * vint.c
 */

#include "vint.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <strings.h>

#include <sys/param.h>

int
vint_to_u64(const char *x, uint64_t *y)
{
    size_t i, len;
    uint64_t ret;

    /* find VINT_MARKER */
    if (*x == 0)
        return -EINVAL;

    /* determine VINT_WIDTH */
    len = NBBY + 1 - fls(*x);

    /* scan VINT_DATA */
    ret = *x & (0xff >> len);
    ret <<= (--len * NBBY);
    for (i = len - 1; i > 0; i--) {
        ++x;
        ret |= *x << (i * NBBY);
    }

    *y = ret;
    return 0;
}

int
u64_to_vint(uint64_t x, char *y, size_t bufsz)
{
    char b, m;
    size_t i, len;
    uint64_t bnd;

    /* determine VINT_WIDTH */
    bnd = (1 << NBBY);
    len = 1;
    for (;;) {
        if (x < bnd)
            break;
        ++len;
        if (bnd == (1ull << (sizeof(x) - 1) * NBBY))
            break;
        bnd <<= NBBY;
    }
    if (bufsz < len)
        return -EINVAL;

    /* output VINT_MARKER and first octet of VINT_DATA */
    i = len;
    m = 1 << (NBBY - i);
    --i;
    b = x & (0xff << (i * NBBY));
    if (b >= m)
        return -ERANGE;
    y[0] = (m << (i * NBBY)) | b;
    --len;
    while (i > 0) {
        --i;
        y[len-i] = x & (0xff << (i * NBBY));
    }

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
