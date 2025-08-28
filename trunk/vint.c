/*
 * vint.c
 */

#include "debug.h"
#include "util.h"
#include "vint.h"

#define NO_ASSERT_MACROS
#include "common.h"
#undef NO_ASSERT_MACROS

#include <assert.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

static int fmss(int);

static int _u64_to_vint(uint64_t, char *, size_t);

static int
fmss(int i)
{
    int pos;
    unsigned val;

    if (!i)
        return 0;

    val = (unsigned)i;

    pos = 32;
    if (!(val & 0xffff0000)) {
        val <<= 16;
        pos -= 16;
    }
    if (!(val & 0xff000000)) {
        val <<= 8;
        pos -= 8;
    }
    if (!(val & 0xf0000000)) {
        val <<= 4;
        pos -= 4;
    }
    if (!(val & 0xc0000000)) {
        val <<= 2;
        pos -= 2;
    }
    if (!(val & 0x80000000))
        pos -= 1;

    return pos;
}

static int
_u64_to_vint(uint64_t x, char *y, size_t bufsz)
{
    size_t i;
    uint64_t b, m;

    /* output VINT_MARKER and first octet of VINT_DATA */
    i = bufsz;
    m = 1 << (CHAR_BIT - i);
    --i;
    b = (x & UINT64_C(0xff) << i * CHAR_BIT) >> i * CHAR_BIT;
    if (b >= m)
        return -E_RANGE;
    y[0] = m | b;
    --bufsz;
    while (i > 0) {
        --i;
        y[bufsz-i] = (x & UINT64_C(0xff) << i * CHAR_BIT) >> i * CHAR_BIT;
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
        return ERR_TAG(E_INVAL);

    if (sz == NULL && y == NULL)
        return 0;

    d = (unsigned char)*x;

    /* determine VINT_WIDTH */
    len = CHAR_BIT + 1 - fmss(d);
    if (sz != NULL) {
        *sz = len;
        if (y == NULL)
            return 0;
    }

    /* scan VINT_DATA */
    assert(len <= 8);
    ret = d & 0xff >> len;
    ret <<= --len * CHAR_BIT;
    i = len;
    while (i > 0) {
        ++x;
        ret |= (uint64_t)(unsigned char)*x << --i * CHAR_BIT;
    }

    *y = ret;
    return 0;
}

EXPORTED int
u64_to_vint(uint64_t x, char *y, size_t *bufsz)
{
    int err;
    size_t len;
    uint64_t bnd;

    /* determine VINT_WIDTH */
    bnd = 1 << CHAR_BIT;
    len = 1;
    for (;;) {
        if (x < bnd)
            break;
        ++len;
        if (bnd == UINT64_C(1) << (sizeof(x) - 1) * CHAR_BIT)
            break;
        bnd <<= CHAR_BIT;
    }
    if (*bufsz < len)
        return ERR_TAG(E_INVAL);

    if (y == NULL)
        goto end;

    err = _u64_to_vint(x, y, len);
    if (err) {
        if (err != -E_RANGE)
            return ERR_TAG(-err);
        ++len;
        if (*bufsz < len)
            return ERR_TAG(E_INVAL);
        err = _u64_to_vint(x, y, len);
        if (err)
            return ERR_TAG(-err);
    }

end:
    *bufsz = len;
    return 0;
}

EXPORTED int
u64_to_vint_l(uint64_t x, char *y, size_t bufsz)
{
    int err;

    err = _u64_to_vint(x, y, bufsz);
    return err ? ERR_TAG(-err) : 0;
}

/* vi: set expandtab sw=4 ts=4: */
