/*
 * element.c
 */

#include "common.h"
#include "element.h"
#include "vint.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

EXPORTED int
eid_to_u64(const char *x, uint64_t *y, size_t *sz)
{
    char buf[8];
    int err;
    size_t bufsz, tmpsz;
    uint64_t tmp;

    err = vint_to_u64(x, &tmp, &tmpsz);
    if (err)
        return err;

    if (tmp == 0 /* VINT_DATA must not be set to all 0 */
        || tmp == VINT_MAX_VAL(tmpsz)) /* VINT_DATA must not be set to all 1 */
        return -EINVAL;

    bufsz = sizeof(buf);
    err = u64_to_vint(tmp, buf, &bufsz);
    if (err)
        return err;
    if (tmp == VINT_MAX_VAL(bufsz))
        ++bufsz;

    if (tmpsz != bufsz) /* a shorter VINT_DATA encoding is available */
        return -EINVAL;

    *y = tmp;
    *sz = tmpsz;
    return 0;
}

EXPORTED int
u64_to_eid(uint64_t x, char *y, size_t *bufsz)
{
    return u64_to_vint(x, y, bufsz);
}

/* vi: set expandtab sw=4 ts=4: */
