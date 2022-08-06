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

uint64_t
vintmax(size_t len)
{
    return (1ull << 7 * len) - 2;
}

EXPORTED int
edatasz_to_u64(const char *x, uint64_t *y, size_t *sz)
{
    int err;
    size_t tmpsz;
    uint64_t tmp;

    err = vint_to_u64(x, &tmp, &tmpsz);
    if (!err) {
        *y = tmp > vintmax(tmpsz) ? EDATASZ_UNKNOWN : tmp;
        *sz = tmpsz;
    }

    return err;
}

EXPORTED int
u64_to_edatasz(uint64_t x, char *y, size_t *bufsz)
{
    if (x == EDATASZ_UNKNOWN)
        x = vintmax(1) + 1;

    return u64_to_vint(x, y, bufsz);
}

EXPORTED int
u64_to_edatasz_l(uint64_t x, char *y, size_t bufsz)
{
    if (x == EDATASZ_UNKNOWN)
        x = vintmax(bufsz) + 1;

    return u64_to_vint_l(x, y, bufsz);
}

const char *
etype_to_str(enum etype etype)
{
    static const char *const typemap[] = {
#define _X(type, name, hash) \
        [type] = name,
        LIST_ETYPES()
#undef _X
    };

    return etype >= ARRAY_SIZE(typemap) ? NULL : typemap[etype];
}

enum etype
str_to_etype(const char *str)
{
    static const struct {
        const char  *str;
        enum etype  etype;
    } typemap[256 * 256] = {
#define _X(type, name, hash) \
        [hash] = {.str = name, .etype = type},
        LIST_ETYPES()
#undef _X
    };

    return str[0] == '\0' || str[1] == '\0'
           ? ETYPE_NONE : typemap[ETYPE_HASH(str[0], str[1])].etype;
}

/* vi: set expandtab sw=4 ts=4: */
