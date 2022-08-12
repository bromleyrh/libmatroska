/*
 * element.c
 */

#include "common.h"
#include "element.h"
#include "vint.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

typedef int unpack_fn_t(const char *, edata_t *);

static unpack_fn_t unpack_integer_1;
static unpack_fn_t unpack_integer_2;
static unpack_fn_t unpack_integer_4;
static unpack_fn_t unpack_integer_8;

static unpack_fn_t unpack_uinteger_1;
static unpack_fn_t unpack_uinteger_2;
static unpack_fn_t unpack_uinteger_4;
static unpack_fn_t unpack_uinteger_8;

static unpack_fn_t unpack_float_4;
static unpack_fn_t unpack_float_8;

static unpack_fn_t unpack_string;

static unpack_fn_t unpack_utf8;

static unpack_fn_t unpack_date_4;

static unpack_fn_t unpack_binary;

static unpack_fn_t *const integer_fns[] = {
    [1] = &unpack_integer_1,
    [2] = &unpack_integer_2,
    [4] = &unpack_integer_4,
    [8] = &unpack_integer_8
};

static unpack_fn_t *const uinteger_fns[] = {
    [1] = &unpack_uinteger_1,
    [2] = &unpack_uinteger_2,
    [4] = &unpack_uinteger_4,
    [8] = &unpack_uinteger_8
};

static unpack_fn_t *const float_fns[] = {
    [4] = &unpack_float_4,
    [8] = &unpack_float_8
};

static unpack_fn_t *const date_fns[] = {
    [4] = &unpack_date_4
};

static int
unpack_integer_1(const char *x, edata_t *y)
{
    y->integer = (int64_t)*x;

    return 0;
}

static int
unpack_integer_2(const char *x, edata_t *y)
{
    y->bytes[0] = x[1];
    y->bytes[1] = x[0];

    return 0;
}

static int
unpack_integer_4(const char *x, edata_t *y)
{
    int i;

    for (i = 0; i < 4; i++)
        y->bytes[i] = x[~i & 3];

    return 0;
}

static int
unpack_integer_8(const char *x, edata_t *y)
{
    int i;

    for (i = 0; i < 8; i++)
        y->bytes[i] = x[~i & 7];

    return 0;
}

static int
unpack_uinteger_1(const char *x, edata_t *y)
{
    y->integer = (uint64_t)*x;

    return 0;
}

static int
unpack_uinteger_2(const char *x, edata_t *y)
{
    y->bytes[0] = x[1];
    y->bytes[1] = x[0];

    return 0;
}

static int
unpack_uinteger_4(const char *x, edata_t *y)
{
    int i;

    for (i = 0; i < 4; i++)
        y->bytes[i] = x[~i & 3];

    return 0;
}

static int
unpack_uinteger_8(const char *x, edata_t *y)
{
    int i;

    for (i = 0; i < 8; i++)
        y->bytes[i] = x[~i & 7];

    return 0;
}

static int
unpack_float_4(const char *x, edata_t *y)
{
    (void)x;
    (void)y;

    return 0;
}

static int
unpack_float_8(const char *x, edata_t *y)
{
    (void)x;
    (void)y;

    return 0;
}

static int
unpack_string(const char *x, edata_t *y)
{
    (void)x;
    (void)y;

    return 0;
}

static int
unpack_utf8(const char *x, edata_t *y)
{
    (void)x;
    (void)y;

    return 0;
}

static int
unpack_date_4(const char *x, edata_t *y)
{
    (void)x;
    (void)y;

    return 0;
}

static int
unpack_binary(const char *x, edata_t *y)
{
    (void)x;
    (void)y;

    return 0;
}

EXPORTED int
eid_to_u64(const char *x, uint64_t *y, size_t *sz)
{
    char buf[8];
    int err;
    int fixup = 0;
    size_t bufsz, tmpsz;
    uint64_t tmp;

    err = vint_to_u64(x, &tmp, &tmpsz);
    if (err)
        return err;

    if (tmp == VINT_MAX_VAL(tmpsz)) /* VINT_DATA must not be set to all 1 */
        return -EINVAL;
    if (tmp == 0) /* VINT_DATA must not be set to all 0 */
        fixup = 1;

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
    return fixup ? -ENOTSUP : 0;
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

int
edata_unpack(const char *x, edata_t *y, enum etype etype, size_t sz)
{
    int err;
    unpack_fn_t *fn;

    static const struct ent {
        union {
            unpack_fn_t *fn;
            unpack_fn_t *const *fns;
        };
        int             nfns;
    } fns[] = {
        [ETYPE_INTEGER]     = {.fns = integer_fns,
                               .nfns = ARRAY_SIZE(integer_fns)},
        [ETYPE_UINTEGER]    = {.fns = uinteger_fns,
                               .nfns = ARRAY_SIZE(uinteger_fns)},
        [ETYPE_FLOAT]       = {.fns = float_fns,
                               .nfns = ARRAY_SIZE(float_fns)},
        [ETYPE_STRING]      = {.fn  = &unpack_string,   .nfns = -1},
        [ETYPE_UTF8]        = {.fn  = &unpack_utf8,     .nfns = -1},
        [ETYPE_DATE]        = {.fns = date_fns,
                               .nfns = ARRAY_SIZE(date_fns)},
        [ETYPE_BINARY]      = {.fn  = &unpack_binary,   .nfns = -1}
    };
    const struct ent *fnsp;

    if (etype >= ARRAY_SIZE(fns))
        return -EINVAL;
    fnsp = &fns[etype];
    if (fnsp->nfns == 0)
        return -EINVAL;

    if (fnsp->nfns == -1)
        fn = fnsp->fn;
    else {
        if (sz > INT_MAX || (int)sz >= fnsp->nfns)
            return -EINVAL;
        fn = fnsp->fns[sz];
        if (fn == NULL)
            return -EINVAL;
    }

    err = (*fn)(x, y);
    if (!err)
        y->type = etype;

    return err;
}

/* vi: set expandtab sw=4 ts=4: */
