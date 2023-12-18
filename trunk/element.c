/*
 * element.c
 */

#include "common.h"
#include "debug.h"
#include "element.h"
#include "util.h"
#include "vint.h"

#include <errno.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef int unpack_fn_t(const char *, edata_t *, size_t);

#define TIME_T_MIN (~(time_t)0)
#define TIME_T_MAX ((time_t)((unsigned)TIME_T_MIN >> 1))

#define TM_YEAR(year) ((year) - 1900)

#define REFERENCE_TIME \
    { \
        .tm_mday    = 1, \
        .tm_mon     = 1, \
        .tm_year    = TM_YEAR(2001), \
        .tm_isdst   = -1 \
    }

#define TIME_GRAN 1000000000

static unpack_fn_t unpack_integer;

static unpack_fn_t unpack_uinteger;

static unpack_fn_t unpack_float_4;
static unpack_fn_t unpack_float_8;

static unpack_fn_t unpack_string;

static unpack_fn_t unpack_date_8;

static unpack_fn_t unpack_binary;

static unpack_fn_t *const float_fns[] = {
    [4] = &unpack_float_4,
    [8] = &unpack_float_8
};

static unpack_fn_t *const date_fns[] = {
    [8] = &unpack_date_8
};

static int
unpack_integer(const char *x, edata_t *y, size_t sz)
{
    char byte;
    size_t i;

    --sz;
    if (power_of_2(sz + 1)) {
        for (i = 0; i <= sz; i++)
            y->bytes[i] = x[~i & sz];
    } else {
        for (i = 0; i <= sz; i++)
            y->bytes[i] = x[sz - i];
    }

    byte = (y->bytes[sz] & 1 << 7) >> 7 ? 0xff : 0;

    for (; i < sizeof(y->integer); i++)
        y->bytes[i] = byte;

    return 0;
}

static int
unpack_uinteger(const char *x, edata_t *y, size_t sz)
{
    size_t i;

    --sz;
    if (power_of_2(sz + 1)) {
        for (i = 0; i <= sz; i++)
            y->bytes[i] = x[~i & sz];
    } else {
        for (i = 0; i <= sz; i++)
            y->bytes[i] = x[sz - i];
    }

    for (; i < sizeof(y->uinteger); i++)
        y->bytes[i] = 0;

    return 0;
}

static int
unpack_float_4(const char *x, edata_t *y, size_t sz)
{
    size_t i;

    (void)sz;

    for (i = 0; i < 4; i++)
        y->bytes[i] = x[~i & 3];
    for (; i < sizeof(y->bytes); i++)
        y->bytes[i] = 0;

    y->dbl = 0;

    return 0;
}

static int
unpack_float_8(const char *x, edata_t *y, size_t sz)
{
    size_t i;

    (void)sz;

    for (i = 0; i < 8; i++)
        y->bytes[i] = x[~i & 7];

    y->dbl = 1;

    return 0;
}

static int
unpack_string(const char *x, edata_t *y, size_t sz)
{
    char *ret;

    ret = malloc(sz + 1);
    if (ret == NULL)
        return ERR_TAG(errno);

    ret[sz] = '\0';

    y->ptr = memcpy(ret, x, sz);
    return 0;
}

static int
unpack_date_8(const char *x, edata_t *y, size_t sz)
{
    size_t i;

    (void)sz;

    for (i = 0; i < 8; i++)
        y->bytes[i] = x[~i & 7];

    return 0;
}

static int
unpack_binary(const char *x, edata_t *y, size_t sz)
{
    char *ret;

    ret = malloc(sz);
    if (ret == NULL)
        return ERR_TAG(errno);

    y->ptr = memcpy(ret, x, sz);
    return 0;
}

EXPORTED int
eid_to_u64(const char *x, uint64_t *y, size_t *sz)
{
    char buf[8];
    int err, err_fixup = 0;
    size_t bufsz, tmpsz;
    uint64_t tmp;

    err = vint_to_u64(x, &tmp, &tmpsz);
    if (err)
        return err;

    if (tmp == VINT_MAX_VAL(tmpsz)) /* VINT_DATA must not be set to all 1 */
        return ERR_TAG(EINVAL);
    if (tmp == 0) /* VINT_DATA must not be set to all 0 */
        err_fixup = ERR_TAG(ENOTSUP);

    bufsz = sizeof(buf);
    err = u64_to_vint(tmp, buf, &bufsz);
    if (err)
        return err;
    if (tmp == VINT_MAX_VAL(bufsz))
        ++bufsz;

    if (tmpsz != bufsz) /* a shorter VINT_DATA encoding is available */
        return ERR_TAG(EINVAL);

    *y = tmp;
    *sz = tmpsz;
    return err_fixup;
}

EXPORTED int
u64_to_eid(uint64_t x, char *y, size_t *bufsz)
{
    return u64_to_vint(x, y, bufsz);
}

uint64_t
vintmax(size_t len)
{
    return (UINT64_C(1) << 7 * len) - 2;
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
    int err;
    size_t tmpsz;
    uint64_t tmp;

    if (x == EDATASZ_UNKNOWN) {
        x = vintmax(1) + 1;
        tmpsz = 1;
    } else {
        err = u64_to_vint(x, y, bufsz);
        if (err)
            return err;

        err = edatasz_to_u64(y, &tmp, &tmpsz);
        if (err || tmp != EDATASZ_UNKNOWN)
            return err;

        ++tmpsz;
    }

    err = u64_to_edatasz_l(x, y, tmpsz);
    if (!err)
        *bufsz = tmpsz;

    return err;
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
#define _X(type, val, name, hash) \
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
#define _X(type, val, name, hash) \
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
        [ETYPE_INTEGER]     = {.fn  = &unpack_integer,  .nfns = -1},
        [ETYPE_UINTEGER]    = {.fn  = &unpack_uinteger, .nfns = -1},
        [ETYPE_FLOAT]       = {.fns = float_fns,
                               .nfns = ARRAY_SIZE(float_fns)},
        [ETYPE_STRING]      = {.fn  = &unpack_string,   .nfns = -1},
        [ETYPE_UTF8]        = {.fn  = &unpack_string,   .nfns = -1},
        [ETYPE_DATE]        = {.fns = date_fns,
                               .nfns = ARRAY_SIZE(date_fns)},
        [ETYPE_BINARY]      = {.fn  = &unpack_binary,   .nfns = -1}
    };
    const struct ent *fnsp;

    if (etype >= ARRAY_SIZE(fns))
        return ERR_TAG(EINVAL);
    fnsp = &fns[etype];
    if (fnsp->nfns == 0)
        return ERR_TAG(EINVAL);

    if (fnsp->nfns == -1)
        fn = fnsp->fn;
    else {
        if (sz > INT_MAX || (int)sz >= fnsp->nfns)
            return ERR_TAG(EINVAL);
        fn = fnsp->fns[sz];
        if (fn == NULL)
            return ERR_TAG(EINVAL);
    }

    err = (*fn)(x, y, sz);
    if (!err)
        y->type = etype;

    return err;
}

int
edata_to_timespec(edata_t *x, struct timespec *y)
{
    int64_t s;
    struct tm tm = REFERENCE_TIME;
    time_t reftm;

    reftm = mktime(&tm);

    s = x->date / TIME_GRAN;

    if (s >= 0) {
        if ((int64_t)(TIME_T_MAX - reftm) < s)
            return ERR_TAG(EOVERFLOW);
    } else if ((int64_t)(TIME_T_MIN - reftm) > s)
        return ERR_TAG(EOVERFLOW);

    y->tv_sec = reftm + s;
    y->tv_nsec = x->date % TIME_GRAN;
    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
