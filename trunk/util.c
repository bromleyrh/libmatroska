/*
 * util.c
 */

#include "config.h"

#include "common.h"
#include "util.h"

#include <strings_ext.h>

#include <errno.h>
#include <locale.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __APPLE__
#include <xlocale.h>
#endif

#define TZ_ENV "TZ"

#define TZ_ENV_VAL_UTC "UTC"

static int get_locale(locale_t *);

static int strerror_lr(int, char *, size_t, locale_t);

static int
get_locale(locale_t *loc)
{
    locale_t ret;

    ret = uselocale((locale_t)0);
    if (ret == (locale_t)0)
        return ERRNO;

    ret = duplocale(ret);
    if (ret == (locale_t)0)
        return ERRNO;

    *loc = ret;
    return 0;
}

static int
strerror_lr(int errnum, char *strerrbuf, size_t buflen, locale_t loc)
{
#ifdef HAVE_STRERROR_L
    char *ret;
    int err, old_errno;

    old_errno = errno;
    errno = 0;
    ret = strerror_l(errnum, loc);
    err = en;
    errno = old_errno;
    if (ret == NULL)
        return err ? err : E_IO;

    return _strlcpy(strerrbuf, ret, buflen) < buflen ? err : E_RANGE;
#else
    (void)loc;

    return strerror_r(errnum, strerrbuf, buflen);
#endif
}

int
_fls(int i)
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

#define BITS_PER_CHAR 6

int
al64(const char *a, long int *l)
{
    long int ret = 0;
    size_t i;

    for (i = 0; a[i] != '\0'; i++) {
        long int val;
        size_t hi, lo;

        static const struct ent {
            char    first;
            char    last;
            int     base;
        } cmap[] = {
            {'.', '.',  0},
            {'/', '/',  1},
            {'0', '9',  2},
            {'A', 'Z', 12},
            {'a', 'z', 38}
        };
        const struct ent *ent;

        lo = 0;
        hi = ARRAY_SIZE(cmap);
        for (;;) {
            size_t idx;

            idx = lo + (hi - lo) / 2;
            ent = &cmap[idx];
            if (a[i] >= ent->first && a[i] <= ent->last)
                break;
            if (a[i] < ent->first)
                hi = idx;
            else
                lo = idx + 1;
            if (hi == lo)
                return -1;
        }
        val = a[i] - ent->first + ent->base;

        ret |= val << i * BITS_PER_CHAR;
    }

    *l = ret;
    return 0;
}

#undef BITS_PER_CHAR

/*
 * Note: In this emulation of timegm(), the TZ environment variable may not be
 * restored to its original value on error from unsetenv() or setenv(). It is
 * therefore necessary for the caller to check for a return value of (time_t)-1
 * from _timegm() and take an appropriate action in this case.
 */
time_t
_timegm(struct tm *timeptr)
{
    char *tz;
    int old_errno;
    int tmp;
    int utc_env;
    time_t ret;

    tz = getenv(TZ_ENV);
    utc_env = tz != NULL && strcmp(tz, TZ_ENV_VAL_UTC) == 0;

    if (!utc_env) {
        old_errno = errno;
        tmp = setenv(TZ_ENV, TZ_ENV_VAL_UTC, 1);
        errno = old_errno;
        if (tmp == -1)
            goto err;
    }

    ret = mktime(timeptr);

    if (!utc_env) {
        old_errno = errno;
        tmp = tz == NULL ? unsetenv(TZ_ENV) : setenv(TZ_ENV, tz, 1);
        errno = old_errno;
        if (tmp == -1)
            goto err;
    }

    return ret;

err:
    return (time_t)-1;
}

int
strerror_rp(int errnum, char *strerrbuf, size_t buflen)
{
    int err;
    locale_t loc;

    err = get_locale(&loc);
    if (!err) {
        err = strerror_lr(errnum, strerrbuf, buflen, loc);
        freelocale(loc);
    }

    return err;
}

char *
strperror_r(int errnum, char *strerrbuf, size_t buflen)
{
#ifdef HAVE_STRERROR_L
    char *ret;
    int err;
    locale_t loc;

    static _Thread_local char buf[32];

    if (get_locale(&loc) != 0) {
        snprintf(buf, sizeof(buf), "%d", errnum);
        return buf;
    }

    err = strerror_lr(errnum, strerrbuf, buflen, loc);
    ret = err ? strerror_l(errnum, loc) : strerrbuf;
    freelocale(loc);
    return ret;
#else
    const char *fmt = "%d";
    int err;
    locale_t loc;

    static _Thread_local char buf[32];

    err = get_locale(&loc);
    if (err)
        goto err;

    err = strerror_lr(errnum, strerrbuf, buflen, loc);
    freelocale(loc);
    if (err) {
        if (err == E_INVAL)
            fmt = "Unknown error %d";
        goto err;
    }

    return strerrbuf;

err:
    snprintf(buf, sizeof(buf), fmt, errnum);
    return buf;
#endif
}

/* vi: set expandtab sw=4 ts=4: */
