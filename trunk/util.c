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
#include <string.h>

#ifdef __APPLE__
#include <xlocale.h>
#endif

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
    err = errno;
    errno = old_errno;
    if (ret == NULL)
        return err ? err : EIO;

    return strlcpy(strerrbuf, ret, buflen) < buflen ? err : ERANGE;
#else
    (void)loc;

    return strerror_r(errnum, strerrbuf, buflen);
#endif
}

#ifndef HAVE_FLS
int
fls(int i)
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

#endif

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
        if (err == EINVAL)
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
