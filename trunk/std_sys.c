/*
 * std_sys.c
 */

#define NO_ASSERT_MACROS
#include "common.h"
#include "debug.h"
#undef NO_ASSERT_MACROS

#include "errtbl.h"
#include "std_sys.h"
#include "util.h"

#include <errno.h>
#include <locale.h>
#include <stddef.h>
#include <string.h>

#ifdef __APPLE__
#include <xlocale.h>
#endif

#define ERRNUM_DFL IO

#define ___ERRNO_DFL(prefix, err) prefix##err
#define __ERRNO_DFL(...) ___ERRNO_DFL(__VA_ARGS__)
#define _ERRNO_DFL(prefix) __ERRNO_DFL(prefix, ERRNUM_DFL)

#define SYS_ERRNO_DFL _ERRNO_DFL(SYS_E)
#define ERRNO_DFL _ERRNO_DFL(E)

static int get_locale(locale_t *);

static int strerror_lr(int, char *, size_t, locale_t);

static int _strerror_rp(int, char *, size_t);

static int map_errno(int);
static int rmap_errno(int);

static int
get_locale(locale_t *loc)
{
    locale_t ret;

    ret = uselocale((locale_t)0);
    if (ret == (locale_t)0)
        return errno;

    ret = duplocale(ret);
    if (ret == (locale_t)0)
        return errno;

    *loc = ret;
    return 0;
}

static int
strerror_lr(int errnum, char *strerrbuf, size_t buflen, locale_t loc)
{
#ifdef HAVE_STRERROR_L
    char *ret;
    int err, old_errno;
    size_t i;

    old_errno = errno;
    errno = 0;
    ret = strerror_l(errnum, loc);
    err = errno;
    errno = old_errno;
    if (ret == NULL)
        return err ? err : EIO;

    for (i = 0;; i++) {
        if (i == buflen)
            return ERANGE;
        strerrbuf[i] = *ret;
        if (*ret == '\0')
            break;
        ++ret;
    }

    return err;
#else
    (void)loc;

    return strerror_r(errnum, strerrbuf, buflen);
#endif
}

static int
_strerror_rp(int errnum, char *strerrbuf, size_t buflen)
{
    int err;
    locale_t loc = 0;

    err = get_locale(&loc);
    if (!err) {
        err = strerror_lr(errnum, strerrbuf, buflen, loc);
        freelocale(loc);
    }

    return err;
}

static int
map_errno(int errn)
{
#ifdef ERRTBL
    int ret;
    size_t idx;

    if (errn == 0)
        return 0;

    if (errn < min_errn)
        return SYS_ERRNO_DFL;

    idx = errn - min_errn;

    if (idx >= ARRAY_SIZE(errtbl))
        return SYS_ERRNO_DFL;

    ret = errtbl[idx];

    return ret == 0 ? SYS_ERRNO_DFL : ret;
#else
    int num_errn;
    int ret;
    size_t idx, startidx;

    if (errn == 0)
        return 0;

    if (errn < min_errn)
        return SYS_ERRNO_DFL;

    num_errn = ARRAY_SIZE(errmap);

    idx = startidx = (errn - min_errn) % num_errn;
    for (;;) {
        const struct errmap_ent *ent = &errmap[idx];

        if (ent->src == errn) {
            ret = ent->dst;
            break;
        }
        idx = (idx + 1) % num_errn;
        if (idx == startidx) {
            ret = SYS_ERRNO_DFL;
            break;
        }
    }

    return ret;
#endif
}

static int
rmap_errno(int errn)
{
    int ret;

    if (errn == 0)
        return 0;

    if (errn >= (int)ARRAY_SIZE(errmapr))
        return ERRNO_DFL;

    ret = errmapr[errn];
    return ret == 0 ? ERRNO_DFL : ret;
}

int
sys_maperrn()
{
    return map_errno(errno);
}

int
sys_maperror(int errnum)
{
    return map_errno(errnum);
}

int
sys_rmaperror(int errnum)
{
    return rmap_errno(errnum);
}

int
sys_strerror_r(int errnum, char *strerrbuf, size_t buflen)
{
    return map_errno(_strerror_rp(rmap_errno(errnum), strerrbuf, buflen));
}

/* vi: set expandtab sw=4 ts=4: */
