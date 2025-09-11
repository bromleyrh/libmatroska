/*
 * std_sys.c
 */

#define _FILE_OFFSET_BITS 64

#include "config.h"

#define NO_ASSERT_MACROS
#include "common.h"
#include "debug.h"
#undef NO_ASSERT_MACROS

#include "errtbl.h"
#include "std_sys.h"
#include "util.h"

#include <errno.h>
#include <fcntl.h>
#include <locale.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __APPLE__
#include <xlocale.h>
#endif

#include <sys/stat.h>
#include <sys/types.h>

_Thread_local int sys_errno;

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

static int call_sv_errno(int (*)(va_list), va_list);

static int sys_call(int (*)(va_list), ...);

static int _sys_call_nocancel(va_list);

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

static int
call_sv_errno(int (*fn)(va_list), va_list ap)
{
    int old_errno;
    int ret;

    old_errno = errno;

    errno = 0;
    ret = (*fn)(ap);
    sys_errno = map_errno(errno);

    errno = old_errno;

    return ret;
}

static int
sys_call(int (*fn)(va_list), ...)
{
    int ret;
    va_list ap;

    va_start(ap, fn);
    ret = call_sv_errno(fn, ap);
    va_end(ap);

    return ret;
}

static int
_sys_call_nocancel(va_list ap)
{
    int (*fn)(va_list);
    int ret;

    fn = va_arg(ap, int (*)(va_list));

    for (;;) {
        va_list argp;

        va_copy(argp, ap);
        ret = (*fn)(argp);
        va_end(argp);
        if (ret != -1 || errno != EINTR)
            break;
        errno = 0;
    }

    return ret;
}

#define _na(...)

#define _sys_call_nocancel(...) sys_call(&_sys_call_nocancel, __VA_ARGS__)

#define _expand_sys_call_name(name) name

#define _expand_type_and_name_0(type, name) type name
#define _expand_type_and_name(type, name) , type name

#define _expand_type(type) type

#define _expand_itype(type) type
#define _expand_itypep(type) type *

#define _expand_type_cvt(type_int, type) type

#define _expand_itype_cvt(type_int, type) type_int
#define _expand_itypep_cvt(type_int, type) type_int *

#define _expand_name_0(type, name) name
#define _expand_name(type, name) , name

#define _expand_name_append_0 _expand_name_append
#define _expand_name_append _expand_name

#define _expand_name_cvt_append_0 _expand_name_cvt_append
#define _expand_name_cvt_append(type, name) , (type)name

#define _def_args_0 _def_args
#define _def_args(type, name) type name = va_arg(ap, type);

#define _cvt(dsttype, srctype) dsttype
#define _nocvt(dsttype, srctype) srctype

#define _NAME __SYS_CALL__(_expand_sys_call_name, _na, _na)
#define _PARAM_LIST(X) __SYS_CALL__(_na, X##_0, X)

#define _NAME_RETV __SYS_CALL__(_expand_sys_call_name, _na, _na, _na, _na, _na)
#define _PARAM_LIST_RETV(X, XCVT) __SYS_CALL__(_na, _na, _na, X##_0, X, XCVT)
#define _TYPE_RETV(X) __SYS_CALL__(_na, X, X##_cvt, _na, _na, _na)

#define ___DEF_SYS_CALL(fn, nm) \
static int _sys_##nm(va_list); \
\
int \
sys_##nm(_PARAM_LIST(_expand_type_and_name)) \
{ \
    return fn(&_sys_##nm _PARAM_LIST(_expand_name_append)); \
} \
\
static int \
_sys_##nm(va_list ap) \
{ \
    _PARAM_LIST(_def_args) \
    \
    (void)ap;

#define RET(val) \
        return val; \
    } \
\
    return -1

#define ___DEF_SYS_CALL_RETV(fn, nm) \
static int _sys_##nm(va_list); \
\
_TYPE_RETV(_expand_type) \
sys_##nm(_PARAM_LIST_RETV(_expand_type_and_name, _nocvt)) \
{ \
    _TYPE_RETV(_expand_itype) ret; \
\
    return fn(&_sys_##nm, \
              &ret _PARAM_LIST_RETV(_expand_name_cvt_append, _cvt)) \
           == -1 ? -1 : (_TYPE_RETV(_expand_type))ret; \
} \
\
static int \
_sys_##nm(va_list ap) \
{ \
    _TYPE_RETV(_expand_itype) ret; \
    _TYPE_RETV(_expand_itypep) retp = va_arg(ap, _TYPE_RETV(_expand_itypep)); \
    _PARAM_LIST_RETV(_def_args, _nocvt)

#define CALL_AND_RET RET(_NAME(_PARAM_LIST(_expand_name)))

#define CALL_AND_RET_RETV \
        ret = _NAME_RETV(_PARAM_LIST_RETV(_expand_name, _nocvt)); \
        if (ret != -1) { \
            *retp = ret; \
            return 0; \
        } \
    } \
\
    return -1

#define __DEF_SYS_CALL(fn, nm, nm_suf) ___DEF_SYS_CALL(fn, nm##nm_suf)
#define __DEF_SYS_CALL_RETV(fn, nm, nm_suf) ___DEF_SYS_CALL_RETV(fn, nm##nm_suf)

#define _DEF_SYS_CALL(...) __DEF_SYS_CALL(__VA_ARGS__)
#define _DEF_SYS_CALL_RETV(...) __DEF_SYS_CALL_RETV(__VA_ARGS__)

#define DEF_SYS_CALL _DEF_SYS_CALL(sys_call, _NAME, )
#define DEF_SYS_CALL_NOCANCEL \
    _DEF_SYS_CALL(_sys_call_nocancel, _NAME, _nocancel)

#define DEF_SYS_CALL_RETV _DEF_SYS_CALL_RETV(sys_call, _NAME_RETV, )
#define DEF_SYS_CALL_RETV_NOCANCEL \
    _DEF_SYS_CALL_RETV(_sys_call_nocancel, _NAME_RETV, _nocancel)

#define __SYS_CALL__(SYS_CALL, X1, X) \
SYS_CALL(openat) \
    X1(int,          dirfd) \
    X( const char *, pathname) \
    X( int,          flags)
DEF_SYS_CALL
{
    if (dirfd == SYS_AT_FDCWD)
        dirfd = AT_FDCWD;

    CALL_AND_RET;
}
#undef __SYS_CALL__

#define __SYS_CALL__(SYS_CALL, X1, X) \
SYS_CALL(dup) \
    X1(int, oldfd)
DEF_SYS_CALL
{
    CALL_AND_RET;
}
#undef __SYS_CALL__

#define __SYS_CALL__(SYS_CALL, X1, X) \
SYS_CALL(dup2) \
    X1(int, oldfd) \
    X( int, newfd)
DEF_SYS_CALL_NOCANCEL
{
    CALL_AND_RET;
}
#undef __SYS_CALL__

#define __SYS_CALL__(SYS_CALL, X1, X) \
SYS_CALL(close) \
    X1(int, fd)
DEF_SYS_CALL
{
    CALL_AND_RET;
}
#undef __SYS_CALL__

#define __SYS_CALL__(SYS_CALL, X1, X) \
SYS_CALL(close) \
    X1(int, fd)
DEF_SYS_CALL_NOCANCEL
{
#ifdef POSIX_CLOSE_RESTART
    RET(posix_close(fd, 0));
#else
    (void)fd;

    errno = ENOTSUP;
    RET(-1);
#endif
}
#undef __SYS_CALL__

#define __SYS_CALL__(SYS_CALL, RETV, RETV_CVT, X1, X, CVT) \
SYS_CALL(lseek) \
    RETV_CVT(off_t, int64_t) \
    X1(               int, fd) \
    X(CVT(off_t, int64_t), offset) \
    X(                int, whence)
DEF_SYS_CALL_RETV
{
    CALL_AND_RET_RETV;
}
#undef __SYS_CALL__

int
sys_fseek64(FILE *stream, off_t offset, int whence)
{
    return fseeko(stream, offset, whence);
}

int64_t
sys_ftell64(FILE *stream)
{
    return ftello(stream);
}

#define __SYS_CALL__(SYS_CALL, RETV, RETV_CVT, X1, X, CVT) \
SYS_CALL(read) \
    RETV(ssize_t) \
    X1(  int, fd) \
    X(void *, buf) \
    X(size_t, count)
DEF_SYS_CALL_RETV_NOCANCEL
{
    CALL_AND_RET_RETV;
}
#undef __SYS_CALL__

#define __SYS_CALL__(SYS_CALL, RETV, RETV_CVT, X1, X, CVT) \
SYS_CALL(write) \
    RETV(ssize_t) \
    X1(        int, fd) \
    X(const void *, buf) \
    X(      size_t, count)
DEF_SYS_CALL_RETV_NOCANCEL
{
    CALL_AND_RET_RETV;
}
#undef __SYS_CALL__

#define __SYS_CALL__(SYS_CALL, X1, X) \
SYS_CALL(fsync) \
    X1(int, fd)
DEF_SYS_CALL_NOCANCEL
{
    CALL_AND_RET;
}
#undef __SYS_CALL__

#define DEF_SYS_FILENO(nm, val) \
int \
sys_std##nm##_fileno() \
{ \
    return STD##val##_FILENO; \
}

DEF_SYS_FILENO(in, IN)
DEF_SYS_FILENO(out, OUT)
DEF_SYS_FILENO(err, ERR)

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

char *
sys_strerror(int errnum)
{
    return strerror(rmap_errno(errnum));
}

int
sys_strerror_r(int errnum, char *strerrbuf, size_t buflen)
{
    return map_errno(_strerror_rp(rmap_errno(errnum), strerrbuf, buflen));
}

/* vi: set expandtab sw=4 ts=4: */
