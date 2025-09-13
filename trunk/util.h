/*
 * util.h
 */

#ifndef _UTIL_H
#define _UTIL_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define UINT64_BIT (sizeof(uint64_t) * CHAR_BIT)

#define power_of_2(x) ((~((x) - 1) & (x)) == (x))

#define _E_AGAIN 11
#define _E_OPNOTSUPP 95

#define LIST_ERRNO(X) \
    X(PERM,              1) X(FBIG,        27) X(NOPROTOOPT,               92) \
    X(NOENT,             2) X(NOSPC,       28) X(PROTONOSUPPORT,           93) \
    X(SRCH,              3) X(SPIPE,       29) X(OPNOTSUPP,      _E_OPNOTSUPP) \
    X(INTR,              4) X(ROFS,        30) X(NOTSUP,         _E_OPNOTSUPP) \
    X(IO,                5) X(MLINK,       31) X(AFNOSUPPORT,              97) \
    X(NXIO,              6) X(PIPE,        32) X(ADDRINUSE,                98) \
    X(2BIG,              7) X(DOM,         33) X(ADDRNOTAVAIL,             99) \
    X(NOEXEC,            8) X(RANGE,       34) X(NETDOWN,                 100) \
    X(BADF,              9) X(DEADLK,      35) X(NETUNREACH,              101) \
    X(CHILD,            10) X(NAMETOOLONG, 36) X(NETRESET,                102) \
    X(AGAIN,      _E_AGAIN) X(NOLCK,       37) X(CONNABORTED,             103) \
    X(WOULDBLOCK, _E_AGAIN) X(NOSYS,       38) X(CONNRESET,               104) \
    X(NOMEM,            12) X(NOTEMPTY,    39) X(NOBUFS,                  105) \
    X(ACCES,            13) X(LOOP,        40) X(ISCONN,                  106) \
    X(FAULT,            14) X(NOMSG,       42) X(NOTCONN,                 107) \
    X(BUSY,             16) X(IDRM,        43) X(TIMEDOUT,                110) \
    X(EXIST,            17) X(NOLINK,      67) X(CONNREFUSED,             111) \
    X(XDEV,             18) X(PROTO,       71) X(HOSTUNREACH,             113) \
    X(NODEV,            19) X(MULTIHOP,    72) X(ALREADY,                 114) \
    X(NOTDIR,           20) X(BADMSG,      74) X(INPROGRESS,              115) \
    X(ISDIR,            21) X(OVERFLOW,    75) X(STALE,                   116) \
    X(INVAL,            22) X(ILSEQ,       84) X(DQUOT,                   122) \
    X(NFILE,            23) X(NOTSOCK,     88) X(CANCELED,                125) \
    X(MFILE,            24) X(DESTADDRREQ, 89) X(OWNERDEAD,               130) \
    X(NOTTY,            25) X(MSGSIZE,     90) X(NOTRECOVERABLE,          131) \
    X(TXTBSY,           26) X(PROTOTYPE,   91)

enum {
#define X(nm, no) \
    E_##nm = no,
    LIST_ERRNO(X)
#undef X
};

int _fls(int i);

int al64(const char *a, long int *l);

time_t _timegm(struct tm *timeptr);

int syncfd(int fd);

char *_strptime(const char *s, const char *format, struct tm *tm);

int strerror_rp(int errnum, char *strerrbuf, size_t buflen);

char *strperror_r(int errnum, char *strerrbuf, size_t buflen);

#endif

/* vi: set expandtab sw=4 ts=4: */
