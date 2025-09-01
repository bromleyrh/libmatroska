/*
 * std_sys.h
 */

#ifndef _STD_SYS_H
#define _STD_SYS_H

#include "util.h"

#include <stddef.h>

enum {
#define X(nm, ...) \
    SYS_E##nm = E_##nm,
    LIST_ERRNO(X)
#undef X
};

int sys_maperrn(void);

int sys_maperror(int errnum);

int sys_rmaperror(int errnum);

char *sys_strerror(int errnum);

int sys_strerror_r(int errnum, char *strerrbuf, size_t buflen);

#endif

/* vi: set expandtab sw=4 ts=4: */
