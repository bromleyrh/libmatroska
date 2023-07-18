/*
 * util.h
 */

#ifndef _UTIL_H
#define _UTIL_H

#include "config.h"

#include <time.h>
#include <stddef.h>

#ifdef HAVE_FLS
#include <strings.h>
#endif

#define power_of_2(x) ((~((x) - 1) & (x)) == (x))

#ifndef HAVE_FLS
int fls(int i);

#endif
int al64(const char *a, long int *l);

int strerror_rp(int errnum, char *strerrbuf, size_t buflen);

char *strperror_r(int errnum, char *strerrbuf, size_t buflen);

char *_strptime(const char *s, const char *format, struct tm *tm);

#endif

/* vi: set expandtab sw=4 ts=4: */
