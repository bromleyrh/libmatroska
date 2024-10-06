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

int _fls(int i);

int al64(const char *a, long int *l);

int strerror_rp(int errnum, char *strerrbuf, size_t buflen);

char *strperror_r(int errnum, char *strerrbuf, size_t buflen);

char *_strptime(const char *s, const char *format, struct tm *tm);

#endif

/* vi: set expandtab sw=4 ts=4: */
