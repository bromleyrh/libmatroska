/*
 * strptime.c
 */

#define _XOPEN_SOURCE

#include <time.h>

char *
_strptime(const char *s, const char *format, struct tm *tm)
{
    return strptime(s, format, tm);
}

/* vi: set expandtab sw=4 ts=4: */
