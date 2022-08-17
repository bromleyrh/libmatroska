/*
 * matroska.c
 */

#include "matroska.h"

#include <stddef.h>
#include <stdio.h>

int
matroska_tracknumber_handler(const char *val, const void *buf, size_t len,
                             void *ctx)
{
    (void)buf;
    (void)len;
    (void)ctx;

    if (val == NULL)
        fputs("...\n", stderr);
    else
        fprintf(stderr, "%s(): %s\n", __FUNCTION__, val);

    return 0;
}

int
matroska_simpleblock_handler(const char *val, const void *buf, size_t len,
                             void *ctx)
{
    (void)buf;
    (void)len;
    (void)ctx;

    if (val == NULL)
        fputs("...\n", stderr);
    else
        fprintf(stderr, "%s(): %s\n", __FUNCTION__, val);

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
