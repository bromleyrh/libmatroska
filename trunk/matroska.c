/*
 * matroska.c
 */

#include "matroska.h"

#include <stdio.h>

int
matroska_tracknumber_handler(const char *val, void *ctx)
{
    (void)ctx;

    fprintf(stderr, "%s(): %s\n", __FUNCTION__, val);

    return 0;
}

int
matroska_simpleblock_handler(const char *val, void *ctx)
{
    (void)ctx;

    fprintf(stderr, "%s(): %s\n", __FUNCTION__, val);

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
