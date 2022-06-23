/*
 * element.c
 */

#include "element.h"
#include "vint.h"

#include <stddef.h>
#include <stdint.h>

int
eid_to_u64(const char *x, uint64_t *y)
{
    (void)x;
    (void)y;

    return 0;
}

int
u64_to_eid(uint64_t x, char *y, size_t bufsz)
{
    return u64_to_vint(x, y, bufsz);
}

/* vi: set expandtab sw=4 ts=4: */
