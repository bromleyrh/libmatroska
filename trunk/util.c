/*
 * util.c
 */

#include "config.h"

#include "util.h"

#ifndef HAVE_FLS
int
fls(int i)
{
    int pos;
    unsigned val;

    if (!i)
        return 0;

    val = (unsigned)i;

    pos = 32;
    if (!(val & 0xffff0000)) {
        val <<= 16;
        pos -= 16;
    }
    if (!(val & 0xff000000)) {
        val <<= 8;
        pos -= 8;
    }
    if (!(val & 0xf0000000)) {
        val <<= 4;
        pos -= 4;
    }
    if (!(val & 0xc0000000)) {
        val <<= 2;
        pos -= 2;
    }
    if (!(val & 0x80000000))
        pos -= 1;

    return pos;
}

#endif

/* vi: set expandtab sw=4 ts=4: */
