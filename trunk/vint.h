/*
 * vint.h
 */

#ifndef _VINT_H
#define _VINT_H

#include <stddef.h>
#include <stdint.h>

int vint_to_u64(const char *x, uint64_t *y);

int u64_to_vint(uint64_t x, char *y, size_t bufsz);
int u64_to_vint_l(uint64_t x, char *y, size_t bufsz);

#endif

/* vi: set expandtab sw=4 ts=4: */
