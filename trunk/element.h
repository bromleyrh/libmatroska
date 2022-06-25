/*
 * element.h
 */

#ifndef _ELEMENT_H
#define _ELEMENT_H

#include <stddef.h>
#include <stdint.h>

#define EDATASZ_UNKNOWN (~0ull)

int eid_to_u64(const char *x, uint64_t *y, size_t *sz);

int u64_to_eid(uint64_t x, char *y, size_t *bufsz);

uint64_t vintmax(size_t len);

int edatasz_to_u64(const char *x, uint64_t *y, size_t *sz);

int u64_to_edatasz(uint64_t x, char *y, size_t *bufsz);

int u64_to_edatasz_l(uint64_t x, char *y, size_t bufsz);

#endif

/* vi: set expandtab sw=4 ts=4: */
