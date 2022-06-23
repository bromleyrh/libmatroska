/*
 * element.h
 */

#ifndef _ELEMENT_H
#define _ELEMENT_H

#include <stddef.h>
#include <stdint.h>

int eid_to_u64(const char *x, uint64_t *y);

int u64_to_eid(uint64_t x, char *y, size_t bufsz);

#endif

/* vi: set expandtab sw=4 ts=4: */
