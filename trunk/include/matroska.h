/*
 * matroska.h
 */

#ifndef _MATROSKA_H
#define _MATROSKA_H

#define _LIBMATROSKALITE_H_INTERNAL
#include <matroska/libmatroskalite_common.h>
#undef _LIBMATROSKALITE_H_INTERNAL

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

struct matroska_state {
    int     block_hdr;
    char    hdr_buf[8];
    size_t  hdr_len;
    size_t  hdr_sz;
};

#ifdef __cplusplus
}
#endif

#endif

