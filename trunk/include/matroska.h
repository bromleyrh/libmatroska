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

#define LIST_BLOCK_HDR_FIELDS() \
    _X(TRACKNO,     8) \
    _X(TIMESTAMP,   2) \
    _X(FLAGS,       1)

#define _X(nm, len) \
enum { \
    BLOCK_HDR_##nm##_LEN = len \
};
LIST_BLOCK_HDR_FIELDS()
#undef _X

struct matroska_state {
    int     block_hdr;
#define _X(nm, len) + len
    char    hdr_buf[LIST_BLOCK_HDR_FIELDS()];
#undef _X
    size_t  hdr_len;
    size_t  hdr_sz;
};

#ifdef __cplusplus
}
#endif

#endif

