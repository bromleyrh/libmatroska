/*
 * zlib_stream.h
 */

#ifndef _ZLIB_STREAM_H
#define _ZLIB_STREAM_H

#include "common.h"

#include <stddef.h>

typedef struct zlib_stream *zlib_stream_hdl_t;

EXPORTED int zlib_stream_init(zlib_stream_hdl_t *hdl,
                              int (*cb)(const void *, size_t, void *),
                              void *ctx);

EXPORTED int zlib_stream_destroy(zlib_stream_hdl_t hdl);

EXPORTED int zlib_stream_inflate(zlib_stream_hdl_t hdl, void *buf, size_t len,
                                 size_t *remlen);

#endif

/* vi: set expandtab sw=4 ts=4: */