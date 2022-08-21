/*
 * zlib_stream.h
 */

#ifndef _ZLIB_STREAM_H
#define _ZLIB_STREAM_H

#include <stddef.h>

typedef struct zlib_stream *zlib_stream_hdl_t;

int zlib_stream_init(zlib_stream_hdl_t *hdl,
                     int (*cb)(const void *, size_t, void *), void *ctx);

int zlib_stream_destroy(zlib_stream_hdl_t hdl);

int zlib_stream_inflate(zlib_stream_hdl_t hdl, void *buf, size_t len);

#endif

/* vi: set expandtab sw=4 ts=4: */
