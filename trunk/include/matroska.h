/*
 * matroska.h
 */

#ifndef _MATROSKA_H
#define _MATROSKA_H

#define _LIBMATROSKALITE_H_INTERNAL
#include <matroska/libmatroskalite_common.h>
#undef _LIBMATROSKALITE_H_INTERNAL

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct matroska_state *matroska_hdl_t;

typedef int matroska_bitstream_cb_t(uint64_t, const void *, size_t, void *);

int matroska_open(matroska_hdl_t *hdl, int fd, const char *pathname,
                  matroska_bitstream_cb_t *cb, void *ctx);

int matroska_close(matroska_hdl_t hdl);

int matroska_read(FILE *f, matroska_hdl_t hdl);

#ifdef __cplusplus
}
#endif

#endif

