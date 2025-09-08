/*
 * matroska.h
 */

#ifndef _MATROSKA_H
#define _MATROSKA_H

#define _LIBMATROSKA_H_INTERNAL
#include <matroska/libmatroska_common.h>
#undef _LIBMATROSKA_H_INTERNAL

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct matroska_state *matroska_hdl_t;

typedef struct {
    int (*open)(void **, int, void *);
    int (*close)(void *);
    int (*read)(void *, void *, ssize_t *);
    int (*write)(void *, const void *, size_t);
    int (*sync)(void *);
    int (*get_fpos)(void *, int64_t *);
} matroska_io_fns_t;

#define MATROSKA_FD_CWD -128

struct matroska_file_args {
    int         fd;
    const char  *pathname;
};

enum matroska_metadata_type {
    MATROSKA_TYPE_INTEGER = 1,
    MATROSKA_TYPE_UINTEGER,
    MATROSKA_TYPE_DOUBLE,
    MATROSKA_TYPE_BYTES
};

typedef struct {
    enum matroska_metadata_type type;
    union {
        int64_t     integer;
        uint64_t    uinteger;
        double      dbl;
        struct {
            char    *data;
            size_t  len;
        };
    };
} matroska_metadata_t;

typedef int matroska_metadata_output_cb_t(const char *, matroska_metadata_t *,
                                          size_t, size_t, int, void *);

typedef int matroska_bitstream_output_cb_t(uint64_t, const void *, size_t,
                                           size_t, size_t, size_t, size_t,
                                           int64_t, int16_t, int, int, void *);

typedef int matroska_bitstream_input_cb_t(uint64_t *, void *, ssize_t *,
                                          int16_t *, int *, void *);

typedef union {
    matroska_metadata_output_cb_t *output_cb;
} matroska_metadata_cb_t;

typedef union {
    matroska_bitstream_output_cb_t  *output_cb;
    matroska_bitstream_input_cb_t   *input_cb;
} matroska_bitstream_cb_t;

struct matroska_error_info {
    int errcode;
};

#define MATROSKA_OPEN_FLAG_RDONLY 1

#define MATROSKA_READ_FLAG_HEADER 1
#define MATROSKA_READ_FLAG_MASTER 2

#define MATROSKA_WRITE_FLAG_HEADER 1

#define MATROSKA_METADATA_FLAG_FRAGMENT 1
#define MATROSKA_METADATA_FLAG_HEADER 2

int matroska_open(matroska_hdl_t *hdl, matroska_io_fns_t *fns,
                  matroska_metadata_cb_t *metacb, matroska_bitstream_cb_t *cb,
                  int flags, void *args, void *ctx);

int matroska_close(matroska_hdl_t hdl);

int matroska_read(FILE *f, matroska_hdl_t hdl, int flags);

int matroska_read_header(FILE *f, matroska_hdl_t hdl, int flags);

int matroska_read_body(FILE *f, matroska_hdl_t hdl, int flags);

int matroska_write(matroska_hdl_t hdl, const char *id, matroska_metadata_t *val,
                   size_t *len, size_t *hdrlen,
                   int (*master_cb)(const char *, size_t, size_t, void *,
                                    void *),
                   void (*master_free_cb)(void *, void *), void *mdata,
                   void *mctx, int flags);

int matroska_error(struct matroska_error_info *info, int errdes, int flags);

#ifdef __cplusplus
}
#endif

#endif

