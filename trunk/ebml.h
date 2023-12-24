/*
 * ebml.h
 */

#ifndef _EBML_H
#define _EBML_H

#include "matroska.h"
#include "parser.h"

#include <stddef.h>
#include <stdio.h>

#include <sys/types.h>

typedef struct ebml_hdl *ebml_hdl_t;

typedef struct {
    int (*open)(void **, int, void *);
    int (*close)(void *);
    int (*read)(void *, void *, ssize_t *);
    int (*write)(void *, const void *, size_t);
    int (*sync)(void *);
    int (*get_fpos)(void *, off_t *);
} ebml_io_fns_t;

struct ebml_file_args {
    int         fd;
    const char  *pathname;
};

struct buf;

typedef int ebml_metadata_cb_t(const char *, matroska_metadata_t *, size_t,
                               size_t, int, void *);

typedef int ebml_master_cb_t(const char *, size_t, size_t, void *, void *);
typedef void ebml_master_free_cb_t(void *, void *);

extern const ebml_io_fns_t ebml_file_fns;
#define EBML_FILE_FNS (&ebml_file_fns)

#define EBML_READ_FLAG_HEADER 1
#define EBML_READ_FLAG_MASTER 2

#define EBML_WRITE_FLAG_HEADER 1

int ebml_open(ebml_hdl_t *hdl, const ebml_io_fns_t *fns,
              const struct parser *parser,
              const struct semantic_processor *sproc, ebml_metadata_cb_t *cb,
              int ro, void *args, void *sproc_ctx, void *ctx);

int ebml_close(ebml_hdl_t hdl);

int ebml_read(FILE *f, ebml_hdl_t hdl, int flags);

int ebml_read_header(FILE *f, ebml_hdl_t hdl, int flags);

int ebml_read_body(FILE *f, ebml_hdl_t hdl, int flags);

int ebml_write(ebml_hdl_t hdl, const char *id, matroska_metadata_t *val,
               size_t *len, size_t *hdrlen, ebml_master_cb_t *master_cb,
               ebml_master_free_cb_t *master_free_cb, void *mdata, void *mctx,
               int flags);

void *ebml_ctx(ebml_hdl_t hdl);

int buf_set_binhdr(struct buf *buf, char *binhdr, size_t binhdrsz);

#endif

/* vi: set expandtab sw=4 ts=4: */
