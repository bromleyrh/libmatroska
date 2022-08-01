/*
 * ebml.c
 */

#include "common.h"
#include "ebml.h"
#include "parser.h"

#include <malloc_ext.h>

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/types.h>

struct ebml_hdl {
    const ebml_io_fns_t *fns;
    const struct parser *parser;
    void                *ctx;
};

struct ebml_file_ctx {
    int fd;
};

static int ebml_file_open(void **, void *);
static int ebml_file_close(void *);

static int ebml_file_read(void *, void *, ssize_t *);

const ebml_io_fns_t ebml_file_fns = {
    .open   = &ebml_file_open,
    .close  = &ebml_file_close,
    .read   = &ebml_file_read
};

static int
ebml_file_open(void **ctx, void *args)
{
    int err;
    struct ebml_file_args *a;
    struct ebml_file_ctx *ret;

    if (omalloc(&ret) == NULL)
        return -errno;

    a = args;

    if (a->pathname == NULL)
        ret->fd = a->fd;
    else {
        ret->fd = openat(a->fd, a->pathname, O_CLOEXEC | O_RDONLY);
        if (ret->fd == -1) {
            err = -errno;
            free(ret);
            return err;
        }
    }

    *ctx = ret;
    return 0;
}

static int
ebml_file_close(void *ctx)
{
    int err;
    struct ebml_file_ctx *fctx = ctx;

    err = close(fctx->fd);

    free(fctx);

    return err;
}

static int
ebml_file_read(void *ctx, void *buf, ssize_t *nbytes)
{
    ssize_t ret;
    struct ebml_file_ctx *fctx = ctx;

    for (;;) {
        ret = read(fctx->fd, buf, *nbytes);
        if (ret >= 0)
            break;
        if (errno != EINTR)
            return -errno;
    }

    *nbytes = ret;
    return 0;
}

EXPORTED int
ebml_open(ebml_hdl_t *hdl, const ebml_io_fns_t *fns,
          const struct parser *parser, void *args)
{
    int err;
    struct ebml_hdl *ret;

    if (omalloc(&ret) == NULL)
        return -errno;

    err = (*fns->open)(&ret->ctx, args);
    if (err) {
        free(ret);
        return err;
    }

    ret->fns = fns;
    ret->parser = parser;

    *hdl = ret;
    return 0;
}

EXPORTED int
ebml_close(ebml_hdl_t hdl)
{
    int err;

    err = (*hdl->fns->close)(hdl->ctx);

    free(hdl);

    return err;
}

EXPORTED int
ebml_dump(FILE *f, ebml_hdl_t hdl)
{
    (void)f;
    (void)hdl;

    return -ENOSYS;
}

/* vi: set expandtab sw=4 ts=4: */
