/*
 * zlib_stream.c
 */

#include "common.h"
#include "zlib_stream.h"

#include <malloc_ext.h>

#undef in
#include <zlib.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

#define BUFSZ 4096

struct zlib_stream {
    z_stream    s;
    int         (*cb)(const void *, size_t, void *);
    void        *ctx;
    char        buf[BUFSZ];
};

static int xlat_zlib_err(int);

#define ENTRY(zlib_err, err) [-zlib_err] = {.valid = 1, .ret = err}

static int
xlat_zlib_err(int err)
{
    static const struct ent {
        unsigned    valid:1;
        int         ret:31;
    } errmap[] = {
        ENTRY(Z_OK,             0),
        ENTRY(Z_MEM_ERROR,      -ENOMEM),
        ENTRY(Z_VERSION_ERROR,  -EPROTONOSUPPORT),
        ENTRY(Z_STREAM_ERROR,   -EINVAL)
    };
    const struct ent *ent;

    if (err >= (int)ARRAY_SIZE(errmap))
        return -EIO;

    ent = &errmap[-err];
    return ent->valid ? ent->ret : -EIO;
}

#undef ENTRY

int
zlib_stream_init(zlib_stream_hdl_t *hdl,
                 int (*cb)(const void *, size_t, void *), void *ctx)
{
    struct zlib_stream *ret;

    if (omalloc(&ret) == NULL)
        return MINUS_ERRNO;

    ret->s.next_in = NULL;

    ret->s.zalloc = Z_NULL;
    ret->s.zfree = Z_NULL;
    ret->s.opaque = Z_NULL;

    ret->cb = cb;
    ret->ctx = ctx;

    *hdl = ret;
    return 0;
}

int
zlib_stream_destroy(zlib_stream_hdl_t hdl)
{
    int ret;

    ret = inflateEnd(&hdl->s);

    free(hdl);

    return ret == Z_OK ? 0 : -EIO;
}

int
zlib_stream_inflate(zlib_stream_hdl_t hdl, void *buf, size_t len,
                    size_t *remlen)
{
    int end;
    int first;
    int ret;

    first = hdl->s.next_in == NULL;

    hdl->s.next_in = buf;
    hdl->s.avail_in = len;

    if (first) {
        ret = inflateInit(&hdl->s);
        if (ret != Z_OK)
            return xlat_zlib_err(ret);
    }

    for (;;) {
        hdl->s.next_out = (unsigned char *)hdl->buf;
        hdl->s.avail_out = sizeof(hdl->buf);

        ret = inflate(&hdl->s, Z_NO_FLUSH);
        if (ret != Z_OK) {
            end = ret == Z_STREAM_END;
            if (!end)
                return xlat_zlib_err(ret);
        } else
            end = 0;

        ret = (*hdl->cb)(hdl->buf, (char *)hdl->s.next_out - hdl->buf,
                         hdl->ctx);
        if (ret != 0)
            return ret;

        if (end || hdl->s.avail_in == 0)
            break;
    }

    *remlen = hdl->s.avail_in;
    return end;
}

/* vi: set expandtab sw=4 ts=4: */
