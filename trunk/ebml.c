/*
 * ebml.c
 */

#include "common.h"
#include "ebml.h"
#include "element.h"
#include "parser.h"
#include "vint.h"

#include <malloc_ext.h>
#include <strings_ext.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/types.h>

struct ebml_hdl {
    const ebml_io_fns_t *fns;
    const struct parser *parser_ebml;
    const struct parser *parser_doc;
    void                *ctx;
};

struct ebml_file_ctx {
    int fd;
};

#define EID_MAX_LEN 8
#define EDATASZ_MAX_LEN 8

#define EBML_ELEMENT_ID 0xa45dfa3

static int ebml_file_open(void **, void *);
static int ebml_file_close(void *);

static int ebml_file_read(void *, void *, ssize_t *);

static int read_elem_hdr(struct ebml_hdl *, char **, char *);
static int read_elem_data(struct ebml_hdl *, char *, uint64_t, size_t);

static int parse_eid(uint64_t *, size_t *, char *);
static int parse_edatasz(uint64_t *, size_t *, char *);

static int look_up_elem(struct ebml_hdl *, uint64_t, uint64_t, uint64_t,
                        enum etype *, int);

static int parse_header(struct ebml_hdl *);

static int parse_body(struct ebml_hdl *);

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

static int
read_elem_hdr(struct ebml_hdl *hdl, char **buf, char *bufp)
{
    char *di;
    int res;
    ssize_t nbytes;

    di = *buf + EID_MAX_LEN + EDATASZ_MAX_LEN;
    for (; bufp < di; bufp += nbytes) {
        nbytes = di - bufp;
        res = (*hdl->fns->read)(hdl->ctx, bufp, &nbytes);
        if (res != 0)
            return res;
    }

    *buf = di;
    return 0;
}

static int
read_elem_data(struct ebml_hdl *hdl, char *buf, uint64_t elen, size_t bufsz)
{
    char *di, *si;
    int res;
    size_t sz;
    ssize_t nbytes;

    for (; elen > 0; elen -= sz) {
        sz = MIN(elen, bufsz);
        di = buf + sz;
        for (si = buf; si < di; si += nbytes) {
            nbytes = di - si;
            res = (*hdl->fns->read)(hdl->ctx, si, &nbytes);
            if (res != 0)
                return res;
        }
    }

    return 0;
}

static int
parse_eid(uint64_t *eid, size_t *sz, char *bufp)
{
    int byteidx;
    int res;
    size_t retsz;
    uint64_t ret;
    union {
        uint64_t    eid;
        char        bytes[8];
    } conv;

    res = eid_to_u64(bufp, &ret, &retsz);
    if (res != 0 && res != -ENOTSUP)
        return res;

    if (retsz > EID_MAX_LEN)
        return -EIO;

    if (res == -ENOTSUP)
        fputs("Error resilience: found invalid all-zero element ID\n", stderr);

    /* reenable marker bit in EBML element ID */
    byteidx = (retsz - 1) / 8;
    conv.eid = ret;
    conv.bytes[retsz - 1 - byteidx] |= 1 << (8 - (retsz % 8));

    *eid = conv.eid;
    *sz = retsz;
    return 0;
}

static int
parse_edatasz(uint64_t *elen, size_t *sz, char *bufp)
{
    int res;
    size_t retsz;
    uint64_t ret;

    res = edatasz_to_u64(bufp, &ret, &retsz);
    if (res != 0)
        return res;

    if (retsz > EDATASZ_MAX_LEN)
        return -EIO;

    if (ret == EDATASZ_UNKNOWN)
        return -ENOSYS;

    *elen = ret;
    *sz = retsz;
    return 0;
}

static int
look_up_elem(struct ebml_hdl *hdl, uint64_t eid, uint64_t elen, uint64_t totlen,
             enum etype *etype, int ebml)
{
    char idstr[7];
    const char *val;
    const struct parser *parsers[2];
    enum etype ret;
    int res;
    size_t i;

    res = l64a_r(eid, idstr, sizeof(idstr));
    if (res != 0)
        return res;

    fprintf(stderr, "Found element %s (%" PRIx64 ") containing %" PRIu64
                    " byte%s of data (total length %" PRIu64 " byte%s)",
            idstr, eid, elen, elen == 1 ? "" : "s", totlen,
            totlen == 1 ? "" : "s");

    parsers[!ebml] = hdl->parser_ebml;
    parsers[ebml] = hdl->parser_doc;

    for (i = 0; i < ARRAY_SIZE(parsers); i++) {
        res = parser_look_up(parsers[i], idstr, &val, &ret);
        if (res < 0)
            goto err;
        if (res == 1)
            fprintf(stderr, " (%s: %s)", parser_desc(parsers[i]), val);
    }

    fputc('\n', stderr);

    *etype = ret;
    return 0;

err:
    fputc('\n', stderr);
    return res;
}

static int
parse_header(struct ebml_hdl *hdl)
{
    char buf[4096], *di, *si, *tmp;
    int res;
    size_t sz;
    ssize_t nbytes;
    uint64_t eid, elen;

    /* read EBML element ID and length */
    di = buf;
    res = read_elem_hdr(hdl, &di, buf);
    if (res != 0)
        return res;

    /* parse EBML element ID */
    res = eid_to_u64(buf, &eid, &sz);
    if (res != 0)
        return res;
    if (eid != EBML_ELEMENT_ID)
        return -EILSEQ;
    si = buf + sz;

    /* parse EBML element length */
    res = parse_edatasz(&elen, &sz, si);
    if (res != 0)
        return res;
    si += sz;

    fprintf(stderr, "EBML header is %" PRIu64 " bytes long\n", elen);

    /* read remaining EBML element data */
    tmp = si;
    si = di;
    di = tmp + elen;
    for (; si < di; si += nbytes) {
        nbytes = di - si;
        res = (*hdl->fns->read)(hdl->ctx, si, &nbytes);
        if (res != 0)
            return res;
    }

    si = tmp;
    di = si + elen;
    for (; si < di; si += elen) {
        enum etype etype;
        uint64_t totlen;

        /* parse EBML element ID */
        res = parse_eid(&eid, &sz, si);
        if (res != 0)
            return res;
        totlen = sz;
        si += sz;

        /* parse EBML element length */
        res = parse_edatasz(&elen, &sz, si);
        if (res != 0)
            return res;
        totlen += sz + elen;
        si += sz;

        res = look_up_elem(hdl, eid, elen, totlen, &etype, 1);
        if (res != 0)
            return res;
    }

    return 0;
}

static int
parse_body(struct ebml_hdl *hdl)
{
    char buf[4096], *di, *si, *tmp;
    int res;

    di = si = buf;
    for (;;) {
        enum etype etype;
        size_t sz;
        uint64_t eid;
        uint64_t elen, totlen;

        /* read EBML element ID and length */
        tmp = si;
        si = di;
        di = tmp;
        res = read_elem_hdr(hdl, &di, si);
        if (res != 0)
            return res;

        /* parse EBML element ID */
        res = parse_eid(&eid, &sz, tmp);
        if (res != 0)
            return res;
        totlen = sz;
        si = tmp + sz;

        /* parse EBML element length */
        res = parse_edatasz(&elen, &sz, si);
        if (res != 0)
            return res;
        si += sz;
        totlen += sz + elen;

        res = look_up_elem(hdl, eid, elen, totlen, &etype, 0);
        if (res != 0)
            return res;

        sz = di - si;

        if (etype == ETYPE_MASTER) {
            memmove(buf, si, sz);
            si = buf;
            di = si + sz;
            continue;
        }

        if (elen <= sz) {
            si += elen;
            continue;
        }

        /* read remaining EBML element data */
        res = read_elem_data(hdl, buf, elen - sz, sizeof(buf));
        if (res != 0)
            return res;
        di = si = buf;
    }

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
    ret->parser_ebml = EBML_PARSER;
    ret->parser_doc = parser;

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
    int err;

    (void)f;

    err = parse_header(hdl);
    return err ? err : parse_body(hdl);
}

/* vi: set expandtab sw=4 ts=4: */
