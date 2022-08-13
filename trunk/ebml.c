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

static int ebml_file_get_fpos(void *, off_t *);

static int read_elem_hdr(struct ebml_hdl *, char **, char *);
static int read_elem_data(struct ebml_hdl *, char *, uint64_t, size_t);

static int parse_eid(uint64_t *, size_t *, char *);
static int parse_edatasz(uint64_t *, size_t *, char *);

static int look_up_elem(struct ebml_hdl *, uint64_t, uint64_t, uint64_t,
                        enum etype *, int, uint64_t, FILE *);

static int parse_header(FILE *, struct ebml_hdl *);

static int parse_body(FILE *, struct ebml_hdl *);

const ebml_io_fns_t ebml_file_fns = {
    .open       = &ebml_file_open,
    .close      = &ebml_file_close,
    .read       = &ebml_file_read,
    .get_fpos   = &ebml_file_get_fpos
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
ebml_file_get_fpos(void *ctx, off_t *offset)
{
    off_t ret;
    struct ebml_file_ctx *fctx = ctx;

    ret = lseek(fctx->fd, 0, SEEK_CUR);
    if (ret == -1)
        return -errno;

    *offset = ret;
    return 0;
}

static int
read_elem_hdr(struct ebml_hdl *hdl, char **buf, char *bufp)
{
    char *di, *si;
    int res;
    ssize_t nbytes;

    si = bufp;
    di = *buf + EID_MAX_LEN + EDATASZ_MAX_LEN;
    for (; bufp < di; bufp += nbytes) {
        nbytes = di - bufp;
        res = (*hdl->fns->read)(hdl->ctx, bufp, &nbytes);
        if (res != 0)
            return res;
        if (nbytes == 0) {
            di = bufp;
            break;
        }
    }

    *buf = di;
    return bufp == si;
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
             enum etype *etype, int ebml, uint64_t n, FILE *f)
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

    if (f != NULL
        && fprintf(f, "%" PRIu64 "\t%s\t%" PRIx64 "\t%" PRIu64 "\t%" PRIu64,
                   n, idstr, eid, elen, totlen) < 0)
        return -EIO;

    parsers[!ebml] = hdl->parser_ebml;
    parsers[ebml] = hdl->parser_doc;

    for (i = 0; i < ARRAY_SIZE(parsers); i++) {
        res = parser_look_up(parsers[i], idstr, &val, &ret);
        if (res < 0)
            return res;
        if (f != NULL && res == 1
            && fprintf(f, "\t%s\t%s", parser_desc(parsers[i]), val) < 0)
            return -EIO;
    }

    *etype = ret;
    return 0;
}

static int
parse_header(FILE *f, struct ebml_hdl *hdl)
{
    char buf[4096], *di, *si, *tmp;
    int res;
    size_t sz;
    ssize_t nbytes;
    uint64_t eid, elen;
    uint64_t n;
    uint64_t totlen;

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
    totlen = sz;
    si = buf + sz;

    /* parse EBML element length */
    res = parse_edatasz(&elen, &sz, si);
    if (res != 0)
        return res;
    totlen += sz + elen;
    si += sz;

    if (f != NULL
        && (fprintf(f, "header\t\t\t%" PRIu64 "\n", elen) < 0
            || fprintf(f,
                       "1\t\t%" PRIx64 "\t%" PRIu64 "\t%" PRIu64 "\tEBML\t\n",
                       (uint64_t)EBML_ELEMENT_ID, elen, totlen) < 0))
        return -EIO;

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

    n = 2;
    si = tmp;
    di = si + elen;
    for (; si < di; si += elen) {
        enum etype etype;

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

        res = look_up_elem(hdl, eid, elen, totlen, &etype, 1, n, f);
        if (res != 0)
            return res;

        if (f != NULL && fputc('\n', f) == EOF)
            return -EIO;

        ++n;
    }

    return 0;
}

static int
parse_body(FILE *f, struct ebml_hdl *hdl)
{
    char buf[4096], *di, *si, *tmp;
    int res;
    uint64_t n;

    di = si = buf;
    for (n = 1;; n++) {
        char valbuf[8];
        edata_t val;
        enum etype etype;
        off_t off;
        size_t sz;
        ssize_t nbytes;
        uint64_t eid;
        uint64_t elen, totlen;

        /* read EBML element ID and length */
        tmp = si;
        si = di;
        di = tmp;
        res = read_elem_hdr(hdl, &di, si);
        if (res != 0) {
            if (res != 1)
                return res;
            if (f != NULL && (*hdl->fns->get_fpos)(hdl->ctx, &off) == 0
                && fprintf(f, "EOF\t\t\t\t%lld\n", off) < 0)
                return -EIO;
            break;
        }

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

        if (f != NULL && n == 1
            && fprintf(f, "body\t\t\t%" PRIu64 "\n", elen) < 0)
            return -EIO;

        res = look_up_elem(hdl, eid, elen, totlen, &etype, 0, n, f);
        if (res != 0)
            return res;

        sz = di - si;

        if (etype == ETYPE_MASTER) {
            if (f != NULL && fputc('\n', f) == EOF)
                return -EIO;
            memmove(buf, si, sz);
            si = buf;
            di = si + sz;
            continue;
        }

        if (etype == ETYPE_INTEGER || etype == ETYPE_UINTEGER) {
            if (elen > 8)
                return -EINVAL;
            if (elen > sz) {
                memcpy(valbuf, si, sz);
                di = valbuf + elen;
                for (si = valbuf + sz; si < di; si += nbytes) {
                    nbytes = di - si;
                    res = (*hdl->fns->read)(hdl->ctx, si, &nbytes);
                    if (res != 0)
                        return res;
                }
                si = valbuf;
            }
            res = edata_unpack(si, &val, etype, elen);
            if (res == 0) {
                fputc('\t', f);
                if (etype == ETYPE_INTEGER)
                    fprintf(f, "%" PRIi64, val.integer);
                else
                    fprintf(f, "%" PRIu64, val.uinteger);
                fputc('\n', f);
            } else if (res != -EINVAL)
                return res;
            else if (f != NULL && fputc('\n', f) == EOF)
                return -EIO;
            if (elen <= sz) {
                si += elen;
                continue;
            }
        } else {
            if (f != NULL && fputc('\n', f) == EOF)
                return -EIO;
            if (elen <= sz) {
                si += elen;
                continue;
            }
            /* read remaining EBML element data */
            res = read_elem_data(hdl, buf, elen - sz, sizeof(buf));
            if (res != 0)
                return res;
        }
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

    err = parse_header(f, hdl);
    return err ? err : parse_body(f, hdl);
}

/* vi: set expandtab sw=4 ts=4: */
