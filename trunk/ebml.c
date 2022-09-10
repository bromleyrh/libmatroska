/*
 * ebml.c
 */

#define _FILE_OFFSET_BITS 64

#include "common.h"
#include "ebml.h"
#include "element.h"
#include "matroska.h"
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
    const ebml_io_fns_t             *fns;
    const struct parser             *parser_ebml;
    const struct parser             *parser_doc;
    const struct semantic_processor *sproc;
    ebml_metadata_cb_t              *cb;
    char                            buf[4096];
    char                            *di;
    char                            *si;
    uint64_t                        n;
    void                            *ctx;
    void                            *sproc_ctx;
    void                            *metactx;
    int                             interrupt_read;
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
static int read_elem_data(struct ebml_hdl *, char *, uint64_t, uint64_t, size_t,
                          semantic_action_t *, const char *, enum etype);

static int parse_eid(uint64_t *, size_t *, char *);
static int parse_edatasz(uint64_t *, size_t *, char *);

static int look_up_elem(struct ebml_hdl *, uint64_t, uint64_t, uint64_t,
                        semantic_action_t **, enum etype *, const char **, int,
                        uint64_t, FILE *);

static int invoke_value_handler(enum etype, semantic_action_t *, edata_t *,
                                struct ebml_hdl *);
static int invoke_binary_handler(enum etype, semantic_action_t *, const char *,
                                 size_t, size_t, struct ebml_hdl *);

static int invoke_user_cb(const char *, enum etype, edata_t *, char *, uint64_t,
                          uint64_t, struct ebml_hdl *);

static int handle_fixed_width_value(char **, char **, size_t, enum etype,
                                    const char *, uint64_t, semantic_action_t *,
                                    FILE *, struct ebml_hdl *);
static int handle_variable_length_value(char *, char **, char **, size_t,
                                        size_t, enum etype, const char *,
                                        uint64_t, semantic_action_t *, FILE *,
                                        struct ebml_hdl *);

static int parse_header(FILE *, struct ebml_hdl *);

static int parse_body(FILE *, struct ebml_hdl *);

EXPORTED const ebml_io_fns_t ebml_file_fns = {
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
read_elem_data(struct ebml_hdl *hdl, char *buf, uint64_t elen,
               uint64_t tot_elen, size_t bufsz, semantic_action_t *act,
               const char *value, enum etype etype)
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
        if (act != NULL) {
            res = (*act)(NULL, ETYPE_BINARY, NULL, buf, sz, tot_elen,
                         hdl->sproc_ctx);
            if (res != 0)
                return res;
        }
        res = invoke_user_cb(value, etype, NULL, buf, sz, tot_elen, hdl);
        if (res != 0)
            return res;
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

    *elen = ret;
    *sz = retsz;
    return 0;
}

static int
look_up_elem(struct ebml_hdl *hdl, uint64_t eid, uint64_t elen, uint64_t totlen,
             semantic_action_t **act, enum etype *etype, const char **value,
             int ebml, uint64_t n, FILE *f)
{
    char idstr[7];
    const char *val;
    const struct parser *parsers[2];
    enum etype ret;
    int res;
    semantic_action_t *action = NULL;
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

    res = semantic_processor_look_up(hdl->sproc, idstr, &action);
    if (res != 0) {
        if (res != 1)
            return res;

        res = (*action)(val, ret, NULL, NULL, 0, 0, hdl->sproc_ctx);
        if (res != 0)
            return res;
    }

    if (act != NULL)
        *act = action;
    *etype = ret;
    *value = val;
    return 0;
}

static int
invoke_value_handler(enum etype etype, semantic_action_t *act, edata_t *edata,
                     struct ebml_hdl *hdl)
{
    return act != NULL
           ? (*act)(NULL, etype, edata, NULL, 0, 0, hdl->sproc_ctx) : 0;
}

static int
invoke_binary_handler(enum etype etype, semantic_action_t *act,
                      const char *buf, size_t len, size_t totlen,
                      struct ebml_hdl *hdl)
{
    int res;

    if (etype != ETYPE_BINARY || act == NULL)
        return 0;

    res = (*act)(NULL, ETYPE_BINARY, NULL, buf, len, totlen, hdl->sproc_ctx);
    if (res == 1) {
        hdl->interrupt_read = 1;
        res = 0;
    }

    return res;
}

static int
invoke_user_cb(const char *value, enum etype etype, edata_t *val, char *buf,
               uint64_t len, uint64_t totlen, struct ebml_hdl *hdl)
{
    int ret;
    matroska_metadata_t d;

    static const enum matroska_metadata_type typemap[] = {
        [ETYPE_INTEGER]     = MATROSKA_TYPE_INTEGER,
        [ETYPE_UINTEGER]    = MATROSKA_TYPE_UINTEGER,
        [ETYPE_FLOAT]       = MATROSKA_TYPE_DOUBLE,
        [ETYPE_STRING]      = MATROSKA_TYPE_BYTES,
        [ETYPE_UTF8]        = MATROSKA_TYPE_BYTES,
        [ETYPE_DATE]        = MATROSKA_TYPE_INTEGER,
        [ETYPE_BINARY]      = MATROSKA_TYPE_BYTES
    };

    if (hdl->cb == NULL)
        return 0;

    memset(&d, 0, sizeof(d));

    if (val == NULL) {
        d.data = buf;
        d.len = len;
        d.type = typemap[etype];

        ret = (*hdl->cb)(value, &d, totlen, MATROSKA_METADATA_FLAG_FRAGMENT,
                         hdl->metactx);
        goto end;
    }

    switch (val->type) {
    case ETYPE_INTEGER:
        d.integer = val->integer;
        break;
    case ETYPE_UINTEGER:
        d.uinteger = val->uinteger;
        break;
    case ETYPE_FLOAT:
        d.dbl = val->dbl ? val->floatd : (double)val->floats;
        break;
    case ETYPE_DATE:
        d.integer = val->date;
        break;
    case ETYPE_STRING:
    case ETYPE_UTF8:
    case ETYPE_BINARY:
        d.data = val->ptr;
        d.len = ETYPE_IS_STRING(val->type) ? strlen(val->ptr) : totlen;
        break;
    default:
        abort();
    }

    d.type = typemap[val->type];

    ret = (*hdl->cb)(value, &d, totlen, 0, hdl->metactx);

end:
    if (ret == 1) {
        hdl->interrupt_read = 1;
        ret = 0;
    }
    return ret;
}

static int
handle_fixed_width_value(char **sip, char **dip, size_t sz, enum etype etype,
                         const char *value, uint64_t elen,
                         semantic_action_t *act, FILE *f, struct ebml_hdl *hdl)
{
    char buf[26];
    char *di, *si;
    char valbuf[8];
    edata_t val;
    int res;
    struct timespec tm;

    if (elen > ETYPE_MAX_FIXED_WIDTH)
        return -EINVAL;

    si = *sip;
    di = *dip;

    if (elen > sz) {
        ssize_t nbytes;

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
    if (res != 0) {
        if (res != -EINVAL)
            return res;
        goto end;
    }

    switch (val.type) {
    case ETYPE_INTEGER:
        res = fprintf(f, "%" PRIi64, val.integer);
        break;
    case ETYPE_UINTEGER:
        res = fprintf(f, "%" PRIu64, val.uinteger);
        break;
    case ETYPE_FLOAT:
        res = fprintf(f, "%f",
                      val.dbl ? val.floatd : (double)val.floats);
        break;
    case ETYPE_DATE:
        res = edata_to_timespec(&val, &tm);
        if (res != 0)
            return res;
        res = fprintf(f, "%s", ctime_r(&tm.tv_sec, buf));
        break;
    default:
        abort();
    }
    if (res < 0)
        return -EIO;

    res = invoke_value_handler(val.type, act, &val, hdl);
    if (res != 0)
        return res;

    res = invoke_user_cb(value, etype, &val, buf, 0, elen, hdl);
    if (res != 0)
        return res;

end:
    *sip = si;
    *dip = di;
    return 0;
}

static int
handle_variable_length_value(char *buf, char **sip, char **dip, size_t bufsz,
                             size_t sz, enum etype etype, const char *value,
                             uint64_t elen, semantic_action_t *act, FILE *f,
                             struct ebml_hdl *hdl)
{
    char *di, *si;
    edata_t val;
    int res;
    int user_cb_invoked = 0;

    si = *sip;
    di = *dip;

    if (elen > sz) { /* read remaining EBML element data */
        memmove(buf, si, sz);
        res = invoke_binary_handler(etype, act, buf, sz, elen, hdl);
        if (res != 0)
            return res;
        res = invoke_user_cb(value, etype, NULL, buf, sz, elen, hdl);
        if (res != 0)
            return res;

        res = read_elem_data(hdl, buf + sz, elen - sz, elen, bufsz - sz,
                             etype == ETYPE_BINARY ? act : NULL, value, etype);
        if (res != 0)
            return res;

        if (elen > bufsz) {
            res = invoke_binary_handler(etype, act, NULL, elen, elen, hdl);
            if (res != 0)
                return res;
            goto end;
        }

        si = buf;
        user_cb_invoked = 1;
    }

    res = edata_unpack(si, &val, etype, elen);
    if (res != 0)
        return res;

    if (ETYPE_IS_STRING(val.type))
        res = fprintf(f, "%s", val.ptr);
    else if (elen <= sz) {
        res = invoke_binary_handler(val.type, act, si, elen, elen, hdl);
        if (res != 0)
            return res;
    }
    if (res < 0) {
        res = -EIO;
        goto err;
    }

    res = invoke_binary_handler(val.type, act, NULL, elen, elen, hdl);
    if (res != 0)
        goto err;

    if (!user_cb_invoked) {
        res = invoke_user_cb(value, etype, &val, NULL, 0, elen, hdl);
        if (res != 0)
            goto err;
    }

    free(val.ptr);

end:
    *sip = si;
    *dip = di;
    return 0;

err:
    free(val.ptr);
    return res;
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
    if (elen == EDATASZ_UNKNOWN)
        elen = 0;
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
        const char *val;
        enum etype etype;
        int sz_unknown;

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
        sz_unknown = elen == EDATASZ_UNKNOWN;
        if (sz_unknown)
            elen = 0;
        totlen += sz + elen;
        si += sz;

        res = look_up_elem(hdl, eid, elen, totlen, NULL, &etype, &val, 1, n, f);
        if (res != 0)
            return res;

        if (sz_unknown && etype != ETYPE_MASTER)
            return -EILSEQ;

        if (f != NULL && fputc('\n', f) == EOF)
            return -EIO;

        ++n;
    }

    return 0;
}

static int
parse_body(FILE *f, struct ebml_hdl *hdl)
{
    char *tmp;
    int res;

    for (;;) {
        const char *val;
        enum etype etype;
        int sz_unknown;
        off_t off;
        semantic_action_t *act;
        size_t sz;
        uint64_t eid;
        uint64_t elen, totlen;

        static const char *const typestrmap[] = {
            [ETYPE_NONE]        = "-",
            [ETYPE_INTEGER]     = "d",
            [ETYPE_UINTEGER]    = "u",
            [ETYPE_FLOAT]       = "f",
            [ETYPE_STRING]      = "s",
            [ETYPE_UTF8]        = "w",
            [ETYPE_DATE]        = "t",
            [ETYPE_MASTER]      = "m",
            [ETYPE_BINARY]      = "b"
        };

        /* read EBML element ID and length */
        tmp = hdl->si;
        hdl->si = hdl->di;
        hdl->di = tmp;
        res = read_elem_hdr(hdl, &hdl->di, hdl->si);
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
        hdl->si = tmp + sz;

        /* parse EBML element length */
        res = parse_edatasz(&elen, &sz, hdl->si);
        if (res != 0)
            return res;
        sz_unknown = elen == EDATASZ_UNKNOWN;
        if (sz_unknown)
            elen = 0;
        hdl->si += sz;
        totlen += sz + elen;

        if (f != NULL && hdl->n == 1
            && fprintf(f, "body\t\t\t%" PRIu64 "\n", elen) < 0)
            return -EIO;

        res = look_up_elem(hdl, eid, elen, totlen, &act, &etype, &val, 0,
                           hdl->n, f);
        if (res != 0)
            return res;

        if (sz_unknown && etype != ETYPE_MASTER)
            return -EILSEQ;

        if (f != NULL && fprintf(f, "\t%s\t", typestrmap[etype]) < 0)
            return -EIO;

        sz = hdl->di - hdl->si;

        if (etype == ETYPE_MASTER) {
            memmove(hdl->buf, hdl->si, sz);
            hdl->si = hdl->buf;
            hdl->di = hdl->si + sz;
        } else {
            if (ETYPE_IS_FIXED_WIDTH(etype)) {
                res = handle_fixed_width_value(&hdl->si, &hdl->di, sz, etype,
                                               val, elen, act, f, hdl);
            } else {
                res = handle_variable_length_value(hdl->buf, &hdl->si, &hdl->di,
                                                   sizeof(hdl->buf), sz, etype,
                                                   val, elen, act, f, hdl);
            }
            if (res != 0)
                return res;

            if (elen > sz)
                hdl->di = hdl->si = hdl->buf;
            else
                hdl->si += elen;
        }

        if (f != NULL && fputc('\n', f) == EOF)
            return -EIO;

        ++hdl->n;

        if (hdl->interrupt_read) {
            hdl->interrupt_read = 0;
            return 1;
        }
    }

    return 0;
}

EXPORTED int
ebml_open(ebml_hdl_t *hdl, const ebml_io_fns_t *fns,
          const struct parser *parser, const struct semantic_processor *sproc,
          ebml_metadata_cb_t *cb, void *args, void *sproc_ctx, void *ctx)
{
    int err;
    struct ebml_hdl *ret;

    if (ocalloc(&ret, 1) == NULL)
        return -errno;

    err = (*fns->open)(&ret->ctx, args);
    if (err) {
        free(ret);
        return err;
    }

    ret->fns = fns;
    ret->parser_ebml = EBML_PARSER;
    ret->parser_doc = parser;
    ret->sproc = sproc;
    ret->cb = cb;

    ret->di = ret->si = ret->buf;
    ret->n = 1;

    ret->sproc_ctx = sproc_ctx;
    ret->metactx = ctx;

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
ebml_read(FILE *f, ebml_hdl_t hdl)
{
    int err;

    err = parse_header(f, hdl);
    return err ? err : parse_body(f, hdl);
}

EXPORTED int
ebml_read_header(FILE *f, ebml_hdl_t hdl)
{
    return parse_header(f, hdl);
}

EXPORTED int
ebml_read_body(FILE *f, ebml_hdl_t hdl)
{
    return parse_body(f, hdl);
}

/* vi: set expandtab sw=4 ts=4: */
