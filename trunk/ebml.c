/*
 * ebml.c
 */

#define _FILE_OFFSET_BITS 64

#include "common.h"
#include "debug.h"
#include "ebml.h"
#include "element.h"
#include "matroska.h"
#include "parser.h"
#include "util.h"
#include "vint.h"

#include <malloc_ext.h>
#include <strings_ext.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/types.h>

struct elem_stack_ent {
    const struct elem_data  *data;
    size_t                  hdrlen;
    size_t                  elen;
    size_t                  totlen;
    unsigned                segment;
};

struct elem_stack {
    struct elem_stack_ent   **stk;
    size_t                  len;
    size_t                  sz;
};

struct ebml_hdl {
    const ebml_io_fns_t             *fns;
    const struct parser             *parser_ebml;
    const struct parser             *parser_doc;
    const struct semantic_processor *sproc;
    struct elem_stack               stk;
    ebml_metadata_cb_t              *cb;
    char                            buf[4096];
    char                            *di;
    char                            *si;
    off_t                           off;
    void                            *valbuf;
    size_t                          vallen;
    uint64_t                        n;
    void                            *ctx;
    int                             ro;
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
#define EBML_ELEMENT_ID_WITH_MARKER 0x1a45dfa3

#define SEGMENT_ELEMENT_ID 0x18538067

#define VOID_ELEMENT_ID 0xec
#define CRC32_ELEMENT_ID 0xbf

#define TM_YEAR(year) ((year) - 1900)

#define REFERENCE_TIME \
    { \
        .tm_mday    = 1, \
        .tm_mon     = 1, \
        .tm_year    = TM_YEAR(2001), \
        .tm_isdst   = -1 \
    }

#define TIME_GRAN 1000000000

static int ebml_file_open(void **, int, void *);
static int ebml_file_close(void *);

static int ebml_file_read(void *, void *, ssize_t *);
static int ebml_file_write(void *, const void *, size_t);
static int ebml_file_sync(void *);

static int ebml_file_get_fpos(void *, off_t *);

static int read_elem_hdr(struct ebml_hdl *, char **, char *);
static int read_elem_data(struct ebml_hdl *, char *, uint64_t, uint64_t, size_t,
                          size_t, semantic_action_t *, const char *, enum etype,
                          int);

static int parse_eid(uint64_t *, size_t *, char *);
static int parse_edatasz(uint64_t *, size_t *, char *);

static int output_eid(char *, size_t *, uint64_t);
static int output_edatasz(char *, size_t *, const matroska_metadata_t *,
                          enum etype);

static int look_up_elem(struct ebml_hdl *, uint64_t, uint64_t, uint64_t, size_t,
                        semantic_action_t **, enum etype *, const char **,
                        const struct elem_data **, const struct elem_data **,
                        int, uint64_t, FILE *);

static int push_master(struct elem_stack *, const struct elem_data *, unsigned);
static void return_from_master(struct elem_stack *, const struct elem_data *);

static int invoke_value_handler(enum etype, size_t, semantic_action_t *,
                                edata_t *, struct ebml_hdl *);
static int invoke_binary_handler(enum etype, semantic_action_t *, void **,
                                 size_t *, void **, size_t *, size_t, size_t,
                                 int, struct ebml_hdl *);

static int invoke_user_cb(const char *, enum etype, edata_t *, char *, uint64_t,
                          uint64_t, size_t, int, struct ebml_hdl *);

static int handle_fixed_width_value(char **, char **, size_t, enum etype,
                                    const char *, uint64_t, size_t,
                                    semantic_action_t *, int, FILE *,
                                    struct ebml_hdl *);
static int handle_variable_length_value(char *, char **, char **, size_t,
                                        size_t, enum etype, const char *,
                                        uint64_t, size_t, semantic_action_t *,
                                        int, FILE *, struct ebml_hdl *);

static int parse_header(FILE *, struct ebml_hdl *, int);

static int parse_body(FILE *, struct ebml_hdl *, int);

EXPORTED const ebml_io_fns_t ebml_file_fns = {
    .open       = &ebml_file_open,
    .close      = &ebml_file_close,
    .read       = &ebml_file_read,
    .write      = &ebml_file_write,
    .sync       = &ebml_file_sync,
    .get_fpos   = &ebml_file_get_fpos
};

static int
ebml_file_open(void **ctx, int ro, void *args)
{
    int err;
    struct ebml_file_args *a;
    struct ebml_file_ctx *ret;

    if (omalloc(&ret) == NULL)
        return ERR_TAG(errno);

    a = args;

    if (a->pathname == NULL)
        ret->fd = a->fd;
    else {
        ret->fd = openat(a->fd, a->pathname,
                         O_CLOEXEC | (ro ? O_RDONLY : O_WRONLY));
        if (ret->fd == -1) {
            err = ERR_TAG(errno);
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
            return ERR_TAG(errno);
    }

    *nbytes = ret;
    return 0;
}

static int
ebml_file_write(void *ctx, const void *buf, size_t nbytes)
{
    size_t numwritten;
    ssize_t ret;
    struct ebml_file_ctx *fctx = ctx;

    for (numwritten = 0; numwritten < nbytes; numwritten += ret) {
        ret = write(fctx->fd, (const char *)buf + numwritten,
                    nbytes - numwritten);
        if (ret == -1) {
            if (errno != EINTR)
                return ERR_TAG(errno);
            ret = 0;
        }
    }

    return 0;
}

static int
ebml_file_sync(void *ctx)
{
    struct ebml_file_ctx *fctx = ctx;

    return fsync(fctx->fd) == -1
           && errno != EBADF && errno != EINVAL && errno != ENOTSUP
           ? ERR_TAG(errno) : 0;
}

static int
ebml_file_get_fpos(void *ctx, off_t *offset)
{
    off_t ret;
    struct ebml_file_ctx *fctx = ctx;

    ret = lseek(fctx->fd, 0, SEEK_CUR);
    if (ret == -1)
        return ERR_TAG(errno);

    *offset = ret;
    return 0;
}

static int
read_elem_hdr(struct ebml_hdl *hdl, char **buf, char *bufp)
{
    char *di, *si;
    int res;
    off_t off;
    ssize_t nbytes;

    if ((*hdl->fns->get_fpos)(hdl->ctx, &off) == 0) {
        off -= bufp - *buf;
        if (hdl->off != off) {
            fprintf(stderr, "Synchronization error: file offset %" PRIi64
                            " byte%s (%+" PRIi64 " byte%s)\n",
                    PL(hdl->off), PL(hdl->off - off));
            abort();
        }
    }

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
               uint64_t tot_elen, size_t hdrlen, size_t bufsz,
               semantic_action_t *act, const char *value, enum etype etype,
               int ebml)
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
        res = invoke_user_cb(value, etype, NULL, buf, sz, tot_elen, hdrlen,
                             ebml, hdl);
        if (res != 0)
            return res;
        if (act != NULL) {
            void *bufp = buf;

            res = (*act)(NULL, ETYPE_BINARY, NULL, NULL, NULL, &bufp, &sz,
                         tot_elen, hdrlen, hdl->off, hdl->sproc_ctx, 0);
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
    int notsup;
    int res;
    size_t retsz;
    uint64_t ret;
    union {
        uint64_t    eid;
        char        bytes[8];
    } conv;

    res = eid_to_u64(bufp, &ret, &retsz);
    if (res == 0)
        notsup = 0;
    else if (err_get_code(res) == -ENOTSUP)
        notsup = 1;
    else
        return res;

    if (retsz > EID_MAX_LEN)
        return ERR_TAG(EIO);

    if (notsup)
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
output_eid(char *bufp, size_t *sz, uint64_t eid)
{
    return u64_to_eid(eid, bufp, sz, FLAG_HAVE_MARKER);
}

static int
output_edatasz(char *bufp, size_t *sz, const matroska_metadata_t *val,
               enum etype etype)
{
    int err;
    uint64_t elen;

    if (ETYPE_IS_FIXED_WIDTH(etype)) {
        char buf[16];
        edata_t d;
        size_t len;

        switch (etype) {
        case ETYPE_INTEGER:
            d.integer = val->integer;
            break;
        case ETYPE_UINTEGER:
            d.uinteger = val->uinteger;
            break;
        case ETYPE_FLOAT:
            d.floats = val->dbl;
            d.dbl = d.floats != val->dbl;
            if (d.dbl)
                d.floatd = val->dbl;
            break;
        case ETYPE_DATE:
            d.date = val->integer;
            break;
        default:
            abort();
        }

        err = edata_pack(&d, buf, etype, &len);
        if (err)
            return err;
        elen = len;
    } else
        elen = val->len;

    return u64_to_edatasz(elen, bufp, sz);
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
        return ERR_TAG(EIO);

    *elen = ret;
    *sz = retsz;
    return 0;
}

static int
look_up_elem(struct ebml_hdl *hdl, uint64_t eid, uint64_t elen, uint64_t totlen,
             size_t hdrlen, semantic_action_t **act, enum etype *etype,
             const char **value, const struct elem_data **parent,
             const struct elem_data **data, int ebml, uint64_t n, FILE *f)
{
    char idstr[7];
    const struct elem_data *datap, *parentp;
    const struct parser *parsers[2];
    int found;
    int res;
    semantic_action_t *action = NULL;
    size_t i;

    res = l64a_r(eid, idstr, sizeof(idstr));
    if (res != 0)
        return ERR_TAG(EIO);

    if (f != NULL
        && fprintf(f, "%" PRIu64 "\t%s\t%" PRIx64 "\t%" PRIu64 "\t%" PRIu64,
                   n, idstr, eid, elen, totlen) < 0)
        return ERR_TAG(EIO);

    parsers[!ebml] = hdl->parser_ebml;
    parsers[ebml] = hdl->parser_doc;

    found = 0;

    for (i = 0; i < ARRAY_SIZE(parsers); i++) {
        res = parser_look_up(parsers[i], idstr, &datap, &parentp);
        if (res < 0)
            return ERR_TAG(-res);
        if (res == 1) {
            if (f != NULL
                && fprintf(f, "\t%s\t%s", parser_desc(parsers[i]), datap->val)
                   < 0)
                return ERR_TAG(EIO);
            found = 1;
        }
    }
    if (!found)
        return ERR_TAG(EILSEQ);

    res = semantic_processor_look_up(hdl->sproc, idstr, &action);
    if (res != 0) {
        if (res != 1)
            return ERR_TAG(-res);

        res = (*action)(datap->val, datap->etype, NULL, NULL, 0, NULL, 0, 0,
                        hdrlen, hdl->off, hdl->sproc_ctx, 0);
        if (res != 0)
            return res;
    }

    if (act != NULL)
        *act = action;
    *etype = datap->etype;
    *value = datap->val;
    *parent = parentp;
    *data = datap;
    return 0;
}

static int
push_master(struct elem_stack *stk, const struct elem_data *data,
            unsigned segment)
{
    int err;
    struct elem_stack_ent *ent;

    if (omalloc(&ent) == NULL)
        return ERR_TAG(errno);

    if (stk->len == stk->sz) {
        struct elem_stack_ent **tmp;
        size_t newsz;

        newsz = stk->sz == 0 ? 16 : 2 * stk->sz;
        if (oreallocarray(stk->stk, &tmp, newsz) == NULL) {
            err = errno;
            free(ent);
            return err;
        }
        stk->stk = tmp;
        stk->sz = newsz;
    }

    ent->data = data;
    ent->hdrlen = ent->totlen = 0;
    ent->segment = segment;

    stk->stk[stk->len++] = ent;

    return 0;
}

static void
return_from_master(struct elem_stack *stk, const struct elem_data *next_parent)
{
    size_t idx, len;
    size_t tmp;
    struct elem_stack_ent *ent;

    len = stk->len;

    if (len == 0)
        return;
    idx = len - 1;

    ent = stk->stk[idx];

    if (next_parent == ent->data)
        return;

    for (;;) {
        tmp = ent->totlen - ent->hdrlen;
        if (tmp != ent->elen) {
            fprintf(stderr, "Synchronization error: master element size %zu"
                            " byte%s (%+" PRIi64 " byte%s)\n",
                    PL(tmp), PL((int64_t)tmp - (int64_t)ent->elen));
            abort();
        }
        fprintf(stderr, "Master element %s has size %zu byte%s\n",
                ent->data->val, PL(tmp));

        if (idx == 0)
            break;
        --idx;

        tmp = ent->totlen;
        ent = stk->stk[idx];
        ent->totlen += tmp;
        if (next_parent == ent->data) {
            ++idx;
            break;
        }
    }

    stk->len = idx;
    len -= idx;

    fprintf(stderr, "Returned up %zu level%s to %s\n",
            PL(len), idx == 0 ? "root" : next_parent->val);
}

static int
invoke_value_handler(enum etype etype, size_t hdrlen, semantic_action_t *act,
                     edata_t *edata, struct ebml_hdl *hdl)
{
    return act != NULL
           ? (*act)(NULL, etype, edata, NULL, NULL, NULL, 0, 0, hdrlen,
                    hdl->off, hdl->sproc_ctx, 0)
           : 0;
}

static int
invoke_binary_handler(enum etype etype, semantic_action_t *act, void **outbuf,
                      size_t *outlen, void **buf, size_t *len, size_t totlen,
                      size_t hdrlen, int encode, struct ebml_hdl *hdl)
{
    int res;

    if (etype != ETYPE_BINARY || act == NULL)
        return 0;

    res = (*act)(NULL, ETYPE_BINARY, NULL, outbuf, outlen, buf, len, totlen,
                 hdrlen, hdl->off, hdl->sproc_ctx, encode);
    if (res == 1) {
        hdl->interrupt_read = 1;
        res = 0;
    }

    return res;
}

static int
invoke_user_cb(const char *value, enum etype etype, edata_t *val, char *buf,
               uint64_t len, uint64_t totlen, size_t hdrlen, int ebml,
               struct ebml_hdl *hdl)
{
    int fl;
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

    fl = ebml ? MATROSKA_METADATA_FLAG_HEADER : 0;

    if (etype == ETYPE_MASTER) {
        ret = (*hdl->cb)(value, &d, totlen, hdrlen, fl, hdl->metactx);
        goto end;
    }

    if (val == NULL) {
        d.data = buf;
        d.len = len;
        d.type = typemap[etype];

        ret = (*hdl->cb)(value, &d, totlen, hdrlen,
                         fl | MATROSKA_METADATA_FLAG_FRAGMENT, hdl->metactx);
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

    ret = (*hdl->cb)(value, &d, totlen, hdrlen, fl, hdl->metactx);

end:
    if (ret == 1) {
        hdl->interrupt_read = 1;
        ret = 0;
    }
    return ret;
}

static int
handle_fixed_width_value(char **sip, char **dip, size_t sz, enum etype etype,
                         const char *value, uint64_t elen, size_t hdrlen,
                         semantic_action_t *act, int ebml, FILE *f,
                         struct ebml_hdl *hdl)
{
    char buf[26];
    char *di, *si;
    char valbuf[8];
    edata_t val;
    int res;
    struct timespec tm;

    if (elen > ETYPE_MAX_FIXED_WIDTH)
        return ERR_TAG(EINVAL);

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
        if (err_get_code(res) != -EINVAL)
            return res;
        goto end;
    }

    if (f != NULL) {
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
            return ERR_TAG(EIO);
    }

    res = invoke_user_cb(value, etype, &val, buf, 0, elen, hdrlen, ebml, hdl);
    if (res != 0)
        return res;

    res = invoke_value_handler(val.type, hdrlen, act, &val, hdl);
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
                             uint64_t elen, size_t hdrlen,
                             semantic_action_t *act, int ebml, FILE *f,
                             struct ebml_hdl *hdl)
{
    char *di, *si;
    edata_t val;
    int res;
    int user_cb_invoked = 0;
    size_t buflen;
    void *bufp;

    si = *sip;
    di = *dip;

    if (elen > sz) { /* read remaining EBML element data */
        memmove(buf, si, sz);
        res = invoke_user_cb(value, etype, NULL, buf, sz, elen, hdrlen, ebml,
                             hdl);
        if (res != 0)
            return res;
        bufp = buf;
        buflen = sz;
        res = invoke_binary_handler(etype, act, NULL, NULL, &bufp, &buflen,
                                    elen, hdrlen, 0, hdl);
        if (res != 0)
            return res;

        res = read_elem_data(hdl, buf + sz, elen - sz, elen, hdrlen, bufsz - sz,
                             etype == ETYPE_BINARY ? act : NULL, value, etype,
                             ebml);
        if (res != 0)
            return res;

        if (elen > bufsz) {
            buflen = elen;
            res = invoke_binary_handler(etype, act, NULL, NULL, NULL, &buflen,
                                        elen, hdrlen, 0, hdl);
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

    if (!user_cb_invoked) {
        res = invoke_user_cb(value, etype, &val, NULL, 0, elen, hdrlen, ebml,
                             hdl);
        if (res != 0)
            goto err;
    }

    if (ETYPE_IS_STRING(val.type)) {
        if (f != NULL) {
            res = fprintf(f, "%s", val.ptr);
            if (res < 0) {
                res = ERR_TAG(EIO);
                goto err;
            }
        }
    } else if (elen <= sz) {
        bufp = si;
        buflen = elen;
        res = invoke_binary_handler(val.type, act, NULL, NULL, &bufp, &buflen,
                                    elen, hdrlen, 0, hdl);
        if (res != 0)
            return res;
    }

    buflen = elen;
    res = invoke_binary_handler(val.type, act, NULL, NULL, NULL, &buflen, elen,
                                hdrlen, 0, hdl);
    if (res != 0)
        goto err;

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
parse_header(FILE *f, struct ebml_hdl *hdl, int flags)
{
    char buf[4096], *di, *si, *tmp;
    const char *val;
    const struct elem_data *data, *parent;
    enum etype etype;
    int res;
    size_t hdrlen;
    size_t sz;
    ssize_t nbytes;
    struct elem_stack *stk;
    struct elem_stack_ent *ent;
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
        return ERR_TAG(EILSEQ);
    totlen = hdrlen = sz;
    si = buf + sz;
    hdl->off += sz;

    /* parse EBML element length */
    res = parse_edatasz(&elen, &sz, si);
    if (res != 0)
        return res;
    if (elen == EDATASZ_UNKNOWN)
        elen = 0;
    hdrlen += sz;
    totlen += sz + elen;
    si += sz;
    hdl->off += sz;

    res = look_up_elem(hdl, EBML_ELEMENT_ID_WITH_MARKER, elen, totlen, hdrlen,
                       NULL, &etype, &val, &parent, &data, 1, 1, f);
    if (res != 0)
        return res;

    res = push_master(&hdl->stk, data, 0);
    if (res != 0)
        return res;

    res = invoke_user_cb(data->val, ETYPE_MASTER, NULL, NULL, 0, elen, hdrlen,
                         1, hdl);
    if (res != 0)
        return res;

    stk = &hdl->stk;

    ent = stk->stk[0];
    totlen -= elen;
    ent->hdrlen = ent->totlen = totlen;
    ent->elen = elen;

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
        int anon;
        int sz_unknown;

        /* parse EBML element ID */
        res = parse_eid(&eid, &hdrlen, si);
        if (res != 0)
            return res;
        totlen = hdrlen;
        si += hdrlen;
        hdl->off += hdrlen;

        /* parse EBML element length */
        res = parse_edatasz(&elen, &sz, si);
        if (res != 0)
            return res;
        sz_unknown = elen == EDATASZ_UNKNOWN;
        if (sz_unknown)
            elen = 0;
        hdrlen += sz;
        totlen += sz + elen;
        si += sz;
        hdl->off += sz;

        res = look_up_elem(hdl, eid, elen, totlen, hdrlen, NULL, &etype, &val,
                           &parent, &data, 1, n, f);
        if (res != 0)
            return res;

        if (sz_unknown && etype != ETYPE_MASTER)
            return ERR_TAG(EILSEQ);

        anon = eid == VOID_ELEMENT_ID || eid == CRC32_ELEMENT_ID;

        if (!anon)
            return_from_master(&hdl->stk, parent);

        if (flags & EBML_READ_FLAG_HEADER) {
            if (f != NULL && fputc('\t', f) == EOF)
                return ERR_TAG(EIO);

            sz = di - si;

            if (ETYPE_IS_FIXED_WIDTH(etype)) {
                res = handle_fixed_width_value(&si, &di, sz, etype, val, elen,
                                               hdrlen, NULL, 1, f, hdl);
            } else if (etype != ETYPE_MASTER) {
                res = handle_variable_length_value(NULL, &si, &di, 0, sz, etype,
                                                   val, elen, hdrlen, NULL, 1,
                                                   f, hdl);
            } else {
                if (!anon) {
                    res = push_master(&hdl->stk, data,
                                      eid == SEGMENT_ELEMENT_ID);
                    if (res != 0)
                        return res;
                }
                if (flags & EBML_READ_FLAG_MASTER) {
                    res = invoke_user_cb(val, ETYPE_MASTER, NULL, NULL, 0, elen,
                                         hdrlen, 1, hdl);
                }
            }
            if (res != 0)
                return res;
        }

        if (f != NULL && fputc('\n', f) == EOF)
            return ERR_TAG(EIO);

        if (etype != ETYPE_MASTER)
            hdl->off += elen;

        if (stk->len > 0) {
            if (!anon) {
                ent = stk->stk[stk->len-1];
                if (etype == ETYPE_MASTER) {
                    totlen -= elen;
                    ent->hdrlen = totlen;
                    ent->elen = elen;
                }
                ent->totlen += totlen;
            } else {
                ent = stk->stk[0];
                if (ent->segment)
                    ent->totlen += totlen;
            }
        }

        ++n;
    }

    return_from_master(&hdl->stk, NULL);

    return 0;
}

static int
parse_body(FILE *f, struct ebml_hdl *hdl, int flags)
{
    char *tmp;
    int eof;
    int res;
    off_t off;

    (void)flags;

    eof = 0;

    for (;;) {
        const char *val;
        const struct elem_data *data, *parent;
        enum etype etype;
        int anon;
        int sz_unknown;
        semantic_action_t *act;
        size_t hdrlen;
        size_t sz;
        struct elem_stack *stk;
        struct elem_stack_ent *ent;
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

        sz = hdl->di - hdl->si;

        /* read EBML element ID and length */
        tmp = hdl->si;
        hdl->si = hdl->di;
        hdl->di = tmp;
        if (!eof)
            eof = read_elem_hdr(hdl, &hdl->di, hdl->si);
        if (eof == 1) {
            if (sz == 0)
                goto eof;
            hdl->si = tmp;
            hdl->di = hdl->si + sz;
        } else if (eof != 0)
            return eof;

        /* parse EBML element ID */
        res = parse_eid(&eid, &hdrlen, tmp);
        if (res != 0)
            return res;
        totlen = hdrlen;
        hdl->si = tmp + hdrlen;
        hdl->off += hdrlen;

        /* parse EBML element length */
        res = parse_edatasz(&elen, &sz, hdl->si);
        if (res != 0)
            return res;
        sz_unknown = elen == EDATASZ_UNKNOWN;
        if (sz_unknown)
            elen = 0;
        hdrlen += sz;
        totlen += sz + elen;
        hdl->si += sz;
        hdl->off += sz;

        if (f != NULL && hdl->n == 1
            && fprintf(f, "body\t\t\t%" PRIu64 "\n", elen) < 0)
            return ERR_TAG(EIO);

        res = look_up_elem(hdl, eid, elen, totlen, hdrlen, &act, &etype, &val,
                           &parent, &data, 0, hdl->n, f);
        if (res != 0)
            return res;
        if (etype == ETYPE_NONE)
            return ERR_TAG(EILSEQ);

        if (sz_unknown && etype != ETYPE_MASTER)
            return ERR_TAG(EILSEQ);

        if (f != NULL && fprintf(f, "\t%s\t", typestrmap[etype]) < 0)
            return ERR_TAG(EIO);

        anon = eid == VOID_ELEMENT_ID || eid == CRC32_ELEMENT_ID;

        if (!anon)
            return_from_master(&hdl->stk, parent);

        sz = hdl->di - hdl->si;

        if (etype == ETYPE_MASTER) {
            if (!anon) {
                res = push_master(&hdl->stk, data, eid == SEGMENT_ELEMENT_ID);
                if (res != 0)
                    return res;
            }

            memmove(hdl->buf, hdl->si, sz);
            hdl->si = hdl->buf;
            hdl->di = hdl->si + sz;

            if (flags & EBML_READ_FLAG_MASTER) {
                res = invoke_user_cb(val, ETYPE_MASTER, NULL, NULL, 0, elen,
                                     hdrlen, 0, hdl);
                if (res != 0)
                    return res;
            }
        } else {
            if (ETYPE_IS_FIXED_WIDTH(etype)) {
                res = handle_fixed_width_value(&hdl->si, &hdl->di, sz, etype,
                                               val, elen, hdrlen, act, 0, f,
                                               hdl);
            } else {
                res = handle_variable_length_value(hdl->buf, &hdl->si, &hdl->di,
                                                   sizeof(hdl->buf), sz, etype,
                                                   val, elen, hdrlen, act, 0, f,
                                                   hdl);
            }
            if (res != 0)
                return res;

            if (elen > sz)
                hdl->di = hdl->si = hdl->buf;
            else
                hdl->si += elen;
            hdl->off += elen;
        }

        if (f != NULL && fputc('\n', f) == EOF)
            return ERR_TAG(EIO);

        stk = &hdl->stk;

        if (stk->len > 0) {
            if (!anon) {
                ent = stk->stk[stk->len-1];
                if (etype == ETYPE_MASTER) {
                    totlen -= elen;
                    ent->hdrlen = totlen;
                    ent->elen = elen;
                }
                ent->totlen += totlen;
            } else {
                ent = stk->stk[0];
                if (ent->segment)
                    ent->totlen += totlen;
            }
        }

        ++hdl->n;

        if (hdl->interrupt_read) {
            hdl->interrupt_read = 0;
            return 1;
        }
    }

    return 0;

eof:
    return_from_master(&hdl->stk, NULL);
    if (f != NULL && (*hdl->fns->get_fpos)(hdl->ctx, &off) == 0
        && fprintf(f, "EOF\t\t\t\t%lld\n", off) < 0)
        return ERR_TAG(EIO);
    return 0;
}

EXPORTED int
ebml_open(ebml_hdl_t *hdl, const ebml_io_fns_t *fns,
          const struct parser *parser, const struct semantic_processor *sproc,
          ebml_metadata_cb_t *cb, int ro, void *args, void *sproc_ctx,
          void *ctx)
{
    int err;
    struct ebml_hdl *ret;

    if (ocalloc(&ret, 1) == NULL)
        return ERR_TAG(errno);

    err = (*fns->open)(&ret->ctx, ro, args);
    if (err) {
        free(ret);
        return err;
    }
    ret->ro = ro;

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
    int err = 0, tmp;
    size_t i;
    struct elem_stack *stk;

    stk = &hdl->stk;

    for (i = 0; i < stk->len; i++)
        free(stk->stk[i]);
    free(stk->stk);

    if (!hdl->ro)
        err = (*hdl->fns->sync)(hdl->ctx);

    tmp = (*hdl->fns->close)(hdl->ctx);
    if (tmp != 0)
        err = tmp;

    free(hdl->valbuf);

    free(hdl);

    return err;
}

EXPORTED int
ebml_read(FILE *f, ebml_hdl_t hdl, int flags)
{
    int res;

    res = parse_header(f, hdl, flags);
    return res == 0 ? parse_body(f, hdl, flags) : res;
}

EXPORTED int
ebml_read_header(FILE *f, ebml_hdl_t hdl, int flags)
{
    return parse_header(f, hdl, flags);
}

EXPORTED int
ebml_read_body(FILE *f, ebml_hdl_t hdl, int flags)
{
    return parse_body(f, hdl, flags);
}

EXPORTED int
ebml_write(ebml_hdl_t hdl, const char *id, matroska_metadata_t *val, size_t len,
           int flags)
{
    char tmbuf[64];
    const struct elem_data *data;
    edata_t d;
    enum etype etype;
    int res;
    long int tmp;
    semantic_action_t *act;
    size_t buflen;
    size_t binhdrlen, hdrlen;
    struct tm tm;
    time_t date;
    uint64_t eid;

    res = parser_look_up(flags & EBML_WRITE_FLAG_HEADER
                         ? hdl->parser_ebml : hdl->parser_doc,
                         id, &data, NULL);
    if (res != 1)
        return ERR_TAG(res == 0 ? EINVAL : -res);
    etype = data->etype;

    fprintf(stderr, "%s: ", id);
    switch (etype) {
    case ETYPE_INTEGER:
        fprintf(stderr, "%" PRIi64, val->integer);
        break;
    case ETYPE_UINTEGER:
        fprintf(stderr, "%" PRIu64, val->uinteger);
        break;
    case ETYPE_FLOAT:
        fprintf(stderr, "%f", val->dbl);
        break;
    case ETYPE_STRING:
    case ETYPE_UTF8:
        fprintf(stderr, "%s", val->data);
        break;
    case ETYPE_DATE:
        tm = (struct tm)REFERENCE_TIME;
        date = mktime(&tm) + val->integer / TIME_GRAN;
        ctime_r(&date, tmbuf);
        buflen = strlen(tmbuf);
        if (buflen > 0) {
            --buflen;
            if (tmbuf[buflen] == '\n')
                tmbuf[buflen] = '\0';
        }
        fprintf(stderr, "%s", tmbuf);
        break;
    case ETYPE_MASTER:
        fprintf(stderr, "%zu byte%s", PL(len));
        /* fallthrough */
    default:
        break;
    }
    fputc('\n', stderr);

    /* output EBML element ID */

    if (al64(id, &tmp) == -1)
        return ERR_TAG(EILSEQ);
    eid = tmp;

    fprintf(stderr, "Inserting EID 0x%" PRIX64 "\n", eid);

    hdrlen = sizeof(hdl->buf);
    res = output_eid(hdl->buf, &hdrlen, eid);
    if (res != 0)
        return res;
    hdl->si = hdl->buf + hdrlen;
    hdl->off = hdrlen;

    act = NULL;
    res = semantic_processor_look_up(hdl->sproc, id, &act);
    if (res != 0 && res != 1)
        return ERR_TAG(-res);

    /* output EBML element length */

    if (etype == ETYPE_BINARY) {
        binhdrlen = 0;
        res = invoke_binary_handler(etype, act, NULL, &binhdrlen, NULL,
                                    &binhdrlen, buflen, hdrlen, 1, hdl);
        if (res != 0)
            return res;
        val->len += binhdrlen;
    }

    buflen = sizeof(hdl->buf) - hdrlen;
    res = output_edatasz(hdl->si, &buflen, val, etype);
    if (res != 0)
        return res;
    hdrlen += buflen;
    hdl->off += buflen;

    res = (*hdl->fns->write)(hdl->ctx, hdl->buf, hdl->off);
    if (res != 0)
        return res;

    if (etype == ETYPE_MASTER)
        return 0;

    d.type = etype;
    if (ETYPE_IS_FIXED_WIDTH(etype) || ETYPE_IS_STRING(etype)) {
        switch (etype) {
        case ETYPE_INTEGER:
            d.integer = val->integer;
            break;
        case ETYPE_UINTEGER:
            d.uinteger = val->uinteger;
            break;
        case ETYPE_FLOAT:
            d.floats = val->dbl;
            d.dbl = d.floats != val->dbl;
            if (d.dbl)
                d.floatd = val->dbl;
            break;
        case ETYPE_STRING:
        case ETYPE_UTF8:
            d.ptr = val->data;
            buflen = val->len;
            break;
        case ETYPE_DATE:
            d.date = val->integer;
            break;
        default:
            abort();
        }

        res = edata_pack(&d, hdl->buf, etype, &buflen);
        if (res != 0)
            return res;

        res = invoke_value_handler(etype, hdrlen, act, &d, hdl);
        if (res != 0)
            return res;

        res = (*hdl->fns->write)(hdl->ctx, hdl->buf, buflen);
    } else {
        void *bufp;

        bufp = val->data;
        buflen = val->len - binhdrlen;
        res = invoke_binary_handler(etype, act, &bufp, &buflen, &hdl->valbuf,
                                    &hdl->vallen, buflen, hdrlen, 1, hdl);
        if (res != 0)
            return res;

        res = (*hdl->fns->write)(hdl->ctx, bufp, buflen);
    }
    if (res != 0)
        return res;

    return 0;
}

void *
ebml_ctx(ebml_hdl_t hdl)
{
    return hdl->ctx;
}

/* vi: set expandtab sw=4 ts=4: */
