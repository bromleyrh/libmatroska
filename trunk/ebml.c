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

struct buf {
    char        *eid;
    size_t      eidsz;
    char        *elen;
    uint64_t    orig_elenval;
    uint64_t    elenval;
    size_t      elensz;
    char        *binhdr;
    size_t      binhdrsz;
    char        *data;
    size_t      datasz;
};

struct buf_list {
    struct buf  **ents;
    size_t      len;
    size_t      sz;
};

struct elem_stack_ent {
    const struct elem_data  *data;
    size_t                  hdrlen;
    uint64_t                elen;
    uint64_t                totlen;
    unsigned                segment;
    struct buf              *buf;
    ebml_master_cb_t        *master_cb;
    ebml_master_free_cb_t   *master_free_cb;
    void                    *mdata;
    void                    *mctx;
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
    struct buf_list                 buf_list;
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
                          enum etype, uint64_t *);

static int look_up_elem(struct ebml_hdl *, uint64_t, uint64_t, uint64_t, size_t,
                        semantic_action_t **, enum etype *, const char **,
                        const struct elem_data **, const struct elem_data **,
                        int, uint64_t, FILE *);

static int buf_new(struct buf **, char *, size_t, char *, size_t, uint64_t,
                   size_t, int);
static void buf_destroy(struct buf *);

static int buf_list_init(struct buf_list *);
static void buf_list_destroy(struct buf_list *);
static int buf_list_insert(struct buf_list *, char *, size_t, char *, size_t,
                           uint64_t, size_t, int);
static struct buf *buf_list_tail(struct buf_list *);
static int buf_list_flush(struct buf_list *, struct ebml_hdl *);

static int resize_master_elem(struct buf *, int64_t *);

static int push_master(struct elem_stack *, const struct elem_data *,
                       unsigned, struct buf *, ebml_master_cb_t *,
                       ebml_master_free_cb_t *, void *, void *);
static int release_master(struct elem_stack_ent *);
static int return_from_master(struct elem_stack *, const struct elem_data *,
                              struct buf_list *, struct ebml_hdl *);

static int invoke_value_handler(enum etype, size_t, semantic_action_t *,
                                edata_t *, struct ebml_hdl *);
static int invoke_binary_handler(enum etype, semantic_action_t *, void **,
                                 size_t *, void **, size_t *, size_t, size_t,
                                 struct buf *, int, struct ebml_hdl *);

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
                         tot_elen, hdrlen, NULL, hdl->off, hdl->sproc_ctx, 0);
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
               enum etype etype, uint64_t *elen)
{
    int err;
    uint64_t ret;

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
        ret = len;
    } else
        ret = val->len == (size_t)-1 ? EDATASZ_UNKNOWN : val->len;

    err = u64_to_edatasz(ret, bufp, sz);
    if (!err)
        *elen = ret;

    return err;
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
                        hdrlen, NULL, hdl->off, hdl->sproc_ctx, 0);
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
buf_new(struct buf **buf, char *eid, size_t eidsz, char *elen, size_t elensz,
        uint64_t elenval, size_t datasz, int master)
{
    int err;
    struct buf *ret;

    if (omalloc(&ret) == NULL)
        return ERR_TAG(errno);

    ret->eid = malloc(eidsz);
    if (ret->eid == NULL) {
        err = ERR_TAG(errno);
        goto err1;
    }

    ret->elen = malloc(elensz);
    if (ret->elen == NULL) {
        err = ERR_TAG(errno);
        goto err2;
    }

    if (datasz != 0) {
        ret->data = malloc(datasz);
        if (ret->data == NULL) {
            err = ERR_TAG(errno);
            goto err3;
        }
    } else
        ret->data = NULL;
    ret->datasz = datasz;

    memcpy(ret->eid, eid, eidsz);
    ret->eidsz = eidsz;

    memcpy(ret->elen, elen, elensz);
    if (!master)
        ret->elenval = elenval;
    ret->orig_elenval = elenval;
    ret->elensz = elensz;

    ret->binhdr = NULL;
    ret->binhdrsz = 0;

    *buf = ret;
    return 0;

err3:
    free(ret->elen);
err2:
    free(ret->eid);
err1:
    free(ret);
    return err;
}

static void
buf_destroy(struct buf *buf)
{
    free(buf->eid);
    free(buf->elen);
    free(buf->binhdr);
    free(buf->data);

    free(buf);
}

static int
buf_list_init(struct buf_list *list)
{
    list->len = 0;
    list->sz = 16;
    return oallocarray(&list->ents, list->sz) == NULL ? ERR_TAG(errno) : 0;
}

static void
buf_list_destroy(struct buf_list *list)
{
    size_t i;

    for (i = 0; i < list->len; i++)
        buf_destroy(list->ents[i]);

    free(list->ents);
}

static int
buf_list_insert(struct buf_list *list, char *eid, size_t eidsz, char *elen,
                size_t elensz, uint64_t elenval, size_t datasz, int master)
{
    int err;

    if (list->sz == list->len) {
        struct buf **tmp;
        size_t newsz;

        newsz = 2 * list->sz;
        if (oreallocarray(list->ents, &tmp, newsz) == NULL)
            return ERR_TAG(errno);
        list->ents = tmp;
        list->sz = newsz;
    }

    err = buf_new(&list->ents[list->len], eid, eidsz, elen, elensz, elenval,
                  datasz, master);
    if (!err)
        ++list->len;

    return err;
}

static struct buf *
buf_list_tail(struct buf_list *list)
{
    return list->len == 0 ? NULL : list->ents[list->len-1];
}

#define E(nm) {offsetof(struct buf, nm), offsetof(struct buf, nm##sz)}

static int
buf_list_flush(struct buf_list *list, struct ebml_hdl *hdl)
{
    int res;
    size_t i, j;

    static const struct ent {
        size_t dataoff;
        size_t szoff;
    } bufs[] = {
        E(eid),
        E(elen),
        E(binhdr),
        E(data)
    };

    for (i = 0; i < list->len; i++) {
        struct buf *buf = list->ents[i];

        for (j = 0; j < ARRAY_SIZE(bufs); j++) {
            char *data;
            const struct ent *ent = &bufs[j];
            size_t sz;

            sz = *(size_t *)((char *)buf + ent->szoff);
            if (sz == 0)
                continue;

            data = *(char **)((char *)buf + ent->dataoff);

            res = (*hdl->fns->write)(hdl->ctx, data, sz);
            if (res != 0)
                return res;
        }

        buf_destroy(buf);
    }

    list->len = 0;

    return 0;
}

#undef E

static int
resize_master_elem(struct buf *buf, int64_t *adj)
{
    char elen[EDATASZ_MAX_LEN];
    int err;
    int64_t adjust;
    size_t elensz;

    elensz = sizeof(elen);
    err = u64_to_edatasz(buf->elenval, elen, &elensz);
    if (err)
        return err;

    adjust = (int64_t)elensz - (int64_t)buf->elensz;

    if (adjust > 0) {
        char *tmp;

        tmp = realloc(buf->elen, elensz);
        if (tmp == NULL)
            return ERR_TAG(errno);
        buf->elen = tmp;
    }

    memcpy(buf->elen, elen, elensz);
    buf->elensz = elensz;

    *adj = adjust;
    return 0;
}

static int
push_master(struct elem_stack *stk, const struct elem_data *data,
            unsigned segment, struct buf *buf, ebml_master_cb_t *master_cb,
            ebml_master_free_cb_t *master_free_cb, void *mdata, void *mctx)
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
    ent->buf = buf;
    ent->master_cb = master_cb;
    ent->master_free_cb = master_free_cb;
    ent->mdata = mdata;
    ent->mctx = mctx;

    stk->stk[stk->len++] = ent;

    return 0;
}

static int
release_master(struct elem_stack_ent *ent)
{
    int err;
    struct buf *buf;

    if (ent->segment)
        return 0;

    buf = ent->buf;

    if (buf == NULL)
        return 0;

    buf->elenval = ent->totlen - ent->hdrlen;
    if (buf->orig_elenval != buf->elenval) {
        int64_t adj;

        fprintf(stderr, "Element length %" PRIu64 " byte%s"
                        " (%+" PRIi64 " byte%s)\n",
                PL(buf->elenval),
                PL((int64_t)buf->elenval - (int64_t)buf->orig_elenval));

        err = resize_master_elem(buf, &adj);
        if (err)
            return err;
        ent->totlen += adj;
    }

    return 0;
}

static int
return_from_master(struct elem_stack *stk, const struct elem_data *next_parent,
                   struct buf_list *buf_list, struct ebml_hdl *hdl)
{
    int ret;
    size_t idx, len;
    struct elem_stack_ent *ent;
    uint64_t tmp;

    len = stk->len;

    if (len == 0)
        return 0;
    idx = len - 1;

    ent = stk->stk[idx];

    if (next_parent == ent->data)
        return 0;

    for (;;) {
        tmp = ent->totlen - ent->hdrlen;
        if (ent->elen != EDATASZ_UNKNOWN && tmp != ent->elen) {
            fprintf(stderr, "Synchronization error: master element size"
                            " %" PRIu64 " byte%s (%+" PRIi64 " byte%s)\n",
                    PL(tmp), PL((int64_t)tmp - (int64_t)ent->elen));
            abort();
        }
        fprintf(stderr, "Master element %s has size %" PRIu64 " byte%s\n",
                ent->data->val, PL(tmp));

        if (ent->master_cb != NULL) {
            ret = (*ent->master_cb)(ent->data->val, ent->hdrlen, ent->totlen,
                                    ent->mdata, ent->mctx);
            if (ret != 0)
                return ret;
        }

        ret = release_master(ent);
        if (ret != 0)
            return ret;

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

    for (tmp = len - 1;; tmp--) {
        ent = stk->stk[tmp];
        if (ent->master_free_cb != NULL)
            (*ent->master_free_cb)(ent->mdata, ent->mctx);
        if (tmp == idx)
            break;
    }

    stk->len = idx;
    len -= idx;

    fprintf(stderr, "Returned up %zu level%s to %s\n",
            PL(len), idx == 0 ? "root" : next_parent->val);

    return buf_list != NULL && (idx == 0 || stk->stk[idx-1]->segment)
           ? buf_list_flush(buf_list, hdl) : 0;
}

static int
invoke_value_handler(enum etype etype, size_t hdrlen, semantic_action_t *act,
                     edata_t *edata, struct ebml_hdl *hdl)
{
    return act != NULL
           ? (*act)(NULL, etype, edata, NULL, NULL, NULL, 0, 0, hdrlen, NULL,
                    hdl->off, hdl->sproc_ctx, 0)
           : 0;
}

static int
invoke_binary_handler(enum etype etype, semantic_action_t *act, void **outbuf,
                      size_t *outlen, void **buf, size_t *len, size_t totlen,
                      size_t hdrlen, struct buf *bufhdl, int encode,
                      struct ebml_hdl *hdl)
{
    int res;

    if (etype != ETYPE_BINARY || act == NULL)
        return 0;

    res = (*act)(NULL, ETYPE_BINARY, NULL, outbuf, outlen, buf, len, totlen,
                 hdrlen, bufhdl, hdl->off, hdl->sproc_ctx, encode);
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
                                    elen, hdrlen, NULL, 0, hdl);
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
                                        elen, hdrlen, NULL, 0, hdl);
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
                                    elen, hdrlen, NULL, 0, hdl);
        if (res != 0)
            return res;
    }

    buflen = elen;
    res = invoke_binary_handler(val.type, act, NULL, NULL, NULL, &buflen, elen,
                                hdrlen, NULL, 0, hdl);
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

    res = push_master(&hdl->stk, data, 0, NULL, NULL, NULL, NULL, NULL);
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
            return_from_master(&hdl->stk, parent, NULL, NULL);

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
                                      eid == SEGMENT_ELEMENT_ID, NULL, NULL,
                                      NULL, NULL, NULL);
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

    return_from_master(&hdl->stk, NULL, NULL, NULL);

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
            return_from_master(&hdl->stk, parent, NULL, NULL);

        sz = hdl->di - hdl->si;

        if (etype == ETYPE_MASTER) {
            if (!anon) {
                res = push_master(&hdl->stk, data, eid == SEGMENT_ELEMENT_ID,
                                  NULL, NULL, NULL, NULL, NULL);
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
                    if (sz_unknown)
                        ent->elen = EDATASZ_UNKNOWN;
                    else {
                        totlen -= elen;
                        ent->elen = elen;
                    }
                    ent->hdrlen = totlen;
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
    return_from_master(&hdl->stk, NULL, NULL, NULL);
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

    if (!ro) {
        err = buf_list_init(&ret->buf_list);
        if (err) {
            err = ERR_TAG(-err);
            goto err1;
        }
    }

    err = (*fns->open)(&ret->ctx, ro, args);
    if (err)
        goto err2;
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

err2:
    if (!ro)
        buf_list_destroy(&ret->buf_list);
err1:
    free(ret);
    return err;
}

EXPORTED int
ebml_close(ebml_hdl_t hdl)
{
    int err = 0, tmp;
    size_t i;
    struct elem_stack *stk;

    if (!hdl->ro) {
        err = return_from_master(&hdl->stk, NULL, &hdl->buf_list, hdl);
        buf_list_destroy(&hdl->buf_list);
        tmp = (*hdl->fns->sync)(hdl->ctx);
        if (tmp != 0)
            err = tmp;
    }

    tmp = (*hdl->fns->close)(hdl->ctx);
    if (tmp != 0)
        err = tmp;

    stk = &hdl->stk;

    for (i = 0; i < stk->len; i++) {
        struct elem_stack_ent *ent = stk->stk[i];

        if (ent->master_free_cb != NULL)
            (*ent->master_free_cb)(ent->mdata, ent->mctx);
        free(ent);
    }
    free(stk->stk);

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
ebml_write(ebml_hdl_t hdl, const char *id, matroska_metadata_t *val,
           size_t *len, size_t *hdrlen, ebml_master_cb_t *master_cb,
           ebml_master_free_cb_t *master_free_cb, void *mdata, void *mctx,
           int flags)
{
    char tmbuf[64];
    const struct elem_data *data, *parent;
    edata_t d;
    enum etype etype;
    int anon, segment;
    int res;
    long int tmp;
    semantic_action_t *act;
    size_t buflen;
    size_t binhlen, hlen;
    struct buf *buf;
    struct elem_stack *stk;
    struct elem_stack_ent *ent;
    struct tm tm;
    time_t date;
    uint64_t eid, elen;

    res = parser_look_up(flags & EBML_WRITE_FLAG_HEADER
                         ? hdl->parser_ebml : hdl->parser_doc,
                         id, &data, &parent);
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
        fprintf(stderr, "%zu byte%s", PL(*len));
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

    hlen = sizeof(hdl->buf);
    res = output_eid(hdl->buf, &hlen, eid);
    if (res != 0)
        return res;
    hdl->si = hdl->buf + hlen;
    hdl->off = hlen;

    act = NULL;
    res = semantic_processor_look_up(hdl->sproc, id, &act);
    if (res != 0 && res != 1)
        return ERR_TAG(-res);

    segment = eid == SEGMENT_ELEMENT_ID;

    /* output EBML element length */

    buflen = sizeof(hdl->buf) - hlen;

    binhlen = 0;
    if (etype == ETYPE_BINARY) {
        res = invoke_binary_handler(etype, act, NULL, &binhlen, NULL, &binhlen,
                                    buflen, hlen, NULL, 1, hdl);
        if (res != 0)
            return res;
        val->len += binhlen;
    } else if (segment)
        val->len = (size_t)-1;

    res = output_edatasz(hdl->si, &buflen, val, etype, &elen);
    if (res != 0)
        return res;
    hlen += buflen;
    hdl->off += buflen;

/*    res = (*hdl->fns->write)(hdl->ctx, hdl->buf, hdl->off);
    if (res != 0)
        return res;
*/
    stk = &hdl->stk;

    anon = eid == VOID_ELEMENT_ID || eid == CRC32_ELEMENT_ID;

    if (!anon) {
        res = return_from_master(stk, parent, &hdl->buf_list, hdl);
        if (res != 0)
            return res;
    }

    res = buf_list_insert(&hdl->buf_list, hdl->buf, hlen - buflen, hdl->si,
                          buflen, elen, etype == ETYPE_MASTER ? 0 : elen,
                          etype == ETYPE_MASTER);
    if (res != 0)
        return res;
    buf = buf_list_tail(&hdl->buf_list);

    if (etype == ETYPE_MASTER) {
        if (!anon) {
            res = push_master(stk, data, segment, buf, master_cb,
                              master_free_cb, mdata, mctx);
            if (res != 0)
                return res;
        }
        goto end;
    }

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

        res = invoke_value_handler(etype, hlen, act, &d, hdl);
        if (res != 0)
            return res;

        memcpy(buf->data, hdl->buf, buflen);
/*        res = (*hdl->fns->write)(hdl->ctx, hdl->buf, buflen);*/
    } else {
        void *bufp;

        bufp = val->data;
        buflen = val->len - binhlen;
        res = invoke_binary_handler(etype, act, &bufp, &buflen, &hdl->valbuf,
                                    &hdl->vallen, buflen, hlen, buf, 1, hdl);
        if (res != 0)
            return res;

        memcpy(buf->data, bufp, buflen);
/*        res = (*hdl->fns->write)(hdl->ctx, bufp, buflen);*/
    }

end:

    if (stk->len > 0) {
        if (!anon) {
            ent = stk->stk[stk->len-1];
            if (etype == ETYPE_MASTER) {
                ent->hdrlen = buflen = hlen;
                ent->elen = EDATASZ_UNKNOWN;
            } else
                ent->totlen += hlen + binhlen;
            ent->totlen += buflen;
        } else {
            ent = stk->stk[0];
            if (ent->segment)
                ent->totlen += buflen;
        }
    } else {
        res = buf_list_flush(&hdl->buf_list, hdl);
        if (res != 0)
            return res;
    }

    if (len != NULL)
        *len = binhlen + buflen;
    if (hdrlen != NULL)
        *hdrlen = hlen;
    return 0;
}

void *
ebml_ctx(ebml_hdl_t hdl)
{
    return hdl->ctx;
}

int
buf_set_binhdr(struct buf *buf, char *binhdr, size_t binhdrsz)
{
    char *bufp;

    bufp = malloc(binhdrsz);
    if (bufp == NULL)
        return ERR_TAG(errno);

    memcpy(bufp, binhdr, binhdrsz);

    buf->binhdr = bufp;
    buf->binhdrsz = binhdrsz;
    buf->datasz -= binhdrsz;

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
