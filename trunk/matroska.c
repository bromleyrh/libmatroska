/*
 * matroska.c
 */

#include "ebml.h"
#include "matroska.h"
#include "vint.h"

#include <avl_tree.h>
#include <malloc_ext.h>

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/param.h>

#define LIST_BLOCK_HDR_FIELDS() \
    _X(TRACKNO,     8) \
    _X(TIMESTAMP,   2) \
    _X(FLAGS,       1)

#define _X(nm, len) \
enum { \
    BLOCK_HDR_##nm##_LEN = len \
};
LIST_BLOCK_HDR_FIELDS()
#undef _X

enum content_comp_algo {
    CONTENT_COMP_ALGO_ZLIB,
    CONTENT_COMP_ALGO_BZLIB,
    CONTENT_COMP_ALGO_LZO1X,
    CONTENT_COMP_ALGO_HEADER_STRIPPING
};

struct track_data {
    uint64_t                trackno;
    enum content_comp_algo  compalg;
    const void              *stripped_bytes;
    size_t                  num_stripped_bytes;
};

struct matroska_state {
    ebml_hdl_t              hdl;
    matroska_bitstream_cb_t *cb;
    void                    *ctx;
    int                     block_hdr;
#define _X(nm, len) + len
    char                    hdr_buf[LIST_BLOCK_HDR_FIELDS()];
#undef _X
    size_t                  hdr_len;
    size_t                  hdr_sz;
    size_t                  data_len;
    uint64_t                trackno;
    struct avl_tree         *track_data;
};

#define BLOCK_FLAG_KEYFRAME 128
#define BLOCK_FLAG_RESERVED 112
#define BLOCK_FLAG_INVISIBLE 8
#define BLOCK_FLAG_DISCARDABLE 1

#define BLOCK_FLAG_LACING_SHIFT 1
#define BLOCK_FLAG_LACING_MASK (3 << BLOCK_FLAG_LACING_SHIFT)

#define BLOCK_FLAG_LACING_XIPH (1 << BLOCK_FLAG_LACING_SHIFT)
#define BLOCK_FLAG_LACING_FIXED_SIZE (2 << BLOCK_FLAG_LACING_SHIFT)
#define BLOCK_FLAG_LACING_EBML (3 << BLOCK_FLAG_LACING_SHIFT)

static const char *const compalg_typemap[] = {
    [CONTENT_COMP_ALGO_ZLIB]                = "zlib",
    [CONTENT_COMP_ALGO_BZLIB]               = "bzip2",
    [CONTENT_COMP_ALGO_LZO1X]               = "Lempel-Ziv-Oberhumer",
    [CONTENT_COMP_ALGO_HEADER_STRIPPING]    = "header stripping"
};

#define PRINT_HANDLER_INFO(val) print_handler(stderr, __FUNCTION__, val)

static int print_handler(FILE *, const char *, const char *);

static int track_data_cmp(const void *, const void *, void *);
static int track_data_free(const void *, void *);

static int
print_handler(FILE *f, const char *func, const char *val)
{
    return fprintf(f, "%s(): %s\n", func, val) < 0 ? -EIO : 0;
}

static int
track_data_cmp(const void *k1, const void *k2, void *ctx)
{
    const struct track_data *tdata1 = *(const struct track_data *const *)k1;
    const struct track_data *tdata2 = *(const struct track_data *const *)k2;

    (void)ctx;

    return (tdata1->trackno > tdata2->trackno)
           - (tdata1->trackno < tdata2->trackno);
}

static int
track_data_free(const void *keyval, void *ctx)
{
    struct track_data *tdata = *(struct track_data *const *)keyval;

    (void)ctx;

    free(tdata);

    return 0;
}

int
matroska_tracknumber_handler(const char *val, enum etype etype, edata_t *edata,
                             const void *buf, size_t len, void *ctx)
{
    int err;
    struct matroska_state *state = ctx;

    (void)buf;
    (void)len;

    if (state->track_data == NULL) {
        err = avl_tree_new(&state->track_data, sizeof(struct track_data *),
                           &track_data_cmp, 0, NULL, NULL, NULL);
        if (err)
            return err;
    }

    if (val == NULL) {
        struct track_data *tdata;

        if (etype != ETYPE_UINTEGER)
            return -EILSEQ;

        if (omalloc(&tdata) == NULL)
            return -errno;

        tdata->trackno = edata->uinteger;
        tdata->compalg = -1;
        tdata->stripped_bytes = NULL;
        tdata->num_stripped_bytes = 0;

        err = avl_tree_insert(state->track_data, &tdata);
        if (err) {
            free(tdata);
            return err;
        }

        fprintf(stderr, "Track number %" PRIu64 "\n", tdata->trackno);

        state->trackno = tdata->trackno;
    } else
        PRINT_HANDLER_INFO(val);

    return 0;
}

#define BLOCK_HDR_FIXED_LEN (BLOCK_HDR_TIMESTAMP_LEN + BLOCK_HDR_FLAGS_LEN)

#define FLAG_VAL(flags, which) (!!((flags) & BLOCK_FLAG_##which))

int
matroska_simpleblock_handler(const char *val, enum etype etype, edata_t *edata,
                             const void *buf, size_t len, void *ctx)
{
    int lacing;
    int res = 0;
    size_t datalen, sz;
    struct matroska_state *state = ctx;

    (void)edata;

    if (etype != ETYPE_BINARY)
        return -EILSEQ;

    if (val != NULL) {
        if (state->data_len != 0)
            return -EIO;
        state->block_hdr = 0;
        PRINT_HANDLER_INFO(val);
        return 0;
    }

    if (buf == NULL) {
        if (state->data_len != len)
            return -EIO;
        state->data_len = 0;
        fprintf(stderr, "End of block (%zu bytes)\n", len);
        return 0;
    }

    if (state->block_hdr == 1) {
        state->data_len += len;
        if (state->cb != NULL) {
            res = (*state->cb)(state->trackno, buf, len, state->ctx);
            if (res != 0)
                return res;
        }
        fputs("...\n", stderr);
        return 0;
    }

    if (state->block_hdr == 0) {
        res = vint_to_u64(buf, NULL, &state->hdr_sz);
        if (res != 0)
            return res;
        state->hdr_len = 0;
        state->hdr_sz += BLOCK_HDR_FIXED_LEN;

        state->data_len = state->hdr_sz;

        state->block_hdr = 2;
    }

    sz = MIN(state->hdr_sz, len);

    if (sz > sizeof(state->hdr_buf) - state->hdr_len)
        return -EILSEQ;

    memcpy(state->hdr_buf + state->hdr_len, buf, sz);
    state->hdr_len += sz;
    state->hdr_sz -= sz;

    if (state->hdr_sz == 0) {
        struct track_data tdata, *tdatap;
        uint8_t flags;
        union {
            int16_t val;
            char    bytes[2];
        } timestamp;

        static const char *const lacing_typemap[] = {
            [0]                             = "none",
            [BLOCK_FLAG_LACING_XIPH]        = "Xiph",
            [BLOCK_FLAG_LACING_FIXED_SIZE]  = "fixed-size",
            [BLOCK_FLAG_LACING_EBML]        = "EBML"
        };

        res = vint_to_u64(state->hdr_buf, &state->trackno, &datalen);
        if (res != 0)
            return res;
        if (datalen != state->hdr_len - BLOCK_HDR_FIXED_LEN)
            return -EILSEQ;

        timestamp.bytes[0] = state->hdr_buf[datalen+1];
        timestamp.bytes[1] = state->hdr_buf[datalen];

        flags = state->hdr_buf[datalen + BLOCK_HDR_TIMESTAMP_LEN];

        if ((flags & BLOCK_FLAG_RESERVED) != 0)
            return -EILSEQ;

        lacing = flags & BLOCK_FLAG_LACING_MASK;

        tdata.trackno = state->trackno;

        tdatap = &tdata;
        res = avl_tree_search(state->track_data, &tdatap, &tdatap);
        if (res != 1)
            return res == 0 ? -EILSEQ : res;

        fprintf(stderr, "Track number %" PRIu64 "\n"
                        "Timestamp %" PRIi16 "\n"
                        "Flags %" PRIu8 "\n"
                        "Keyframe %d\n"
                        "Invisible %d\n"
                        "Discardable %d\n"
                        "Lacing type %s\n"
                        "Content compression algorithm %s\n",
                tdatap->trackno, timestamp.val, flags,
                FLAG_VAL(flags, KEYFRAME),
                FLAG_VAL(flags, INVISIBLE),
                FLAG_VAL(flags, DISCARDABLE),
                lacing_typemap[lacing], compalg_typemap[tdatap->compalg]);

        state->block_hdr = 1;
    }

    if (state->cb != NULL) {
        datalen = len - sz;
        if (datalen > 0) {
            int off;

            state->data_len += datalen;

            off = lacing == BLOCK_FLAG_LACING_FIXED_SIZE;
            res = (*state->cb)(state->trackno, buf + sz + off, datalen - off,
                               state->ctx);
        }
    }

    return res;
}

#undef BLOCK_HDR_FIXED_LEN

#undef FLAG_VAL

int
matroska_contentcompalgo_handler(const char *val, enum etype etype,
                                 edata_t *edata, const void *buf, size_t len,
                                 void *ctx)
{
    int res;
    struct matroska_state *state = ctx;

    (void)buf;
    (void)len;

    if (etype != ETYPE_UINTEGER)
        return -EILSEQ;

    if (val == NULL) {
        struct track_data tdata, *tdatap;

        tdata.trackno = state->trackno;

        tdatap = &tdata;
        res = avl_tree_search(state->track_data, &tdatap, &tdatap);
        if (res != 1)
            return res == 0 ? -EILSEQ : res;

        tdatap->compalg = edata->uinteger;

        fprintf(stderr, "ContentCompAlgo(%" PRIu64 ") = %s\n",
                state->trackno, compalg_typemap[tdatap->compalg]);
    } else
        PRINT_HANDLER_INFO(val);

    return 0;
}

int
matroska_contentcompsettings_handler(const char *val, enum etype etype,
                                     edata_t *edata, const void *buf,
                                     size_t len, void *ctx)
{
    struct matroska_state *state = ctx;

    (void)edata;
    (void)buf;

    if (etype != ETYPE_BINARY)
        return -EILSEQ;

    if (val == NULL) {
        fprintf(stderr, "|ContentCompSettings(%" PRIu64 ")| == %zu bytes\n",
                state->trackno, len);
    } else
        PRINT_HANDLER_INFO(val);

    return 0;
}

int
matroska_open(matroska_hdl_t *hdl, int fd, const char *pathname,
              matroska_bitstream_cb_t *cb, void *ctx)
{
    int err;
    struct ebml_file_args args;
    struct matroska_state *ret;

    if (ocalloc(&ret, 1) == NULL)
        return -errno;

    args.fd = fd;
    args.pathname = pathname;
    err = ebml_open(&ret->hdl, EBML_FILE_FNS, MATROSKA_PARSER,
                    MATROSKA_SEMANTIC_PROCESSOR, &args, ret);
    if (err) {
        free(ret);
        return err;
    }

    ret->cb = cb;
    ret->ctx = ctx;

    *hdl = ret;
    return 0;
}

int
matroska_close(matroska_hdl_t hdl)
{
    int err;

    if (hdl->track_data != NULL) {
        avl_tree_walk_ctx_t wctx = NULL;

        avl_tree_walk(hdl->track_data, NULL, &track_data_free, NULL, &wctx);
        avl_tree_free(hdl->track_data);
    }

    err = ebml_close(hdl->hdl);

    free(hdl);

    return err;
}

int
matroska_read(FILE *f, matroska_hdl_t hdl)
{
    return ebml_read(f, hdl->hdl);
}

/* vi: set expandtab sw=4 ts=4: */
