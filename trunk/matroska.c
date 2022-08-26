/*
 * matroska.c
 */

#include "ebml.h"
#include "matroska.h"
#include "vint.h"

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

int
matroska_tracknumber_handler(const char *val, const void *buf, size_t len,
                             void *ctx)
{
    (void)buf;
    (void)len;
    (void)ctx;

    if (val == NULL)
        fputs("...\n", stderr);
    else
        fprintf(stderr, "%s(): %s\n", __FUNCTION__, val);

    return 0;
}

#define BLOCK_HDR_FIXED_LEN (BLOCK_HDR_TIMESTAMP_LEN + BLOCK_HDR_FLAGS_LEN)

#define FLAG_VAL(flags, which) (!!((flags) & BLOCK_FLAG_##which))

int
matroska_simpleblock_handler(const char *val, const void *buf, size_t len,
                             void *ctx)
{
    int err = 0;
    int lacing;
    size_t datalen, sz;
    struct matroska_state *state = ctx;

    if (val != NULL) {
        if (state->data_len != 0)
            return -EIO;
        state->block_hdr = 0;
        fprintf(stderr, "%s(): %s\n", __FUNCTION__, val);
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
            err = (*state->cb)(state->trackno, buf, len, state->ctx);
            if (err)
                return err;
        }
        fputs("...\n", stderr);
        return 0;
    }

    if (state->block_hdr == 0) {
        err = vint_to_u64(buf, NULL, &state->hdr_sz);
        if (err)
            return err;
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

        err = vint_to_u64(state->hdr_buf, &state->trackno, &datalen);
        if (err)
            return err;
        if (datalen != state->hdr_len - BLOCK_HDR_FIXED_LEN)
            return -EILSEQ;

        timestamp.bytes[0] = state->hdr_buf[datalen+1];
        timestamp.bytes[1] = state->hdr_buf[datalen];

        flags = state->hdr_buf[datalen + BLOCK_HDR_TIMESTAMP_LEN];

        if ((flags & BLOCK_FLAG_RESERVED) != 0)
            return -EILSEQ;

        lacing = flags & BLOCK_FLAG_LACING_MASK;

        fprintf(stderr, "Track number %" PRIu64 "\n"
                        "Timestamp %" PRIi16 "\n"
                        "Flags %" PRIu8 "\n"
                        "Keyframe %d\n"
                        "Invisible %d\n"
                        "Discardable %d\n"
                        "Lacing type %s\n",
                state->trackno, timestamp.val, flags,
                FLAG_VAL(flags, KEYFRAME),
                FLAG_VAL(flags, INVISIBLE),
                FLAG_VAL(flags, DISCARDABLE),
                lacing_typemap[lacing]);

        state->block_hdr = 1;
    }

    if (state->cb != NULL) {
        datalen = len - sz;
        if (datalen > 0) {
            int off;

            state->data_len += datalen;

            off = lacing == BLOCK_FLAG_LACING_FIXED_SIZE;
            err = (*state->cb)(state->trackno, buf + sz + off, datalen - off,
                               state->ctx);
        }
    }

    return err;
}

#undef BLOCK_HDR_FIXED_LEN

#undef FLAG_VAL

int
matroska_contentcompalgo_handler(const char *val, const void *buf, size_t len,
                                 void *ctx)
{
    (void)val;
    (void)buf;
    (void)len;
    (void)ctx;

    return 0;
}

int
matroska_contentcompsettings_handler(const char *val, const void *buf,
                                     size_t len, void *ctx)
{
    (void)val;
    (void)buf;
    (void)len;
    (void)ctx;

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
