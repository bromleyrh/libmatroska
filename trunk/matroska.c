/*
 * matroska.c
 */

#define _FILE_OFFSET_BITS 64

#include "common.h"
#include "debug.h"
#include "ebml.h"
#include "matroska.h"
#include "vint.h"

#include <avl_tree.h>
#include <malloc_ext.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys/param.h>
#include <sys/types.h>

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
    CONTENT_COMP_ALGO_HEADER_STRIPPING,
    CONTENT_COMP_ALGO_NONE
};

struct track_data {
    uint64_t                trackno;
    enum content_comp_algo  compalg;
    void                    *stripped_bytes;
    size_t                  num_stripped_bytes;
    size_t                  *frame_sz; /* used when lacing employed */
    ssize_t                 frame_idx;
    size_t                  num_frames;
    size_t                  num_frame_sz;
    size_t                  next_frame_off;
    int16_t                 ts;
    int                     keyframe;
};

struct matroska_state {
    ebml_hdl_t              hdl;
    ebml_io_fns_t           iofns;
    matroska_bitstream_cb_t *cb;
    void                    *ctx;
    int                     block_hdr;
    int                     lacing_hdr;
    int                     lacing_type;
#define _X(nm, len) + len
    char                    hdr_buf[LIST_BLOCK_HDR_FIELDS()];
#undef _X
    size_t                  hdr_len;
    size_t                  hdr_sz;
    char                    *lacing_hdr_buf;
    size_t                  lacing_hdr_len;
    size_t                  lacing_hdr_sz;
    off_t                   lacing_hdr_off;
    size_t                  lacing_nframes;
    size_t                  data_len;
    size_t                  ebml_hdr_len;
    uint64_t                trackno;
    struct avl_tree         *track_data;
    int                     interrupt_read;
};

struct matroska_error_info_debug {
    struct matroska_error_info  super;
    const char                  *file;
    int                         line;
    char                        **bt;
    int                         len;
};

#define MATROSKA_ERROR_FLAG_DEBUG 1

#if 0 && !defined(NDEBUG)
#define DEBUG_OUTPUT
#endif

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
    [CONTENT_COMP_ALGO_HEADER_STRIPPING]    = "header stripping",
    [CONTENT_COMP_ALGO_NONE]                = "none"
};

#ifdef DEBUG_OUTPUT
#define debug_puts(s) fputs(s, stderr)
#define debug_printf(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)
#define PRINT_HANDLER_INFO(val) print_handler(stderr, __func__, val)
#else
#define debug_puts(s) ((void)0)
#define debug_printf(fmt, ...) ((void)0)
#define PRINT_HANDLER_INFO(val) ((void)0)
#endif

#ifdef DEBUG_OUTPUT
static int print_handler(FILE *, const char *, const char *);

#endif
static int track_data_cmp(const void *, const void *, void *);
static int track_data_free(const void *, void *);

static int parse_xiph_lacing_header(const void *, size_t, size_t, size_t *,
                                    int *, struct track_data *,
                                    struct matroska_state *);
static int parse_ebml_lacing_header(const void *, size_t, size_t, size_t *,
                                    int *, struct track_data *,
                                    struct matroska_state *);

static int get_track_data(struct matroska_state *, uint64_t,
                          struct track_data **);

static int return_track_data(const char *, size_t, size_t, size_t, off_t,
                             struct track_data *, struct matroska_state *);

static int block_handler(const char *, enum etype, const void *, size_t, size_t,
                         size_t, off_t, int, void *);

#ifdef DEBUG_OUTPUT
static int
print_handler(FILE *f, const char *func, const char *val)
{
    return fprintf(f, "%s(): %s\n", func, val) < 0 ? -EIO : 0;
}

#endif

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

    free(tdata->frame_sz);
    free(tdata->stripped_bytes);

    free(tdata);

    return 0;
}

static int
parse_xiph_lacing_header(const void *buf, size_t len, size_t totlen,
                         size_t *hdrlen, int *offset, struct track_data *tdata,
                         struct matroska_state *state)
{
    char *bufp;
    int err;
    size_t hlen;
    size_t i;
    size_t startoff;
    uint64_t framesz, totframesz;

    startoff = state->lacing_hdr_len;

    hlen = MIN(len, state->lacing_hdr_sz);

    memcpy(state->lacing_hdr_buf + state->lacing_hdr_len, buf, hlen);

    state->lacing_hdr_len += hlen;
    state->lacing_hdr_sz -= hlen;
    if (state->lacing_hdr_sz > 0)
        return 0;

    bufp = state->lacing_hdr_buf;
    totframesz = 0;
    for (i = 0; i < state->lacing_nframes - 1; i++) {
        framesz = 0;
        for (;;) {
            unsigned char val = (unsigned char)*bufp;

            framesz += val;
            ++bufp;
            if (val != 255)
                break;
        }

        tdata->frame_sz[i] = framesz;

        debug_printf("Frame size %" PRIu64 " byte%s\n", PL(framesz));

        totframesz += framesz;
    }

    if (totframesz >= totlen)
        return ERR_TAG(EILSEQ);

    hlen = bufp - state->lacing_hdr_buf;

    tdata->frame_sz[i] = framesz = totlen - hlen - totframesz;
    tdata->frame_idx = 0;
    tdata->num_frames = state->lacing_nframes;

    debug_printf("Frame size %" PRIu64 " byte%s\n", PL(framesz));

    tdata->next_frame_off = 0;

    err = return_track_data(bufp, state->lacing_hdr_len - hlen, totlen - hlen,
                            state->ebml_hdr_len, state->lacing_hdr_off + hlen,
                            tdata, state);
    if (err)
        return err;

    free(state->lacing_hdr_buf);
    state->lacing_hdr_buf = NULL;

    *hdrlen = hlen;
    if (offset != NULL) {
        *offset = startoff < state->lacing_hdr_len
                  ? state->lacing_hdr_len - startoff : 0;
    }
    return 1;
}

static int
parse_ebml_lacing_header(const void *buf, size_t len, size_t totlen,
                         size_t *hdrlen, int *offset, struct track_data *tdata,
                         struct matroska_state *state)
{
    char *bufp;
    int err;
    size_t hlen;
    size_t i;
    size_t startoff;
    uint64_t framesz, totframesz;

    startoff = state->lacing_hdr_len;

    hlen = MIN(len, state->lacing_hdr_sz);

    memcpy(state->lacing_hdr_buf + state->lacing_hdr_len, buf, hlen);

    state->lacing_hdr_len += hlen;
    state->lacing_hdr_sz -= hlen;
    if (state->lacing_hdr_sz > 0)
        return 0;

    bufp = state->lacing_hdr_buf;
    framesz = totframesz = 0;
    for (i = 0; i < state->lacing_nframes - 1; i++) {
        int64_t delta;
        uint64_t fsz;

        err = vint_to_u64(bufp, &fsz, &hlen);
        if (err)
            return err;

        if (i == 0)
            framesz = fsz;
        else {
            delta = fsz + 1 - (1 << (hlen * CHAR_BIT - hlen - 1));
            if (delta < 0 && (uint64_t)-delta > framesz)
                return ERR_TAG(EILSEQ);
            framesz += delta;
        }

        tdata->frame_sz[i] = framesz;

        debug_printf("Frame size %" PRIu64 " byte%s\n", PL(framesz));

        bufp += hlen;
        totframesz += framesz;
    }

    if (totframesz >= totlen)
        return ERR_TAG(EILSEQ);

    hlen = bufp - state->lacing_hdr_buf;

    tdata->frame_sz[i] = framesz = totlen - hlen - totframesz;
    tdata->frame_idx = 0;
    tdata->num_frames = state->lacing_nframes;

    debug_printf("Frame size %" PRIu64 " byte%s\n", PL(framesz));

    tdata->next_frame_off = 0;

    err = return_track_data(bufp, state->lacing_hdr_len - hlen, totlen - hlen,
                            state->ebml_hdr_len, state->lacing_hdr_off + hlen,
                            tdata, state);
    if (err)
        return err;

    free(state->lacing_hdr_buf);
    state->lacing_hdr_buf = NULL;

    *hdrlen = hlen;
    if (offset != NULL) {
        *offset = startoff < state->lacing_hdr_len
                  ? state->lacing_hdr_len - startoff : 0;
    }
    return 1;
}

static int
get_track_data(struct matroska_state *state, uint64_t trackno,
               struct track_data **tdata)
{
    int res;
    struct track_data k, *ret;

    k.trackno = trackno;

    ret = &k;
    res = avl_tree_search(state->track_data, &ret, &ret);
    if (res != 1)
        return ERR_TAG(res == 0 ? EILSEQ : -res);

    *tdata = ret;
    return 0;
}

static int
return_track_data(const char *buf, size_t len, size_t totlen, size_t hdrlen,
                  off_t off, struct track_data *tdata,
                  struct matroska_state *state)
{
    const char *dp, *sp;
    int res;
    size_t frame_off;
    size_t seglen;

    if (len == 0)
        return 0;

    frame_off = tdata->next_frame_off;

    for (sp = buf;; sp = dp) {
        dp = sp + MIN(len, frame_off);

        if ((size_t)(sp - buf) == tdata->next_frame_off) {
            if (state->cb != NULL
                && tdata->compalg == CONTENT_COMP_ALGO_HEADER_STRIPPING) {
                res = (*state->cb)(state->trackno, tdata->stripped_bytes,
                                   tdata->num_stripped_bytes, totlen, hdrlen,
                                   off, tdata->ts, tdata->keyframe, state->ctx);
                if (res != 0)
                    return res;
            }
            assert((size_t)tdata->frame_idx < tdata->num_frames);
            tdata->next_frame_off += tdata->frame_sz[tdata->frame_idx];
        }

        seglen = dp - sp;

        if (seglen > 0) {
            if (state->cb != NULL) {
                res = (*state->cb)(state->trackno, sp, seglen, totlen, hdrlen,
                                   off, tdata->ts, tdata->keyframe, state->ctx);
                if (res != 0) {
                    if (res != 1)
                        return res;
                    state->interrupt_read = 1;
                }
            }

            len -= seglen;
            if (tdata->num_frames > 1
                && (size_t)(dp - buf) == tdata->next_frame_off)
                ++tdata->frame_idx;
        }

        if (len == 0)
            break;

        assert((size_t)tdata->frame_idx < tdata->num_frames);
        frame_off = tdata->frame_sz[tdata->frame_idx];
    }

    tdata->next_frame_off = frame_off - seglen;

    return 0;
}

#define BLOCK_HDR_FIXED_LEN (BLOCK_HDR_TIMESTAMP_LEN + BLOCK_HDR_FLAGS_LEN)

#define FLAG_VAL(flags, which) (!!((flags) & BLOCK_FLAG_##which))

static int
block_handler(const char *val, enum etype etype, const void *buf, size_t len,
              size_t totlen, size_t hdrlen, off_t off, int simple, void *ctx)
{
    int ret = 0;
    int offset;
    lldiv_t q;
    size_t datalen, sz;
    struct matroska_state *state;
    struct track_data *tdata;

    if (etype != ETYPE_BINARY)
        return ERR_TAG(EILSEQ);

    state = ctx;

    if (val != NULL) {
        if (state->data_len != 0)
            return ERR_TAG(EIO);
        state->block_hdr = state->lacing_hdr = 0;
        PRINT_HANDLER_INFO(val);
        return 0;
    }

    if (buf == NULL) {
        int interrupt_read;

        if (state->data_len != len) {
            fprintf(stderr, "Block data length mismatch: %zu byte%s vs. %zu "
                            "byte%s\n",
                    PL(state->data_len), PL(len));
            return ERR_TAG(EIO);
        }
        state->data_len = 0;

        interrupt_read = state->interrupt_read;
        state->interrupt_read = 0;

        debug_printf("End of block (%zu byte%s)\n", PL(len));

        return interrupt_read;
    }

    if (state->block_hdr == 1) {
        if (state->lacing_hdr == 1 || state->cb != NULL) {
            ret = get_track_data(state, state->trackno, &tdata);
            if (ret != 0)
                return ret;
        }

        state->data_len += len;

        if (state->lacing_hdr == 1) {
            ret = (state->lacing_type == BLOCK_FLAG_LACING_XIPH
                   ? parse_xiph_lacing_header
                   : parse_ebml_lacing_header)(buf, len,
                                               totlen - state->hdr_len - 1,
                                               &hdrlen, &offset, tdata, state);
            if (ret != 1)
                return ret;

            buf = (const char *)buf + offset;
            len -= offset;

            state->lacing_hdr = 2;
        }

        if (state->cb != NULL) {
            ret = return_track_data(buf, len, totlen - state->hdr_len,
                                    state->ebml_hdr_len, off, tdata, state);
            if (ret != 0)
                return ret;
        }
        debug_puts("...\n");
        return 0;
    }

    if (state->block_hdr == 0) {
        ret = vint_to_u64(buf, NULL, &state->hdr_sz);
        if (ret != 0)
            return ret;
        state->hdr_len = 0;
        state->hdr_sz += BLOCK_HDR_FIXED_LEN;

        state->data_len = state->hdr_sz;

        state->ebml_hdr_len = hdrlen + state->hdr_sz;

        state->block_hdr = 2;
    }

    sz = MIN(state->hdr_sz, len);

    if (sz > sizeof(state->hdr_buf) - state->hdr_len)
        return ERR_TAG(EILSEQ);

    if (sz > 0) {
        memcpy(state->hdr_buf + state->hdr_len, buf, sz);
        state->hdr_len += sz;
        state->hdr_sz -= sz;
    }

    if (state->hdr_sz == 0) {
        int discardable;
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

        ret = vint_to_u64(state->hdr_buf, &state->trackno, &datalen);
        if (ret != 0)
            return ret;
        if (datalen != state->hdr_len - BLOCK_HDR_FIXED_LEN)
            return ERR_TAG(EILSEQ);

        timestamp.bytes[0] = state->hdr_buf[datalen+1];
        timestamp.bytes[1] = state->hdr_buf[datalen];

        flags = state->hdr_buf[datalen + BLOCK_HDR_TIMESTAMP_LEN];

        if ((flags & BLOCK_FLAG_RESERVED) != 0)
            return ERR_TAG(EILSEQ);

        state->lacing_type = flags & BLOCK_FLAG_LACING_MASK;

        ret = get_track_data(state, state->trackno, &tdata);
        if (ret != 0)
            return ret;

        tdata->ts = timestamp.val;
        tdata->keyframe = FLAG_VAL(flags, KEYFRAME);

        if (simple)
            discardable = FLAG_VAL(flags, DISCARDABLE);
        else {
            if (tdata->keyframe != 0)
                return ERR_TAG(EILSEQ);
            discardable = -1;
        }

        debug_printf("Track number %" PRIu64 "\n"
                     "Timestamp %" PRIi16 "\n"
                     "Flags %" PRIu8 "\n"
                     "Keyframe %d\n"
                     "Invisible %d\n"
                     "Discardable %d\n"
                     "Lacing type %s\n"
                     "Content compression algorithm %s\n",
                     tdata->trackno, tdata->ts, flags,
                     tdata->keyframe,
                     FLAG_VAL(flags, INVISIBLE),
                     discardable,
                     lacing_typemap[state->lacing_type],
                     compalg_typemap[tdata->compalg]);

        (void)discardable;
        (void)lacing_typemap;
        (void)compalg_typemap;

        state->block_hdr = 1;
    } else {
        ret = get_track_data(state, state->trackno, &tdata);
        if (ret != 0)
            return ret;
    }

    totlen -= state->hdr_len;

    debug_printf("Total block data length %zu byte%s\n", PL(totlen));

    datalen = len - sz;
    if (datalen == 0)
        return 0;

    switch (state->lacing_type) {
    case BLOCK_FLAG_LACING_FIXED_SIZE:
        tdata->num_frames = *((unsigned char *)buf + sz) + 1;

        q = lldiv(totlen - 1, tdata->num_frames);
        if (q.rem != 0)
            return ERR_TAG(EILSEQ);
        tdata->frame_sz[0] = q.quot;
        tdata->frame_idx = 0;

        debug_printf("%zu laced frames of size %zu byte%s\n", tdata->num_frames,
                     PL(tdata->frame_sz[0]));

        tdata->num_frames = 1;

        offset = 1;
        ++sz;

        break;
    case BLOCK_FLAG_LACING_XIPH:
    case BLOCK_FLAG_LACING_EBML:
        offset = 0;

        switch (state->lacing_hdr) {
        case 0:
            state->lacing_nframes = *((unsigned char *)buf + sz) + 1;

            state->lacing_hdr_sz = state->lacing_type == BLOCK_FLAG_LACING_XIPH
                                   ? totlen
                                   : state->lacing_nframes
                                     * ETYPE_MAX_FIXED_WIDTH;
            state->lacing_hdr_buf = malloc(state->lacing_hdr_sz);
            if (state->lacing_hdr_buf == NULL)
                return ERR_TAG(errno);
            state->lacing_hdr_len = 0;

            if (tdata->num_frame_sz < state->lacing_nframes) {
                size_t *tmp;
                size_t newsz = 2 * state->lacing_nframes;

                if (oreallocarray(tdata->frame_sz, &tmp, newsz) == NULL)
                    return ERR_TAG(errno);
                tdata->frame_sz = tmp;
                tdata->num_frame_sz = newsz;
            }

            offset = 1;
            ++sz;

            state->lacing_hdr_off = off + sz;

            state->lacing_hdr = 1;
            /* fallthrough */
        case 1:
            hdrlen = 0;
            ret = (state->lacing_type == BLOCK_FLAG_LACING_XIPH
                   ? parse_xiph_lacing_header
                   : parse_ebml_lacing_header)((const char *)buf + sz,
                                               datalen - offset,
                                               totlen - offset, &hdrlen, NULL,
                                               tdata, state);
            if (ret != 1) {
                if (ret == 0)
                    state->data_len += datalen;
                return ret;
            }

            state->lacing_hdr = 2;

            offset += hdrlen;
            /* fallthrough */
        case 2:
            break;
        default:
            abort();
        }

        return 0;
    default:
        tdata->frame_sz[0] = totlen;
        tdata->frame_idx = 0;
        tdata->num_frames = 1;
        offset = 0;
        break;
    }

    tdata->next_frame_off = 0;
    state->data_len += datalen;

    return return_track_data((const char *)buf + sz, datalen - offset,
                             totlen - offset, state->ebml_hdr_len + offset,
                             off + sz, tdata, state);
}

#undef BLOCK_HDR_FIXED_LEN

#undef FLAG_VAL

int
matroska_tracknumber_handler(const char *val, enum etype etype, edata_t *edata,
                             const void *buf, size_t len, size_t totlen,
                             size_t hdrlen, off_t off, void *ctx)
{
    int err;
    struct matroska_state *state = ctx;
    struct track_data *tdata;

    (void)buf;
    (void)len;
    (void)totlen;
    (void)hdrlen;
    (void)off;

    if (state->track_data == NULL) {
        err = avl_tree_new(&state->track_data, sizeof(struct track_data *),
                           &track_data_cmp, 0, NULL, NULL, NULL);
        if (err)
            return ERR_TAG(-err);
    }

    if (val == NULL) {
        if (etype != ETYPE_UINTEGER)
            return ERR_TAG(EILSEQ);

        if (ocalloc(&tdata, 1) == NULL)
            return ERR_TAG(errno);

        tdata->trackno = edata->uinteger;
        tdata->compalg = CONTENT_COMP_ALGO_NONE;

        tdata->num_frame_sz = 8;
        if (oallocarray(&tdata->frame_sz, tdata->num_frame_sz) == NULL) {
            err = ERR_TAG(errno);
            goto err;
        }

        err = avl_tree_insert(state->track_data, &tdata);
        if (err) {
            err = ERR_TAG(-err);
            free(tdata->frame_sz);
            goto err;
        }

        debug_printf("Track number %" PRIu64 "\n", tdata->trackno);

        state->trackno = tdata->trackno;
    } else
        PRINT_HANDLER_INFO(val);

    return 0;

err:
    free(tdata);
    return err;
}

int
matroska_simpleblock_handler(const char *val, enum etype etype, edata_t *edata,
                             const void *buf, size_t len, size_t totlen,
                             size_t hdrlen, off_t off, void *ctx)
{
    (void)edata;

    return block_handler(val, etype, buf, len, totlen, hdrlen, off, 1, ctx);
}

int
matroska_block_handler(const char *val, enum etype etype, edata_t *edata,
                       const void *buf, size_t len, size_t totlen,
                       size_t hdrlen, off_t off, void *ctx)
{
    (void)edata;

    return block_handler(val, etype, buf, len, totlen, hdrlen, off, 0, ctx);
}

int
matroska_contentcompalgo_handler(const char *val, enum etype etype,
                                 edata_t *edata, const void *buf, size_t len,
                                 size_t totlen, size_t hdrlen, off_t off,
                                 void *ctx)
{
    int err;
    struct matroska_state *state;

    (void)buf;
    (void)len;
    (void)totlen;
    (void)hdrlen;
    (void)off;

    if (etype != ETYPE_UINTEGER)
        return ERR_TAG(EILSEQ);

    if (val == NULL) {
        struct track_data *tdata;

        state = ctx;

        err = get_track_data(state, state->trackno, &tdata);
        if (err)
            return err;

        tdata->compalg = edata->uinteger;

        debug_printf("ContentCompAlgo(%" PRIu64 ") = %s\n",
                     state->trackno, compalg_typemap[tdata->compalg]);

        (void)compalg_typemap;
    } else
        PRINT_HANDLER_INFO(val);

    return 0;
}

int
matroska_contentcompsettings_handler(const char *val, enum etype etype,
                                     edata_t *edata, const void *buf,
                                     size_t len, size_t totlen, size_t hdrlen,
                                     off_t off, void *ctx)
{
    int err;
    struct matroska_state *state;
    struct track_data *tdata;

    (void)edata;
    (void)totlen;
    (void)hdrlen;
    (void)off;

    if (etype != ETYPE_BINARY)
        return ERR_TAG(EILSEQ);

    state = ctx;

    err = get_track_data(state, state->trackno, &tdata);
    if (err)
        return err;

    if (buf == NULL) {
        if (tdata->num_stripped_bytes != len)
            return ERR_TAG(EIO);
        return 0;
    }

    if (val == NULL) {
        size_t num_stripped_bytes;
        void *stripped_bytes;

        num_stripped_bytes = tdata->num_stripped_bytes + len;

        stripped_bytes = realloc(tdata->stripped_bytes, num_stripped_bytes);
        if (stripped_bytes == NULL)
            return ERR_TAG(errno);
        memcpy((char *)stripped_bytes + tdata->num_stripped_bytes, buf, len);

        tdata->stripped_bytes = stripped_bytes;
        tdata->num_stripped_bytes = num_stripped_bytes;

        debug_printf("|ContentCompSettings(%" PRIu64 ")| += %zu byte%s\n",
                     state->trackno, PL(len));
    } else
        PRINT_HANDLER_INFO(val);

    return 0;
}

int
matroska_open(matroska_hdl_t *hdl, matroska_io_fns_t *fns,
              matroska_metadata_cb_t *metacb, matroska_bitstream_cb_t *cb,
              void *args, void *ctx)
{
    const ebml_io_fns_t *ebmlfns;
    int err;
    struct ebml_file_args fileargs;
    struct matroska_state *ret;
    void *argsp;

    if (ocalloc(&ret, 1) == NULL)
        return ERR_TAG(errno);

    if (fns == NULL) {
        struct matroska_file_args *fileargsp = args;

        ebmlfns = EBML_FILE_FNS;

        fileargs.fd = fileargsp->fd;
        fileargs.pathname = fileargsp->pathname;
        argsp = &fileargs;
    } else {
        ret->iofns.open = fns->open;
        ret->iofns.close = fns->close;
        ret->iofns.read = fns->read;
        ret->iofns.get_fpos = fns->get_fpos;
        ebmlfns = &ret->iofns;

        argsp = args;
    }

    err = ebml_open(&ret->hdl, ebmlfns, MATROSKA_PARSER,
                    MATROSKA_SEMANTIC_PROCESSOR, metacb, argsp, ret, ctx);
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

    free(hdl->lacing_hdr_buf);

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
matroska_read(FILE *f, matroska_hdl_t hdl, int flags)
{
    int fl;
    size_t i;

    static const struct ent {
        int src;
        int dst;
    } flagmap[] = {
        {MATROSKA_READ_FLAG_HEADER, EBML_READ_FLAG_HEADER},
        {MATROSKA_READ_FLAG_MASTER, EBML_READ_FLAG_MASTER}
    };

    fl = 0;
    for (i = 0; i < ARRAY_SIZE(flagmap); i++) {
        const struct ent *ent = &flagmap[i];

        if (flags & ent->src)
            fl |= ent->dst;
    }

    return ebml_read(f, hdl->hdl, fl);
}

int
matroska_read_header(FILE *f, matroska_hdl_t hdl)
{
    return ebml_read_header(f, hdl->hdl, 0);
}

int
matroska_read_body(FILE *f, matroska_hdl_t hdl)
{
    return ebml_read_body(f, hdl->hdl, 0);
}

int
matroska_error(struct matroska_error_info *info, int errdes, int flags)
{
    int freeall;
    struct err_info_bt *inf;

    inf = err_get_bt(&errdes);
    if (inf == NULL)
        return errdes;

    info->errcode = errdes;

    if (flags & MATROSKA_ERROR_FLAG_DEBUG) {
        struct matroska_error_info_debug *info_debug;

        info_debug = (struct matroska_error_info_debug *)info;

        info_debug->file = inf->file;
        info_debug->line = inf->line;
        info_debug->bt = inf->bt;
        info_debug->len = inf->len;

        freeall = 0;
    } else
        freeall = 1;

    err_info_free(inf, freeall);

    return info->errcode;
}

int
matroska_print_err(FILE *f, int errdes)
{
    err_print(f, &errdes);
    return errdes;
}

/* vi: set expandtab sw=4 ts=4: */
