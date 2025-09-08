/*
 * matroska.c
 */

#define _FILE_OFFSET_BITS 64

#include "common.h"
#include "debug.h"
#include "ebml.h"
#include "matroska.h"
#include "std_sys.h"
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

#include <sys/types.h>

#define LIST_BLOCK_HDR_FIELDS(X) \
    X(TRACKNO,      8) \
    X(TIMESTAMP,    2) \
    X(FLAGS,        1)

#define X(nm, len) \
enum { \
    BLOCK_HDR_##nm##_LEN = len \
};
LIST_BLOCK_HDR_FIELDS(X)
#undef X

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
    matroska_bitstream_cb_t cb;
    void                    *ctx;
    int                     block_hdr;
    int                     lacing_hdr;
    int                     lacing_type;
#define X(nm, len) + len
    char                    hdr_buf[LIST_BLOCK_HDR_FIELDS(X)];
#undef X
    size_t                  hdr_len;
    size_t                  hdr_sz;
    char                    *lacing_hdr_buf;
    size_t                  lacing_hdr_len;
    size_t                  lacing_hdr_sz;
    size_t                  lacing_nframes;
    size_t                  data_len;
    off_t                   data_off;
    size_t                  ebml_hdr_len;
    size_t                  num_frames;
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

#define MAX_OUTPUT_HDR_LEN 32

#define BLOCK_FLAG_KEYFRAME_IDX 7
#define BLOCK_FLAG_INVISIBLE_IDX 3
#define BLOCK_FLAG_DISCARDABLE_IDX 0

#define BLOCK_FLAG_KEYFRAME (1 << BLOCK_FLAG_KEYFRAME_IDX)
#define BLOCK_FLAG_RESERVED 112
#define BLOCK_FLAG_INVISIBLE (1 << BLOCK_FLAG_INVISIBLE_IDX)
#define BLOCK_FLAG_DISCARDABLE (1 << BLOCK_FLAG_DISCARDABLE_IDX)

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

static int block_output_handler(const char *, enum etype, void **, size_t *,
                                void **, size_t *, size_t, size_t, struct buf *,
                                int64_t, int, void *);
static int block_input_handler(const char *, enum etype, void **, size_t *,
                               void **, size_t *, size_t, size_t, struct buf *,
                               int64_t, int, void *);

static int _matroska_read(FILE *, matroska_hdl_t, int,
                          int (*)(FILE *, ebml_hdl_t, int));

#ifdef DEBUG_OUTPUT
static int
print_handler(FILE *f, const char *func, const char *val)
{
    return fprintf(f, "%s(): %s\n", func, val) < 0 ? -E_IO : 0;
}

#endif

static int
track_data_cmp(const void *k1, const void *k2, void *ctx)
{
    const struct track_data *tdata1 = *(struct track_data *const *)k1;
    const struct track_data *tdata2 = *(struct track_data *const *)k2;

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
            unsigned char val = *bufp;

            framesz += val;
            ++bufp;
            if (val != 255)
                break;
        }

        tdata->frame_sz[i] = framesz;

        debug_printf("Frame size %" PRIu64 " byte%s\n", PL(framesz));

        totframesz += framesz;
    }

    if (totframesz >= totlen) {
        err = ERR_TAG(E_ILSEQ);
        goto err;
    }

    hlen = bufp - state->lacing_hdr_buf;

    tdata->frame_sz[i] = framesz = totlen - hlen - totframesz;
    tdata->frame_idx = 0;
    tdata->num_frames = state->lacing_nframes;

    debug_printf("Frame size %" PRIu64 " byte%s\n", PL(framesz));
    (void)framesz;

    tdata->next_frame_off = 0;

    err = return_track_data(bufp, state->lacing_hdr_len - hlen, totlen - hlen,
                            state->ebml_hdr_len + hlen, state->data_off + hlen,
                            tdata, state);
    if (err)
        goto err;

    free(state->lacing_hdr_buf);
    state->lacing_hdr_buf = NULL;

    *hdrlen = hlen;
    if (offset != NULL) {
        *offset = startoff < state->lacing_hdr_len
                  ? state->lacing_hdr_len - startoff : 0;
    }
    return 1;

err:
    assert(err < 0);
    return err;
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
            goto err1;

        if (i == 0)
            framesz = fsz;
        else {
            delta = fsz + 1 - (1 << (hlen * CHAR_BIT - hlen - 1));
            if (delta < 0 && (uint64_t)-delta > framesz)
                goto err2;
            framesz += delta;
        }

        tdata->frame_sz[i] = framesz;

        debug_printf("Frame size %" PRIu64 " byte%s\n", PL(framesz));

        bufp += hlen;
        totframesz += framesz;
    }

    if (totframesz >= totlen)
        goto err2;

    hlen = bufp - state->lacing_hdr_buf;

    tdata->frame_sz[i] = framesz = totlen - hlen - totframesz;
    tdata->frame_idx = 0;
    tdata->num_frames = state->lacing_nframes;

    debug_printf("Frame size %" PRIu64 " byte%s\n", PL(framesz));
    (void)framesz;

    tdata->next_frame_off = 0;

    err = return_track_data(bufp, state->lacing_hdr_len - hlen, totlen - hlen,
                            state->ebml_hdr_len + hlen, state->data_off + hlen,
                            tdata, state);
    if (err)
        goto err1;

    free(state->lacing_hdr_buf);
    state->lacing_hdr_buf = NULL;

    *hdrlen = hlen;
    if (offset != NULL) {
        *offset = startoff < state->lacing_hdr_len
                  ? state->lacing_hdr_len - startoff : 0;
    }
    return 1;

err2:
    err = ERR_TAG(E_ILSEQ);
err1:
    assert(err < 0);
    return err;
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
        return ERR_TAG(res == 0 ? E_ILSEQ : sys_maperror(-res));

    *tdata = ret;
    return 0;
}

static int
return_track_data(const char *buf, size_t len, size_t totlen, size_t hdrlen,
                  off_t off, struct track_data *tdata,
                  struct matroska_state *state)
{
    const char *dp, *sp;
    int pending_new_frame;
    int res;
    size_t frame_off;
    size_t num_logical_bytes;
    size_t seglen;

    if (len == 0)
        return 0;

    frame_off = tdata->next_frame_off;

    if (tdata->compalg == CONTENT_COMP_ALGO_HEADER_STRIPPING) {
        num_logical_bytes = state->num_frames * tdata->num_stripped_bytes;
        totlen += num_logical_bytes;
    } else
        num_logical_bytes = 0;

    pending_new_frame = 0;

    for (sp = buf;; sp = dp) {
        int new_frame;
        size_t framelen;

        dp = sp + MIN(len, frame_off);

        new_frame = (size_t)(sp - buf) == tdata->next_frame_off;
        framelen = tdata->frame_sz[tdata->frame_idx];

        if (new_frame) {
            if (state->cb.output_cb != NULL) {
                if (tdata->compalg == CONTENT_COMP_ALGO_HEADER_STRIPPING) {
                    res = (*state->cb.output_cb)(state->trackno,
                                                 tdata->stripped_bytes,
                                                 tdata->num_stripped_bytes,
                                                 tdata->num_stripped_bytes
                                                 + framelen,
                                                 totlen, hdrlen,
                                                 num_logical_bytes, off,
                                                 tdata->ts, 1, tdata->keyframe,
                                                 state->ctx);
                    if (res != 0)
                        return res;
                    new_frame = pending_new_frame = 0;
                } else
                    pending_new_frame = 1;
            }
            assert((size_t)tdata->frame_idx < tdata->num_frames);
            tdata->next_frame_off += framelen;
        }

        seglen = dp - sp;

        if (seglen > 0) {
            if (state->cb.output_cb != NULL) {
                res = (*state->cb.output_cb)(state->trackno, sp, seglen,
                                             tdata->num_stripped_bytes
                                             + framelen,
                                             totlen, hdrlen, num_logical_bytes,
                                             off, tdata->ts, pending_new_frame,
                                             tdata->keyframe, state->ctx);
                if (res != 0) {
                    if (res != 1)
                        return res;
                    state->interrupt_read = 1;
                }
                pending_new_frame = 0;
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
block_output_handler(const char *val, enum etype etype, void **outbuf,
                     size_t *outlen, void **bufp, size_t *lenp, size_t totlen,
                     size_t hdrlen, struct buf *bufhdl, int64_t off, int simple,
                     void *ctx)
{
    const void *buf;
    int ret = 0;
    int offset;
    lldiv_t q;
    size_t datalen, sz;
    size_t len;
    struct matroska_state *state;
    struct track_data *tdata;

    (void)outbuf;
    (void)outlen;
    (void)bufhdl;

    if (etype != ETYPE_BINARY)
        return ERR_TAG(E_ILSEQ);

    state = ctx;

    if (val != NULL) {
        if (state->data_len != 0)
            return ERR_TAG(E_IO);
        state->block_hdr = state->lacing_hdr = 0;
        PRINT_HANDLER_INFO(val);
        return 0;
    }

    buf = bufp == NULL ? NULL : *bufp;
    len = lenp == NULL ? 0 : *lenp;

    if (buf == NULL) {
        int interrupt_read;

        if (state->data_len != len) {
            fprintf(stderr, "Block data length mismatch: %zu byte%s vs. %zu "
                            "byte%s\n",
                    PL(state->data_len), PL(len));
            return ERR_TAG(E_IO);
        }
        state->data_len = 0;

        interrupt_read = state->interrupt_read;
        state->interrupt_read = 0;

        debug_printf("End of block (%zu byte%s)\n", PL(len));

        return interrupt_read;
    }

    if (state->block_hdr == 1) {
        if (state->lacing_hdr == 1 || state->cb.output_cb != NULL) {
            ret = get_track_data(state, state->trackno, &tdata);
            if (ret != 0)
                return ret;
        }

        state->data_len += len;

        if (state->lacing_hdr == 1) {
            ret = (state->lacing_type == BLOCK_FLAG_LACING_XIPH
                   ? parse_xiph_lacing_header
                   : parse_ebml_lacing_header)(buf, len,
                                               totlen - state->hdr_len, &hdrlen,
                                               &offset, tdata, state);
            if (ret != 1)
                return ret;

            buf = (const char *)buf + offset;
            len -= offset;

            state->data_off += hdrlen;
            state->hdr_len += hdrlen;
            state->ebml_hdr_len += hdrlen;

            state->lacing_hdr = 2;
        }

        if (state->cb.output_cb != NULL) {
            ret = return_track_data(buf, len, totlen - state->hdr_len,
                                    state->ebml_hdr_len, state->data_off, tdata,
                                    state);
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

        state->ebml_hdr_len = hdrlen + state->hdr_sz;

        state->data_len = state->hdr_sz;
        state->data_off = off + state->hdr_sz;

        state->block_hdr = 2;
    }

    sz = MIN(state->hdr_sz, len);

    if (sz > sizeof(state->hdr_buf) - state->hdr_len)
        return ERR_TAG(E_ILSEQ);

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
            return ERR_TAG(E_ILSEQ);

        timestamp.bytes[0] = state->hdr_buf[datalen+1];
        timestamp.bytes[1] = state->hdr_buf[datalen];

        flags = state->hdr_buf[datalen + BLOCK_HDR_TIMESTAMP_LEN];

        if ((flags & BLOCK_FLAG_RESERVED) != 0)
            return ERR_TAG(E_ILSEQ);

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
                return ERR_TAG(E_ILSEQ);
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
            return ERR_TAG(E_ILSEQ);
        tdata->frame_sz[0] = q.quot;
        tdata->frame_idx = 0;

        debug_printf("%zu laced frames of size %zu byte%s\n", tdata->num_frames,
                     PL(tdata->frame_sz[0]));

        state->num_frames = tdata->num_frames;
        tdata->num_frames = 1;

        offset = 1;
        ++state->data_off;
        ++state->hdr_len;
        ++state->ebml_hdr_len;
        ++sz;

        break;
    case BLOCK_FLAG_LACING_XIPH:
    case BLOCK_FLAG_LACING_EBML:
        offset = 0;

        switch (state->lacing_hdr) {
        case 0:
            state->lacing_nframes = *((unsigned char *)buf + sz) + 1;

            state->lacing_hdr_sz = state->lacing_type == BLOCK_FLAG_LACING_XIPH
                                   ? totlen - 1
                                   : state->lacing_nframes
                                     * ETYPE_MAX_FIXED_WIDTH;
            state->lacing_hdr_buf = malloc(state->lacing_hdr_sz);
            if (state->lacing_hdr_buf == NULL)
                return ERR_TAG(en);
            state->lacing_hdr_len = 0;

            if (tdata->num_frame_sz < state->lacing_nframes) {
                size_t *tmp;
                size_t newsz = 2 * state->lacing_nframes;

                if (oreallocarray(tdata->frame_sz, &tmp, newsz) == NULL)
                    return ERR_TAG(en);
                tdata->frame_sz = tmp;
                tdata->num_frame_sz = newsz;
            }

            offset = 1;
            ++state->data_off;
            ++state->hdr_len;
            ++state->ebml_hdr_len;
            ++sz;

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
            state->data_off += hdrlen;
            state->hdr_len += hdrlen;
            state->ebml_hdr_len += hdrlen;
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
        tdata->num_frames = state->num_frames = 1;
        offset = 0;
        break;
    }

    tdata->next_frame_off = 0;
    state->data_len += datalen;

    return return_track_data((const char *)buf + sz, datalen - offset,
                             totlen - offset, state->ebml_hdr_len,
                             state->data_off, tdata, state);
}

#undef FLAG_VAL

static int
block_input_handler(const char *val, enum etype etype, void **outbuf,
                    size_t *outlen, void **bufp, size_t *lenp, size_t totlen,
                    size_t hdrlen, struct buf *bufhdl, int64_t off, int simple,
                    void *ctx)
{
    char buf[MAX_OUTPUT_HDR_LEN];
    int err;
    int keyframe;
    int resize;
    size_t len;
    ssize_t nbytes;
    struct matroska_state *state = ctx;
    uint64_t trackno;
    union {
        int16_t val;
        char    bytes[2];
    } timestamp;
    void *ret;

    (void)val;
    (void)etype;
    (void)totlen;
    (void)hdrlen;
    (void)bufhdl;
    (void)off;

    if (!simple)
        return ERR_TAG(E_NOSYS);

    err = (*state->cb.input_cb)(&trackno, NULL, &nbytes, NULL, NULL,
                                state->ctx);
    if (err)
        return err;

    if (bufp == NULL) {
        /* track number */
        len = sizeof(buf);
        err = u64_to_vint(trackno, buf, &len);
        if (err)
            return err;

        /* timestamp and flags */
        len += BLOCK_HDR_FIXED_LEN;

        *lenp = len;
        return 0;
    }

    len = nbytes;

    if (*bufp == NULL || len != *lenp) {
        ret = malloc(len);
        if (ret == NULL)
            return MINUS_ERRNO;
        resize = 1;
    } else {
        ret = *bufp;
        resize = 0;
    }

    err = (*state->cb.input_cb)(&trackno, ret, &nbytes, &timestamp.val,
                                &keyframe, state->ctx);
    if (err)
        goto err;
    if ((size_t)nbytes != len) {
        err = -E_IO;
        goto err;
    }

    fprintf(stderr, "Header:\n"
                    "Track number %" PRIu64 "\n"
                    "Timestamp %" PRIi16 "\n"
                    "Keyframe %d\n",
            trackno, timestamp.val, keyframe);

    /* track number */
    len = sizeof(buf);
    err = u64_to_vint(trackno, buf, &len);
    if (err)
        goto err;

    /* timestamp */
    buf[len++] = timestamp.bytes[1];
    buf[len++] = timestamp.bytes[0];

    /* flags */
    buf[len] = keyframe << BLOCK_FLAG_KEYFRAME_IDX;

    err = buf_set_binhdr(bufhdl, buf, len + 1);
    if (err)
        goto err;

/*    err = (*state->iofns.write)(ebml_ctx(state->hdl), buf, len + 1);
    if (err)
        goto err;
*/
    if (resize) {
        free(*bufp);
        *bufp = ret;
        *lenp = nbytes;
    }
    *outbuf = *bufp;
    *outlen = *lenp;
    return 0;

err:
    if (resize)
        free(ret);
    return err;
}

#undef BLOCK_HDR_FIXED_LEN

static int
_matroska_read(FILE *f, matroska_hdl_t hdl, int flags,
               int (*fn)(FILE *, ebml_hdl_t, int))
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

    return (*fn)(f, hdl->hdl, fl);
}

int
matroska_tracknumber_handler(const char *val, enum etype etype, edata_t *edata,
                             void **outbuf, size_t *outlen, void **buf,
                             size_t *len, size_t totlen, size_t hdrlen,
                             struct buf *bufhdl, int64_t off, void *ctx,
                             int encode)
{
    int err;
    struct matroska_state *state = ctx;
    struct track_data *tdata;

    (void)outbuf;
    (void)outlen;
    (void)buf;
    (void)len;
    (void)totlen;
    (void)hdrlen;
    (void)bufhdl;
    (void)off;

    if (encode)
        return 0;

    if (state->track_data == NULL) {
        err = avl_tree_new(&state->track_data, sizeof(struct track_data *),
                           &track_data_cmp, 0, NULL, NULL, NULL);
        if (err)
            return ERR_TAG(sys_maperror(-err));
    }

    if (val == NULL) {
        if (etype != ETYPE_UINTEGER)
            return ERR_TAG(E_ILSEQ);

        if (ocalloc(&tdata, 1) == NULL)
            return ERR_TAG(en);

        tdata->trackno = edata->uinteger;
        tdata->compalg = CONTENT_COMP_ALGO_NONE;

        tdata->num_frame_sz = 8;
        if (oallocarray(&tdata->frame_sz, tdata->num_frame_sz) == NULL) {
            err = ERR_TAG(en);
            goto err;
        }

        err = avl_tree_insert(state->track_data, &tdata);
        if (err) {
            err = ERR_TAG(sys_maperror(-err));
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
                             void **outbuf, size_t *outlen, void **buf,
                             size_t *len, size_t totlen, size_t hdrlen,
                             struct buf *bufhdl, int64_t off, void *ctx,
                             int encode)
{
    (void)edata;

    return (encode ? block_input_handler : block_output_handler)
           (val, etype, outbuf, outlen, buf, len, totlen, hdrlen, bufhdl, off,
            1, ctx);
}

int
matroska_block_handler(const char *val, enum etype etype, edata_t *edata,
                       void **outbuf, void *outlen, void **buf, size_t *len,
                       size_t totlen, size_t hdrlen, struct buf *bufhdl,
                       int64_t off, void *ctx, int encode)
{
    (void)edata;

    return (encode ? block_input_handler : block_output_handler)
           (val, etype, outbuf, outlen, buf, len, totlen, hdrlen, bufhdl, off,
            0, ctx);
}

int
matroska_contentcompalgo_handler(const char *val, enum etype etype,
                                 edata_t *edata, void **outbuf, size_t *outlen,
                                 void **buf, size_t *len, size_t totlen,
                                 size_t hdrlen, struct buf *bufhdl, int64_t off,
                                 void *ctx, int encode)
{
    int err;
    struct matroska_state *state;

    (void)outbuf;
    (void)outlen;
    (void)buf;
    (void)len;
    (void)totlen;
    (void)hdrlen;
    (void)bufhdl;
    (void)off;

    if (encode)
        return 0;

    if (etype != ETYPE_UINTEGER)
        return ERR_TAG(E_ILSEQ);

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
                                     edata_t *edata, void **outbuf,
                                     size_t *outlen, void **buf, size_t *len,
                                     size_t totlen, size_t hdrlen,
                                     struct buf *bufhdl, int64_t off, void *ctx,
                                     int encode)
{
    int err;
    size_t length;
    struct matroska_state *state;
    struct track_data *tdata;

    (void)edata;
    (void)outbuf;
    (void)outlen;
    (void)totlen;
    (void)hdrlen;
    (void)bufhdl;
    (void)off;

    if (encode)
        return 0;

    if (etype != ETYPE_BINARY)
        return ERR_TAG(E_ILSEQ);

    state = ctx;

    err = get_track_data(state, state->trackno, &tdata);
    if (err)
        return err;

    length = len == NULL ? 0 : *len;

    if (buf == NULL) {
        if (tdata->num_stripped_bytes != length)
            return ERR_TAG(E_IO);
        return 0;
    }

    if (val == NULL) {
        size_t num_stripped_bytes;
        void *stripped_bytes;

        num_stripped_bytes = tdata->num_stripped_bytes + length;

        stripped_bytes = realloc(tdata->stripped_bytes, num_stripped_bytes);
        if (stripped_bytes == NULL)
            return ERR_TAG(en);
        memcpy((char *)stripped_bytes + tdata->num_stripped_bytes, *buf,
               length);

        tdata->stripped_bytes = stripped_bytes;
        tdata->num_stripped_bytes = num_stripped_bytes;

        debug_printf("|ContentCompSettings(%" PRIu64 ")| += %zu byte%s\n",
                     state->trackno, PL(length));
    } else
        PRINT_HANDLER_INFO(val);

    return 0;
}

int
matroska_open(matroska_hdl_t *hdl, matroska_io_fns_t *fns,
              matroska_metadata_cb_t *metacb, matroska_bitstream_cb_t *cb,
              int flags, void *args, void *ctx)
{
    const ebml_io_fns_t *ebmlfns;
    int err;
    struct ebml_file_args fileargs;
    struct matroska_state *ret;
    void *argsp;

    if (ocalloc(&ret, 1) == NULL)
        return ERR_TAG(en);

    if (fns == NULL) {
        int fd;
        struct matroska_file_args *fileargsp = args;

        ret->iofns = *EBML_FILE_FNS;
        ebmlfns = EBML_FILE_FNS;

        fd = fileargsp->fd;
        fileargs.fd = fd == MATROSKA_FD_CWD ? EBML_FD_CWD : fd;
        fileargs.pathname = fileargsp->pathname;
        argsp = &fileargs;
    } else {
        ret->iofns.open = fns->open;
        ret->iofns.close = fns->close;
        ret->iofns.read = fns->read;
        ret->iofns.write = fns->write;
        ret->iofns.sync = fns->sync;
        ret->iofns.get_fpos = fns->get_fpos;
        ebmlfns = &ret->iofns;

        argsp = args;
    }

    err = ebml_open(&ret->hdl, ebmlfns, MATROSKA_PARSER,
                    MATROSKA_SEMANTIC_PROCESSOR,
                    metacb == NULL ? NULL : metacb->output_cb,
                    !!(flags & MATROSKA_OPEN_FLAG_RDONLY), argsp, ret, ctx);
    if (err) {
        free(ret);
        return err;
    }

    if (flags & MATROSKA_OPEN_FLAG_RDONLY)
        ret->cb.output_cb = cb == NULL ? NULL : cb->output_cb;
    else
        ret->cb.input_cb = cb == NULL ? NULL : cb->input_cb;
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
    return _matroska_read(f, hdl, flags, &ebml_read);
}

int
matroska_read_header(FILE *f, matroska_hdl_t hdl, int flags)
{
    return _matroska_read(f, hdl, flags, &ebml_read_header);
}

int
matroska_read_body(FILE *f, matroska_hdl_t hdl, int flags)
{
    return _matroska_read(f, hdl, flags, &ebml_read_body);
}

int
matroska_write(matroska_hdl_t hdl, const char *id, matroska_metadata_t *val,
               size_t *len, size_t *hdrlen,
               int (*master_cb)(const char *, size_t, size_t, void *, void *),
               void (*master_free_cb)(void *, void *), void *mdata, void *mctx,
               int flags)
{
    int fl;
    size_t i;

    static const struct ent {
        int src;
        int dst;
    } flagmap[] = {
        {MATROSKA_WRITE_FLAG_HEADER, EBML_WRITE_FLAG_HEADER}
    };

    fl = 0;
    for (i = 0; i < ARRAY_SIZE(flagmap); i++) {
        const struct ent *ent = &flagmap[i];

        if (flags & ent->src)
            fl |= ent->dst;
    }

    return ebml_write(hdl->hdl, id, val, len, hdrlen, master_cb, master_free_cb,
                      mdata, mctx, fl);
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

    return -sys_rmaperror(-info->errcode);
}

int
matroska_print_err(FILE *f, int errdes)
{
    err_print(f, &errdes);
    return errdes < ERRDES_MIN ? -sys_rmaperror(-errdes) : errdes;
}

/* vi: set expandtab sw=4 ts=4: */
