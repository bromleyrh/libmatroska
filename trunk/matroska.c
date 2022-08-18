/*
 * matroska.c
 */

#include "matroska.h"
#include "vint.h"

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/param.h>

#define BLOCK_FLAG_KEYFRAME 1
#define BLOCK_FLAG_INVISIBLE 16
#define BLOCK_FLAG_DISCARDABLE 128

#define BLOCK_FLAG_LACING_SHIFT 5
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
    int err;
    size_t sz;
    struct matroska_state *state = ctx;

    if (val != NULL) {
        state->block_hdr = 0;
        fprintf(stderr, "%s(): %s\n", __FUNCTION__, val);
        return 0;
    }

    if (state->block_hdr == 1) {
        fputs("...\n", stderr);
        return 0;
    }

    if (state->block_hdr == 0) {
        err = vint_to_u64(buf, NULL, &state->hdr_sz);
        if (err)
            return err;
        state->hdr_len = 0;
        state->hdr_sz += BLOCK_HDR_FIXED_LEN;

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
        uint64_t trackno;
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

        err = vint_to_u64(state->hdr_buf, &trackno, &sz);
        if (err)
            return err;
        if (sz != state->hdr_len - BLOCK_HDR_FIXED_LEN)
            return -EILSEQ;

        timestamp.bytes[0] = state->hdr_buf[sz+1];
        timestamp.bytes[1] = state->hdr_buf[sz];

        flags = state->hdr_buf[sz + BLOCK_HDR_TIMESTAMP_LEN];

        fprintf(stderr, "Track number %" PRIu64 "\n"
                        "Timestamp %" PRIi16 "\n"
                        "Flags %" PRIu8 "\n"
                        "Keyframe %d\n"
                        "Invisible %d\n"
                        "Discardable %d\n"
                        "Lacing type %s\n",
                trackno, timestamp.val, flags,
                FLAG_VAL(flags, KEYFRAME),
                FLAG_VAL(flags, INVISIBLE),
                FLAG_VAL(flags, DISCARDABLE),
                lacing_typemap[(flags & BLOCK_FLAG_LACING_MASK)
                               >> BLOCK_FLAG_LACING_SHIFT]);

        state->block_hdr = 1;
    }

    return 0;
}

#undef BLOCK_HDR_FIXED_LEN

#undef FLAG_VAL

/* vi: set expandtab sw=4 ts=4: */
