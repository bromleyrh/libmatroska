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

        state->block_hdr = 2;
    }

    sz = MIN(state->hdr_sz, len);

    if (sz > sizeof(state->hdr_buf) - state->hdr_len)
        return -EILSEQ;

    memcpy(state->hdr_buf + state->hdr_len, buf, sz);
    state->hdr_len += sz;
    state->hdr_sz -= sz;

    if (state->hdr_sz == 0) {
        uint64_t trackno;

        err = vint_to_u64(state->hdr_buf, &trackno, &sz);
        if (err)
            return err;
        if (sz != state->hdr_len)
            return -EILSEQ;

        fprintf(stderr, "Track number %" PRIu64 "\n", trackno);

        state->block_hdr = 1;
    }

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
