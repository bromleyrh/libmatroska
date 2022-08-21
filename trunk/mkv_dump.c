/*
 * mkv_dump.c
 */

#include "ebml.h"
#include "matroska.h"
#include "parser.h"

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static matroska_bitstream_cb_t bitstream_cb;

static int dump_mkv(int, int);

static int
bitstream_cb(uint64_t trackno, const void *buf, size_t len, void *ctx)
{
    (void)buf;
    (void)ctx;

    fprintf(stderr, "%s(): %" PRIu64 ": length %zu bytes\n", __FUNCTION__,
            trackno, len);

    return 0;
}

static int
dump_mkv(int infd, int outfd)
{
    const char *errmsg;
    FILE *f;
    int err;
    matroska_hdl_t hdl;

    err = matroska_open(&hdl, infd, NULL, &bitstream_cb, NULL);
    if (err) {
        errmsg = "Error opening input file";
        goto err1;
    }

    f = fdopen(outfd, "w");
    if (f == NULL) {
        err = -errno;
        errmsg = "Error opening output file";
        goto err2;
    }
    setlinebuf(f);

    err = matroska_read(f, hdl);
    if (err) {
        errmsg = "Error dumping file";
        goto err3;
    }

    if (fclose(f) == EOF) {
        err = -errno;
        errmsg = "Error closing output file";
        goto err2;
    }

    err = matroska_close(hdl);
    if (err) {
        errmsg = "Error closing input file";
        goto err1;
    }

    return 0;

err3:
    fclose(f);
err2:
    matroska_close(hdl);
err1:
    fprintf(stderr, "%s: %s\n", errmsg, strerror(-err));
    return err;
}

int
main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    return dump_mkv(STDIN_FILENO, STDOUT_FILENO) == 0
           ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
