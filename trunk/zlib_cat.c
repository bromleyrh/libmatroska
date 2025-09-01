/*
 * zlib_cat.c
 */

#define _FILE_OFFSET_BITS 64

#include "common.h"
#include "debug.h"
#include "std_sys.h"
#include "zlib_stream.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int err_print(FILE *, int *);

static int print_err(FILE *, int);

static int zlib_stream_cb(const void *, size_t, void *);

static int
print_err(FILE *f, int errdes)
{
    err_print(f, &errdes);
    return errdes;
}

static int
zlib_stream_cb(const void *buf, size_t len, void *ctx)
{
    FILE *f = *(FILE **)ctx;

    return fwrite(buf, 1, len, f) == len ? 0 : MINUS_ERRNO;
}

int
main(int argc, char **argv)
{
    FILE *f;
    int res;
    off_t off;
    size_t ret;
    zlib_stream_hdl_t hdl;

    (void)argc;
    (void)argv;

    f = stdout;

    res = zlib_stream_init(&hdl, &zlib_stream_cb, &f);
    if (res != 0) {
        if (res > 0)
            res = print_err(stderr, res);
        fprintf(stderr, "Error initializing output: %s\n", sys_strerror(-res));
        return EXIT_FAILURE;
    }

    for (off = 0;; off += ret) {
        char buf[4096];
        size_t remlen;

        ret = fread(buf, 1, sizeof(buf), stdin);
        if (ret == 0) {
            if (!feof(stdin)) {
                fprintf(stderr, "Error reading input: %s\n", strerror(errno));
                goto err;
            }
            break;
        }

        for (;;) {
            res = zlib_stream_inflate(hdl, buf, ret, &remlen);
            if (res == 0)
                break;
            if (res != 1) {
                if (res > 0)
                    res = print_err(stderr, res);
                fprintf(stderr, "Error decompressing input: %s\n",
                        sys_strerror(-res));
                goto err;
            }

            fprintf(stderr, "End of stream, %zu bytes remaining\n", remlen);

            zlib_stream_destroy(hdl);

            res = zlib_stream_init(&hdl, &zlib_stream_cb, &f);
            if (res != 0) {
                if (res > 0)
                    res = print_err(stderr, res);
                fprintf(stderr, "Error initializing output: %s\n",
                        sys_strerror(-res));
                return EXIT_FAILURE;
            }

            if (remlen == 0)
                break;

            memmove(buf, buf + ret - remlen, remlen);
            ret = remlen;
        }

        fprintf(stderr, "Offset %lld bytes\n", off);
    }

    zlib_stream_destroy(hdl);

    return EXIT_SUCCESS;

err:
    zlib_stream_destroy(hdl);
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
