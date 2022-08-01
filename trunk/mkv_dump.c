/*
 * mkv_dump.c
 */

#include "ebml.h"
#include "parser.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int dump_mkv(int, int);

static int
dump_mkv(int infd, int outfd)
{
    const char *errmsg;
    ebml_hdl_t hdl;
    FILE *f;
    int err;
    struct ebml_file_args args;

    args.fd = infd;
    args.pathname = NULL;
    err = ebml_open(&hdl, EBML_FILE_FNS, &matroska_parser, &args);
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

    err = ebml_dump(f, hdl);
    if (err) {
        errmsg = "Error dumping file";
        goto err3;
    }

    if (fclose(f) == EOF) {
        err = -errno;
        errmsg = "Error closing output file";
        goto err2;
    }

    err = ebml_close(hdl);
    if (err) {
        errmsg = "Error closing input file";
        goto err1;
    }

    return 0;

err3:
    fclose(f);
err2:
    ebml_close(hdl);
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
