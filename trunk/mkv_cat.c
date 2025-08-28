/*
 * mkv_cat.c
 */

#define _FILE_OFFSET_BITS 64

#include "common.h"
#include "ebml.h"
#include "matroska.h"
#include "parser.h"

#include <avl_tree.h>
#include <malloc_ext.h>
#include <strings_ext.h>

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>

struct track_cb {
    uint64_t    trackno;
    char        *path;
    int         fd;
    FILE        *f;
};

struct ctx {
    struct avl_tree *tcb;
    uint64_t        n;
    size_t          datalen;
};

int matroska_print_err(FILE *, int);

static int parse_track_spec(const char *, const char *, int, struct avl_tree *);

static int parse_cmdline(int, char **, struct ctx *);

static int syncfd(int);

static int track_cb_cmp(const void *, const void *, void *);
static int track_cb_free(const void *, void *);

static int free_tcb(struct avl_tree *);

static matroska_bitstream_output_cb_t bitstream_cb;

static int cvt_mkv(int, struct ctx *);

static int
parse_track_spec(const char *trackno, const char *path, int fd,
                 struct avl_tree *tcb)
{
    int err;
    struct track_cb e;

    if (path == NULL) {
        e.path = NULL;
        e.fd = fd;

        e.f = fdopen(e.fd, "w");
    } else {
        e.path = strdup(path);
        if (e.path == NULL)
            return MINUS_CERRNO;
        e.fd = -1;

        e.f = fopen(e.path, "w");
    }
    if (e.f == NULL) {
        err = MINUS_CERRNO;
        fprintf(stderr, "Error opening output file: %s\n", strerror(-err));
        goto err1;
    }

    e.trackno = strtoumax(trackno, NULL, 10);

    err = avl_tree_insert(tcb, &e);
    if (err)
        goto err2;

    return 0;

err2:
    fclose(e.f);
err1:
    free(e.path);
    return err;
}

static int
parse_cmdline(int argc, char **argv, struct ctx *ctx)
{
    int err;
    int i;
    struct avl_tree *trackcb;

    err = avl_tree_new(&trackcb, sizeof(struct track_cb), &track_cb_cmp, 0,
                       NULL, NULL, NULL);
    if (err)
        return err;

    for (i = 1; i < argc; i++) {
        char *sep;
        int fd;

        sep = argv[i] + strcspn(argv[i], "#:");
        if (*sep == '\0')
            return -EINVAL;
        fd = *sep == '#';
        *sep++ = '\0';

        if (fd) {
            fd = strtoimax(sep, NULL, 10);
            sep = NULL;
        } else
            fd = -1;

        err = parse_track_spec(argv[i], sep, fd, trackcb);
        if (err)
            goto err;
    }

    ctx->tcb = trackcb;
    return 0;

err:
    free_tcb(trackcb);
    return err;
}

static int
syncfd(int fd)
{
    while (fsync(fd) == -1) {
        if (errno != EINTR) {
            if (errno != EBADF && errno != EINVAL && errno != ENOTSUP)
                return MINUS_CERRNO;
            break;
        }
    }

    return 0;
}

static int
track_cb_cmp(const void *k1, const void *k2, void *ctx)
{
    const struct track_cb *tcb1 = k1;
    const struct track_cb *tcb2 = k2;

    (void)ctx;

    return (tcb1->trackno > tcb2->trackno) - (tcb1->trackno < tcb2->trackno);
}

static int
track_cb_free(const void *keyval, void *ctx)
{
    const struct track_cb *tcb = keyval;
    int err = 0;

    err = syncfd(fileno(tcb->f));

    if (fclose(tcb->f) == EOF)
        err = MINUS_CERRNO;

    if (err) {
        fprintf(stderr, "Error closing output file: %s\n", strerror(-err));
        *(int *)ctx = err;
    }

    free(tcb->path);

    return 0;
}

static int
free_tcb(struct avl_tree *tcb)
{
    avl_tree_walk_ctx_t wctx = NULL;
    int err = 0;

    avl_tree_walk(tcb, NULL, &track_cb_free, &err, &wctx);
    avl_tree_free(tcb);

    return err;
}

static int
bitstream_cb(uint64_t trackno, const void *buf, size_t len, size_t framelen,
             size_t totlen, size_t hdrlen, size_t num_logical_bytes, off_t off,
             int16_t ts, int new_frame, int keyframe, void *ctx)
{
    int res;
    struct ctx *ctxp = ctx;
    struct track_cb e;

    (void)framelen;
    (void)totlen;
    (void)hdrlen;
    (void)num_logical_bytes;
    (void)off;
    (void)ts;
    (void)new_frame;
    (void)keyframe;

    fprintf(stderr, "%" PRIu64 ": length %zu byte%s", trackno, PL(len));

    e.trackno = trackno;
    res = avl_tree_search(ctxp->tcb, &e, &e);
    if (res != 0) {
        char tmp[16];
        size_t ret;

        if (res != 1)
            return res;

        fprintf(stderr, " (>%s)",
                e.path == NULL ? itoa(e.fd, tmp, 10) : e.path);

        ret = fwrite(buf, 1, len, e.f);
        if (ret != len) {
            res = MINUS_CERRNO;
            fprintf(stderr, "Error writing to output file: %s\n",
                    strerror(-res));
            return res;
        }
    }

    fputc('\n', stderr);

    return 0;
}

static int
cvt_mkv(int infd, struct ctx *ctx)
{
    const char *errmsg;
    int res;
    matroska_bitstream_cb_t cb;
    matroska_hdl_t hdl;
    struct matroska_file_args args;

    cb.output_cb = &bitstream_cb;
    args.fd = infd;
    args.pathname = NULL;
    res = matroska_open(&hdl, NULL, NULL, &cb, MATROSKA_OPEN_FLAG_RDONLY, &args,
                        ctx);
    if (res != 0) {
        errmsg = "Error opening input file";
        goto err1;
    }

    res = matroska_read(NULL, hdl, 0);
    if (res != 0 && res != 1) {
        errmsg = "Error dumping file";
        goto err2;
    }

    res = matroska_close(hdl);
    if (res != 0) {
        errmsg = "Error closing input file";
        goto err1;
    }

    return 0;

err2:
    matroska_close(hdl);
err1:
    if (res > 0)
        res = matroska_print_err(stderr, res);
    fprintf(stderr, "%s: %s\n", errmsg, strerror(-res));
    return res;
}

int
main(int argc, char **argv)
{
    int err, tmp;
    struct ctx ctx = {0};

    if (parse_cmdline(argc, argv, &ctx) != 0)
        return EXIT_FAILURE;

    err = cvt_mkv(STDIN_FILENO, &ctx);

    tmp = free_tcb(ctx.tcb);
    if (tmp != 0)
        err = tmp;

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
