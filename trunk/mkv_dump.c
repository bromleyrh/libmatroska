/*
 * mkv_dump.c
 */

#include "common.h"
#include "ebml.h"
#include "matroska.h"
#include "parser.h"

#include <avl_tree.h>
#include <malloc_ext.h>

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
    FILE        *f;
};

static int parse_cmdline(int, char **, struct avl_tree **);

static int track_cb_cmp(const void *, const void *, void *);
static int track_cb_free(const void *, void *);

static int free_tcb(struct avl_tree *);

static matroska_bitstream_cb_t bitstream_cb;

static int dump_mkv(int, int, struct avl_tree *);

static int
parse_cmdline(int argc, char **argv, struct avl_tree **tcb)
{
    int err;
    int i;
    struct avl_tree *ret;
    struct track_cb e;

    err = avl_tree_new(&ret, sizeof(struct track_cb), &track_cb_cmp, 0, NULL,
                       NULL, NULL);
    if (err)
        return err;

    for (i = 1; i < argc; i++) {
        char *sep;

        sep = strchr(argv[i], ':');
        if (sep == NULL) {
            err = -EINVAL;
            goto err1;
        }
        *sep = '\0';

        e.path = strdup(sep + 1);
        if (e.path == NULL) {
            err = MINUS_ERRNO;
            goto err1;
        }

        e.f = fopen(e.path, "w");
        if (e.f == NULL) {
            err = MINUS_ERRNO;
            goto err2;
        }

        e.trackno = strtoull(argv[i], NULL, 10);

        err = avl_tree_insert(ret, &e);
        if (err)
            goto err3;
    }

    *tcb = ret;
    return 0;

err3:
    fclose(e.f);
err2:
    free(e.path);
err1:
    free_tcb(ret);
    return err;
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

    if (fclose(tcb->f) == EOF)
        *(int *)ctx = MINUS_ERRNO;

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
bitstream_cb(uint64_t trackno, const void *buf, size_t len, size_t totlen,
             off_t off, int16_t ts, int keyframe, void *ctx)
{
    int res;
    struct avl_tree *tcb = ctx;
    struct track_cb e;

    (void)totlen;
    (void)off;
    (void)ts;
    (void)keyframe;

    fprintf(stderr, "%s(): %" PRIu64 ": length %zu byte%s", __FUNCTION__,
            trackno, len, PLURAL(len, "s"));

    e.trackno = trackno;
    res = avl_tree_search(tcb, &e, &e);
    if (res != 0) {
        size_t ret;

        if (res != 1)
            return res;

        fprintf(stderr, " (>%s)", e.path);

        ret = fwrite(buf, 1, len, e.f);
        if (ret != len)
            return MINUS_ERRNO;
    }

    fputc('\n', stderr);

    return 0;
}

static int
dump_mkv(int infd, int outfd, struct avl_tree *tcb)
{
    const char *errmsg;
    FILE *f;
    int err;
    matroska_hdl_t hdl;
    struct matroska_file_args args;

    args.fd = infd;
    args.pathname = NULL;
    err = matroska_open(&hdl, NULL, NULL, &bitstream_cb, &args, tcb);
    if (err) {
        errmsg = "Error opening input file";
        goto err1;
    }

    f = fdopen(outfd, "w");
    if (f == NULL) {
        err = MINUS_ERRNO;
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
        err = MINUS_ERRNO;
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
    int err;
    struct avl_tree *tcb;

    if (parse_cmdline(argc, argv, &tcb) != 0)
        return EXIT_FAILURE;

    err = dump_mkv(STDIN_FILENO, STDOUT_FILENO, tcb);

    free_tcb(tcb);

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
