/*
 * mkv_dump.c
 */

#define _FILE_OFFSET_BITS 64

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

struct elem_cb {
    uint64_t    elemno;
    char        *path;
    FILE        *f;
};

struct ctx {
    struct avl_tree *tcb;
    struct avl_tree *ecb;
    uint64_t        n;
    size_t          datalen;
};

static int parse_track_spec(const char *, const char *, struct avl_tree *);
static int parse_elem_spec(const char *, const char *, struct avl_tree *);

static int parse_cmdline(int, char **, struct ctx *);

static int track_cb_cmp(const void *, const void *, void *);
static int track_cb_free(const void *, void *);

static int elem_cb_cmp(const void *, const void *, void *);
static int elem_cb_free(const void *, void *);

static int free_tcb(struct avl_tree *);
static int free_ecb(struct avl_tree *);

static matroska_metadata_cb_t metadata_cb;

static matroska_bitstream_cb_t bitstream_cb;

static int dump_mkv(int, int, struct ctx *);

static int
parse_track_spec(const char *trackno, const char *path, struct avl_tree *tcb)
{
    int err;
    struct track_cb e;

    e.path = strdup(path);
    if (e.path == NULL)
        return MINUS_ERRNO;

    e.f = fopen(e.path, "w");
    if (e.f == NULL) {
        err = MINUS_ERRNO;
        goto err1;
    }

    e.trackno = strtoull(trackno, NULL, 10);

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
parse_elem_spec(const char *elemno, const char *path, struct avl_tree *ecb)
{
    int err;
    struct elem_cb e;

    e.path = strdup(path);
    if (e.path == NULL)
        return MINUS_ERRNO;

    e.f = fopen(e.path, "w");
    if (e.f == NULL) {
        err = MINUS_ERRNO;
        goto err1;
    }

    e.elemno = strtoull(elemno + 1, NULL, 10);

    err = avl_tree_insert(ecb, &e);
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
    struct {
        struct avl_tree *cb;
        int             (*parse_fn)(const char *, const char *,
                                    struct avl_tree *);
    } parse_data[2], *parse_data_p;
    struct avl_tree *elemcb, *trackcb;

    err = avl_tree_new(&trackcb, sizeof(struct track_cb), &track_cb_cmp, 0,
                       NULL, NULL, NULL);
    if (err)
        return err;

    err = avl_tree_new(&elemcb, sizeof(struct elem_cb), &elem_cb_cmp, 0, NULL,
                       NULL, NULL);
    if (err)
        goto err1;

    parse_data[0].cb = trackcb;
    parse_data[0].parse_fn = &parse_track_spec;
    parse_data[1].cb = elemcb;
    parse_data[1].parse_fn = &parse_elem_spec;

    for (i = 1; i < argc; i++) {
        char *sep;

        sep = strchr(argv[i], ':');
        if (sep == NULL)
            return -EINVAL;
        *sep = '\0';

        parse_data_p = &parse_data[argv[i][0] == '[' && sep[-1] == ']'];
        err = (*parse_data_p->parse_fn)(argv[i], sep + 1, parse_data_p->cb);
        if (err)
            goto err2;
    }

    ctx->tcb = trackcb;
    ctx->ecb = elemcb;
    return 0;

err2:
    free_ecb(elemcb);
err1:
    free_tcb(trackcb);
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

    if (fsync(fileno(tcb->f)) == -1 && errno != EINVAL)
        *(int *)ctx = MINUS_ERRNO;

    if (fclose(tcb->f) == EOF)
        *(int *)ctx = MINUS_ERRNO;

    free(tcb->path);

    return 0;
}

static int
elem_cb_cmp(const void *k1, const void *k2, void *ctx)
{
    const struct elem_cb *ecb1 = k1;
    const struct elem_cb *ecb2 = k2;

    (void)ctx;

    return (ecb1->elemno > ecb2->elemno) - (ecb1->elemno < ecb2->elemno);
}

static int
elem_cb_free(const void *keyval, void *ctx)
{
    const struct elem_cb *ecb = keyval;

    if (fsync(fileno(ecb->f)) == -1 && errno != EINVAL)
        *(int *)ctx = MINUS_ERRNO;

    if (fclose(ecb->f) == EOF)
        *(int *)ctx = MINUS_ERRNO;

    free(ecb->path);

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
free_ecb(struct avl_tree *ecb)
{
    avl_tree_walk_ctx_t wctx = NULL;
    int err = 0;

    avl_tree_walk(ecb, NULL, &elem_cb_free, &err, &wctx);
    avl_tree_free(ecb);

    return err;
}

static int
metadata_cb(const char *id, matroska_metadata_t *val, size_t len, int flags,
            void *ctx)
{
    int res;
    struct ctx *ctxp = ctx;
    struct elem_cb e;

    (void)id;
    (void)flags;

    if (ctxp->datalen == 0)
        fprintf(stderr, "[%" PRIu64 "]\n", ctxp->n);

    if (val->type != MATROSKA_TYPE_BYTES) {
        ++ctxp->n;
        return 0;
    }

    e.elemno = ctxp->n;
    res = avl_tree_search(ctxp->ecb, &e, &e);
    if (res != 0) {
        size_t ret;

        if (res != 1)
            return res;

        ret = fwrite(val->data, 1, val->len, e.f);
        if (ret != val->len)
            return MINUS_ERRNO;
    }

    ctxp->datalen += val->len;
    if (ctxp->datalen == len) {
        ++ctxp->n;
        ctxp->datalen = 0;
    }

    return 0;
}

static int
bitstream_cb(uint64_t trackno, const void *buf, size_t len, size_t totlen,
             off_t off, int16_t ts, int keyframe, void *ctx)
{
    int res;
    struct ctx *ctxp = ctx;
    struct track_cb e;

    (void)totlen;
    (void)off;
    (void)ts;
    (void)keyframe;

    fprintf(stderr, "%s(): %" PRIu64 ": length %zu byte%s", __FUNCTION__,
            trackno, len, PLURAL(len, "s"));

    e.trackno = trackno;
    res = avl_tree_search(ctxp->tcb, &e, &e);
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
dump_mkv(int infd, int outfd, struct ctx *ctx)
{
    const char *errmsg;
    FILE *f;
    int err;
    matroska_hdl_t hdl;
    struct matroska_file_args args;

    args.fd = infd;
    args.pathname = NULL;
    err = matroska_open(&hdl, NULL, &metadata_cb, &bitstream_cb, &args, ctx);
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

    if (fsync(fileno(f)) == -1 && errno != EINVAL) {
        err = MINUS_ERRNO;
        errmsg = "Error closing output file";
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
    struct ctx ctx = {0};

    if (parse_cmdline(argc, argv, &ctx) != 0)
        return EXIT_FAILURE;

    err = dump_mkv(STDIN_FILENO, STDOUT_FILENO, &ctx);

    free_tcb(ctx.tcb);
    free_ecb(ctx.ecb);

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
