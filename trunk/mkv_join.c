/*
 * mkv_join.c
 */

#include "debug.h"

#include <json.h>

#include <json/filters.h>

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t json_rd_cb(void *, size_t, size_t, void *);

static size_t json_wr_cb(const void *, size_t, size_t, void *);

static int parse_json(json_value_t *, const char *);

static int handle_xref_marker(json_value_t, json_value_t, json_value_t);

static int handle_object(json_value_t, json_value_t, json_value_t);

static int process_docs(json_value_t, json_value_t *);

static size_t
json_rd_cb(void *buf, size_t off, size_t len, void *ctx)
{
    FILE *f = ctx;
    size_t ret;

    (void)off;

    ret = fread(buf, 1, len, f);
    return ret == 0 && !feof(f) ? (size_t)-1 : ret;
}

static size_t
json_wr_cb(const void *buf, size_t off, size_t len, void *ctx)
{
    FILE *f = ctx;
    int end;
    size_t ret;
    size_t towrite;

    (void)off;

    ret = len - 1;
    end = ((const char *)buf)[ret] == '\0';
    towrite = end ? ret : len;

    ret = fwrite(buf, 1, towrite, f);
    if (ret != towrite)
        return 0;

    if (end && fputc('\n', f) == EOF)
        return 0;

    return len;
}

static int
parse_json(json_value_t *jv, const char *pathname)
{
    FILE *f;
    int err;
    struct json_in_filter_ctx ictx;

    f = fopen(pathname, "r");
    if (f == NULL)
        return ERR_TAG(errno);

    json_in_filter_ctx_init(&ictx);
    ictx.rd_cb = &json_rd_cb;
    ictx.ctx = f;

    err = json_parse_text(jv, NULL, 0, &json_in_filter_discard_comments, &ictx);

    fclose(f);

    return err;
}

static int
handle_xref_marker(json_value_t out, json_value_t alt_in, json_value_t jv)
{
    int err;
    json_type_t jvt;
    json_value_t e;
    size_t i;
    uint64_t end, start;

    err = json_value_get_type(jv, &jvt);
    if (err)
        return err;
    if (jvt != JSON_ARRAY_T)
        return -EINVAL;

    err = json_array_get_at(jv, 0, &e);
    if (err)
        return err;
    err = json_value_get_type(e, &jvt);
    if (err)
        goto err;
    if (jvt != JSON_NUMBER_T) {
        err = -EINVAL;
        goto err;
    }
    start = json_numeric_get(e);
    json_value_put(e);

    err = json_array_get_at(jv, 1, &e);
    if (err)
        return err;
    err = json_value_get_type(e, &jvt);
    if (err)
        goto err;
    if (jvt != JSON_NUMBER_T) {
        err = -EINVAL;
        goto err;
    }
    end = json_numeric_get(e);
    json_value_put(e);

    fprintf(stderr, "xref_marker: [%" PRIu64 ", %" PRIu64 "]\n", start, end);

    for (i = start; i <= end; i++) {
        err = json_array_get_at(alt_in, i, &e);
        if (err)
            return err;

        err = json_array_push(out, e);
        json_value_put(e);
        if (err)
            return err;
    }

    return 1;

err:
    json_value_put(e);
    return err;
}

static int
handle_object(json_value_t out, json_value_t alt_in, json_value_t jv)
{
    int res;
    json_kv_pair_t elm;

    res = json_object_get(jv, L"xref_marker", &elm);
    if (res == -EINVAL)
        return 0;
    if (res != 0)
        return res;

    return handle_xref_marker(out, alt_in, elm.v);
}

static int
process_docs(json_value_t out, json_value_t *in)
{
    int res;
    json_type_t jvt;
    json_value_t jv;
    size_t i, n;

    for (i = 0; i < 2; i++) {
        res = json_value_get_type(in[i], &jvt);
        if (res != 0)
            return res;
        if (jvt != JSON_ARRAY_T)
            return -EINVAL;
    }

    n = json_array_get_size(in[1]);

    for (i = 0; i < n; i++) {
        res = json_array_get_at(in[1], i, &jv);
        if (res != 0)
            return ERR_TAG(-res);

        res = json_value_get_type(jv, &jvt);
        if (res != 0)
            return ERR_TAG(-res);
        if (jvt == JSON_OBJECT_T) {
            res = handle_object(out, in[0], jv);
            if (res != 0) {
                if (res != 1)
                    goto err;
                json_value_put(jv);
                continue;
            }
        }

        res = json_array_push(out, jv);
        if (res != 0)
            goto err;

        json_value_put(jv);
    }

    return 0;

err:
    json_value_put(jv);
    return res;
}

int
main(int argc, char **argv)
{
    int err;
    json_value_t in[2], out;
    size_t i, j;

    if (argc < 3) {
        fputs("Must specify original and modified JSON documents\n", stderr);
        return EXIT_FAILURE;
    }

    err = json_init();
    if (err) {
        fprintf(stderr, "Error initializing: %s\n", strerror(-err));
        return EXIT_FAILURE;
    }

    if (json_value_init(&out, JSON_ARRAY_T) != 0)
        goto err1;

    for (i = 0; i < 2; i = j) {
        j = i + 1;
        if (parse_json(&in[i], argv[j]) != 0)
            goto err3;
    }

    err = process_docs(out, in);
    if (err)
        goto err3;

    for (i = 0; i < 2; i++)
        json_value_put(in[i]);

    err = json_write_text(NULL, NULL, out, &json_wr_cb, stdout, 1);
    if (err) {
        fprintf(stderr, "Error generating output: %s\n", strerror(-err));
        goto err2;
    }

    json_value_put(out);

    json_deinit();

    return EXIT_SUCCESS;

err3:
    for (j = 0; j < i; j++)
        json_value_put(in[j]);
err2:
    json_value_put(out);
err1:
    json_deinit();
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
