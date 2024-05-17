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

static size_t json_read_cb(char *, size_t, size_t, void *);

static size_t json_write_cb(const char *, size_t, size_t, void *);

static int parse_json(json_value_t *, const char *);

static int handle_xref_marker(json_value_t, json_value_t, json_value_t);

static int handle_object(json_value_t, json_value_t, json_value_t);

static int process_docs(json_value_t, json_value_t *);

static size_t
json_read_cb(char *buf, size_t off, size_t len, void *ctx)
{
    FILE *f = ctx;
    size_t ret;

    (void)off;

    ret = fread(buf, 1, len, f);
    return ret == 0 && !feof(f) ? (size_t)-1 : ret;
}

static size_t
json_write_cb(const char *buf, size_t off, size_t len, void *ctx)
{
    FILE *f = ctx;
    int end;
    size_t ret;
    size_t towrite;

    (void)off;

    ret = len - 1;
    end = buf[ret] == '\0';
    towrite = end ? ret : len;

    ret = fwrite(buf, 1, towrite, f);
    if (ret != towrite)
        return 0;

    if (end && fputc('\n', f) == EOF)
        return 0;

    return len;
}

static int
parse_json(json_value_t *jval, const char *pathname)
{
    FILE *f;
    int err;
    struct json_read_cb_ctx rctx;

    f = fopen(pathname, "r");
    if (f == NULL)
        return ERR_TAG(errno);

    json_read_cb_ctx_init(&rctx);
    rctx.read_cb = &json_read_cb;
    rctx.ctx = f;

    err = json_parse(NULL, 0, &json_read_cb_strip_comments, &rctx, jval);

    fclose(f);

    return err;
}

static int
handle_xref_marker(json_value_t out, json_value_t alt_in, json_value_t jv)
{
    int err;
    json_value_t e;
    size_t i;
    uint64_t end, start;

    if (json_val_get_type(jval) != JSON_TYPE_ARRAY)
        return -EINVAL;

    e = json_val_array_get_elem(jval, 0);
    if (e == NULL)
        return -EINVAL;
    if (json_val_get_type(e) != JSON_TYPE_NUMBER)
        goto err;
    start = json_val_numeric_get(e);
    json_val_free(e);

    e = json_val_array_get_elem(jval, 1);
    if (e == NULL)
        return -EINVAL;
    if (json_val_get_type(e) != JSON_TYPE_NUMBER)
        goto err;
    end = json_val_numeric_get(e);
    json_val_free(e);

    fprintf(stderr, "xref_marker: [%" PRIu64 ", %" PRIu64 "]\n", start, end);

    for (i = start; i <= end; i++) {
        e = json_val_array_get_elem(alt_in, i);
        if (e == NULL)
            return -EINVAL;

        err = json_val_array_insert_elem(out, e);
        json_val_free(e);
        if (err)
            return err;
    }

    return 1;

err:
    json_val_free(e);
    return -EINVAL;
}

static int
handle_object(json_value_t out, json_value_t alt_in, json_value_t jv)
{
    int res;
    json_object_elem_t elem;

    res = json_val_object_get_elem_by_key(jval, L"xref_marker", &elem);
    if (res == -EINVAL)
        return 0;
    if (res != 0)
        return res;

    return handle_xref_marker(out, alt_in, elem.value);
}

static int
process_docs(json_value_t out, json_value_t *in)
{
    int res;
    json_value_t jval;
    size_t i, n;

    if (json_val_get_type(in[0]) != JSON_TYPE_ARRAY
        || json_val_get_type(in[1]) != JSON_TYPE_ARRAY)
        return -EINVAL;

    n = json_val_array_get_num_elem(in[1]);

    for (i = 0; i < n; i++) {
        jval = json_val_array_get_elem(in[1], i);
        if (jval == NULL)
            return ERR_TAG(EIO);

        if (json_val_get_type(jval) == JSON_TYPE_OBJECT) {
            res = handle_object(out, in[0], jval);
            if (res != 0) {
                if (res != 1)
                    goto err;
                json_val_free(jval);
                continue;
            }
        }

        res = json_val_array_insert_elem(out, jval);
        if (res != 0)
            goto err;

        json_val_free(jval);
    }

    return 0;

err:
    json_val_free(jval);
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

    out = json_val_new(JSON_TYPE_ARRAY);
    if (out == NULL)
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
        json_val_free(in[i]);

    err = json_generate(out, &json_write_cb, stdout, NULL, NULL, 1);
    if (err) {
        fprintf(stderr, "Error generating output: %s\n", strerror(-err));
        goto err2;
    }

    json_val_free(out);

    json_end();

    return EXIT_SUCCESS;

err3:
    for (j = 0; j < i; j++)
        json_val_free(in[j]);
err2:
    json_val_free(out);
err1:
    json_end();
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
