/*
 * mkv_ls.c
 */

#define _FILE_OFFSET_BITS 64

#include "common.h"
#include "matroska.h"
#include "parser.h"

#include <json.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

struct cb {
    char        *path;
    int         fd;
    FILE        *f;
    json_val_t  jval;
};

struct ctx {
    struct cb   cb;
    char        *data;
    size_t      len;
    int         first_fragment;
};

#define LEN_MAX 128

#define TIME_T_MIN (~(time_t)0)
#define TIME_T_MAX ((time_t)((unsigned)TIME_T_MIN >> 1))

#define TM_YEAR(year) ((year) - 1900)

#define REFERENCE_TIME \
    { \
        .tm_mday    = 1, \
        .tm_mon     = 1, \
        .tm_year    = TM_YEAR(2001), \
        .tm_isdst   = -1 \
    }

#define TIME_GRAN 1000000000

int parser_look_up(const struct parser *, const char *, const char **,
                   enum etype *);

int matroska_print_err(FILE *, int);

static int parse_elem_spec(const char *, int, struct cb *);

static int parse_cmdline(int, char **, struct ctx *);

static int free_cb(struct cb *);

static int _cvt_utf8_to_string(json_val_t *, const char *, size_t);

static int cvt_integer_to_number(json_val_t *, matroska_metadata_t *, size_t,
                                 const char *);
static int cvt_uinteger_to_number(json_val_t *, matroska_metadata_t *, size_t,
                                  const char *);
static int cvt_float_to_number(json_val_t *, matroska_metadata_t *, size_t,
                               const char *);
static int cvt_utf8_to_string(json_val_t *, matroska_metadata_t *, size_t,
                              const char *);
static int cvt_date_to_string(json_val_t *, matroska_metadata_t *, size_t,
                              const char *);
static int cvt_master_to_string(json_val_t *, matroska_metadata_t *, size_t,
                                const char *);
static int cvt_binary_to_string(json_val_t *, matroska_metadata_t *, size_t,
                                const char *);

static matroska_metadata_cb_t metadata_cb;

static size_t json_write_cb(const char *, size_t, size_t, void *);

static int cvt_mkv(int, struct ctx *);

static int
parse_elem_spec(const char *path, int fd, struct cb *cb)
{
    int err;

    if (path == NULL) {
        cb->path = NULL;
        cb->fd = fd;

        cb->f = fdopen(cb->fd, "w");
    } else {
        cb->path = strdup(path);
        if (cb->path == NULL)
            return MINUS_ERRNO;
        cb->fd = -1;

        cb->f = fopen(cb->path, "w");
    }
    if (cb->f == NULL) {
        err = MINUS_ERRNO;
        fprintf(stderr, "Error opening output file: %s\n", strerror(-err));
        free(cb->path);
        return err;
    }

    return 0;
}

static int
parse_cmdline(int argc, char **argv, struct ctx *ctx)
{
    char *sep;
    int fd;

    if (argc != 2) {
        fprintf(stderr, "%s\n",
                argc < 2
                ? "Must specify output file"
                : "Unrecognized arguments");
        return -EINVAL;
    }

    sep = argv[1] + strcspn(argv[1], "#:");
    if (*sep == '\0')
        return -EINVAL;
    fd = *sep == '#';
    ++sep;

    if (fd) {
        fd = strtoimax(sep, NULL, 10);
        sep = NULL;
    } else
        fd = -1;

    return parse_elem_spec(sep, fd, &ctx->cb);
}

static int
free_cb(struct cb *cb)
{
    int err = 0;

    if (fsync(fileno(cb->f)) == -1
        && errno != EBADF && errno != EINVAL && errno != ENOTSUP)
        err = MINUS_ERRNO;

    if (fclose(cb->f) == EOF)
        err = MINUS_ERRNO;

    if (err)
        fprintf(stderr, "Error closing output file: %s\n", strerror(-err));

    free(cb->path);

    return err;
}

static int
_cvt_utf8_to_string(json_val_t *dst, const char *data, size_t len)
{
    char *buf;
    const char *src;
    int err;
    json_val_t ret;
    mbstate_t s;
    wchar_t *str;

    if (data[len] == '\0')
        buf = NULL;
    else {
        buf = malloc(len + 1);
        if (buf == NULL)
            return MINUS_ERRNO;
        memcpy(buf, data, len);
        buf[len] = '\0';
        data = buf;
    }

    str = malloc(len * sizeof(*str));
    if (str == NULL) {
        err = MINUS_ERRNO;
        goto err1;
    }

    for (;;) {
        wchar_t *tmp;

        src = data;
        if (mbsrtowcs(str, &src, len, memset(&s, 0, sizeof(s)))
            == (size_t)-1) {
            err = MINUS_ERRNO;
            goto err2;
        }
        if (src == NULL)
            break;
        len *= 2;
        tmp = realloc(str, len * sizeof(*tmp));
        if (tmp == NULL) {
            err = MINUS_ERRNO;
            goto err2;
        }
        str = tmp;
    }

    free(buf);

    ret = json_val_new(JSON_TYPE_STRING);
    if (ret == NULL) {
        err = -ENOMEM;
        goto end;
    }

    err = json_val_string_set(ret, str);
    if (err)
        json_val_free(ret);
    else
        *dst = ret;

end:
    free(str);
    return err;

err2:
    free(str);
err1:
    free(buf);
    return err;
}

static int
cvt_integer_to_number(json_val_t *dst, matroska_metadata_t *src, size_t len,
                      const char *name)
{
    json_val_t ret;

    (void)len;
    (void)name;

    ret = json_val_new(JSON_TYPE_NUMBER);
    if (ret == NULL)
        return -ENOMEM;

    json_val_numeric_set(ret, src->integer);

    *dst = ret;
    return 0;
}

static int
cvt_uinteger_to_number(json_val_t *dst, matroska_metadata_t *src, size_t len,
                       const char *name)
{
    json_val_t ret;

    (void)len;
    (void)name;

    ret = json_val_new(JSON_TYPE_NUMBER);
    if (ret == NULL)
        return -ENOMEM;

    json_val_numeric_set(ret, src->uinteger);

    *dst = ret;
    return 0;
}

static int
cvt_float_to_number(json_val_t *dst, matroska_metadata_t *src, size_t len,
                    const char *name)
{
    json_val_t ret;

    (void)len;
    (void)name;

    ret = json_val_new(JSON_TYPE_NUMBER);
    if (ret == NULL)
        return -ENOMEM;

    json_val_numeric_set(ret, src->dbl);

    *dst = ret;
    return 0;
}

static int
cvt_utf8_to_string(json_val_t *dst, matroska_metadata_t *src, size_t len,
                   const char *name)
{
    (void)len;
    (void)name;

    return _cvt_utf8_to_string(dst, src->data, src->len);
}

static int
cvt_date_to_string(json_val_t *dst, matroska_metadata_t *src, size_t len,
                   const char *name)
{
    char buf[64];
    int64_t s;
    struct tm tm = REFERENCE_TIME;
    time_t date, reftm;

    (void)dst;
    (void)name;

    reftm = mktime(&tm);

    s = src->integer / TIME_GRAN;

    if (s >= 0) {
        if ((int64_t)(TIME_T_MAX - reftm) < s)
            return -EOVERFLOW;
    } else if ((int64_t)(TIME_T_MIN - reftm) > s)
        return -EOVERFLOW;

    date = reftm + s;

    gmtime_r(&date, &tm);

    len = strftime(buf, sizeof(buf), "%Y %m %d %H %M %S", &tm);
    len += snprintf(buf + len, sizeof(buf) - len, " %09" PRIi64,
                    src->integer % TIME_GRAN);

    return _cvt_utf8_to_string(dst, buf, len + 1);
}

static int
cvt_master_to_string(json_val_t *dst, matroska_metadata_t *src, size_t len,
                     const char *name)
{
    (void)src;
    (void)len;

    return _cvt_utf8_to_string(dst, name, strlen(name) + 1);
}

static int
cvt_binary_to_string(json_val_t *dst, matroska_metadata_t *src, size_t len,
                     const char *name)
{
    char *s, *str;
    int err;
    size_t i;
    size_t slen;

    (void)name;

    slen = 2 * src->len + 1;

    str = malloc(slen);
    if (str == NULL)
        return MINUS_ERRNO;

    i = 0;
    s = str;
    len = slen;
    for (;;) {
        int n;
        unsigned char b = src->data[i];

        n = snprintf(s, len, "%x%x", b >> CHAR_BIT / 2, b & 0xf);
        if (n >= (int)len) {
            err = -ENAMETOOLONG;
            goto end;
        }

        if (++i == src->len)
            break;

        s += n;
        len -= n;
    }

    err = _cvt_utf8_to_string(dst, str, slen);

end:
    free(str);
    return err;
}

static int
metadata_cb(const char *id, matroska_metadata_t *val, size_t len, int flags,
            void *ctx)
{
    char *buf, *value;
    enum etype etype;
    int (*fn)(json_val_t *, matroska_metadata_t *, size_t, const char *);
    int res;
    json_object_elem_t elem;
    json_val_t jval;
    matroska_metadata_t valbuf;
    mbstate_t s;
    size_t buflen;
    struct ctx *ctxp = ctx;
    wchar_t *key;

    static int (*const fns[])(json_val_t *, matroska_metadata_t *, size_t,
                              const char *) = {
        [ETYPE_INTEGER]     = &cvt_integer_to_number,
        [ETYPE_UINTEGER]    = &cvt_uinteger_to_number,
        [ETYPE_FLOAT]       = &cvt_float_to_number,
        [ETYPE_STRING]      = &cvt_utf8_to_string,
        [ETYPE_UTF8]        = &cvt_utf8_to_string,
        [ETYPE_DATE]        = &cvt_date_to_string,
        [ETYPE_MASTER]      = &cvt_master_to_string,
        [ETYPE_BINARY]      = &cvt_binary_to_string
    };

    if (len > LEN_MAX)
        return 0;

    if (flags & MATROSKA_METADATA_FLAG_FRAGMENT) {
        if (ctxp->first_fragment) {
            buf = realloc(ctxp->data, len);
            if (buf == NULL)
                return MINUS_ERRNO;
            ctxp->data = buf;
        } else
            buf = ctxp->data;

        memcpy(buf + ctxp->len, val->data, val->len);
        ctxp->len += val->len;
        if (ctxp->len < len) {
            ctxp->first_fragment = 0;
            return 0;
        }
        ctxp->len = 0;
        ctxp->first_fragment = 1;

        valbuf.data = buf;
        valbuf.len = len;
        val = &valbuf;
    }

    buflen = strlen(id) + 1;

    buf = malloc(2 * buflen);
    if (buf == NULL)
        return MINUS_ERRNO;
    value = buf + buflen;

    if (sscanf(id, "%s -> %s", buf, value) != 2)
        goto end;

    res = parser_look_up(MATROSKA_PARSER, buf, &id, &etype);
    if (res != 1) {
        if (res != 0)
            goto err1;
        goto end;
    }

    if (etype >= ARRAY_SIZE(fns)) {
        res = -EIO;
        goto err1;
    }
    fn = fns[etype];
    if (fn == NULL) {
        res = -EIO;
        goto err1;
    }

    buflen = 16;
    key = malloc(buflen * sizeof(*key));
    if (key == NULL) {
        res = MINUS_ERRNO;
        goto err1;
    }

    for (;;) {
        wchar_t *tmp;

        id = value;
        if (mbsrtowcs(key, &id, buflen, memset(&s, 0, sizeof(s)))
            == (size_t)-1) {
            res = MINUS_ERRNO;
            goto err2;
        }
        if (id == NULL)
            break;
        buflen *= 2;
        tmp = realloc(key, buflen * sizeof(*tmp));
        if (tmp == NULL) {
            res = MINUS_ERRNO;
            goto err2;
        }
        key = tmp;
    }

    jval = json_val_new(JSON_TYPE_OBJECT);
    if (jval == NULL) {
        res = -ENOMEM;
        goto err2;
    }

    res = (*fn)(&elem.value, val, len, value);
    if (res != 0)
        goto err3;

    elem.key = key;

    res = json_val_object_insert_elem(jval, &elem);
    if (res != 0)
        goto err4;

    json_val_free(elem.value);

    res = json_val_array_insert_elem(ctxp->cb.jval, jval);
    if (res != 0) {
        json_val_free(jval);
        free(buf);
        return res;
    }

    json_val_free(jval);

end:
    free(buf);
    return 0;

err4:
    json_val_free(elem.value);
err3:
    json_val_free(jval);
err2:
    free(key);
err1:
    free(buf);
    return res;
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
    if (ret < towrite)
        return 0;

    if (end && fputc('\n', f) == EOF)
        return 0;

    return len;
}

static int
cvt_mkv(int infd, struct ctx *ctx)
{
    const char *errmsg;
    int res;
    json_val_t jval;
    matroska_hdl_t hdl;
    struct matroska_file_args args;

    errmsg = "Error initializing";

    res = json_init();
    if (res != 0)
        goto err1;

    jval = json_val_new(JSON_TYPE_ARRAY);
    if (jval == NULL) {
        res = -ENOMEM;
        goto err2;
    }

    args.fd = infd;
    args.pathname = NULL;
    res = matroska_open(&hdl, NULL, &metadata_cb, NULL, &args, ctx);
    if (res != 0) {
        errmsg = "Error opening input file";
        goto err3;
    }

    ctx->first_fragment = 1;
    ctx->cb.jval = jval;

    res = matroska_read(NULL, hdl);
    free(ctx->data);
    if (res != 0 && res != 1) {
        errmsg = "Error dumping file";
        goto err4;
    }

    res = matroska_close(hdl);
    if (res != 0) {
        errmsg = "Error closing input file";
        goto err3;
    }

    res = json_generate(jval, &json_write_cb, ctx->cb.f, NULL, NULL, 1);
    if (res != 0) {
        errmsg = "Error writing output";
        goto err2;
    }

    json_val_free(jval);

    json_end();

    return 0;

err4:
    matroska_close(hdl);
err3:
    json_val_free(jval);
err2:
    json_end();
err1:
    if (res > 0)
        res = matroska_print_err(stderr, res);
    fprintf(stderr, "%s: %s\n", errmsg, strerror(-res));
    return res;
}

int
main(int argc, char **argv)
{
    int err;
    struct ctx ctx = {0};

    if (parse_cmdline(argc, argv, &ctx) != 0)
        return EXIT_FAILURE;

    err = cvt_mkv(STDIN_FILENO, &ctx);

    free_cb(&ctx.cb);

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
