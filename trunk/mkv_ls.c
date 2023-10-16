/*
 * mkv_ls.c
 */

#define _FILE_OFFSET_BITS 64

#include "common.h"
#include "debug.h"
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

#include <sys/types.h>

struct cb {
    char        *path;
    int         fd;
    FILE        *f;
    json_val_t  jval;
    json_val_t  elem;
    char        *datapath;
    int         datafd;
    FILE        *dataf;
};

struct ctx {
    struct cb   cb;
    char        *data;
    size_t      len;
    unsigned    header:1;
    unsigned    first_fragment:1;
    int         export;
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

static int parse_elem_spec(const char *, int, const char *, int, struct cb *);

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
static int cvt_master_to_number(json_val_t *, matroska_metadata_t *, size_t,
                                const char *);
static int cvt_binary_to_string(json_val_t *, matroska_metadata_t *, size_t,
                                const char *);

static matroska_metadata_cb_t metadata_cb;

static matroska_bitstream_cb_t bitstream_cb;

static size_t json_write_cb(const char *, size_t, size_t, void *);

static int cvt_mkv(int, struct ctx *);

static int
parse_elem_spec(const char *path1, int fd1, const char *path2, int fd2,
                struct cb *cb)
{
    int err;

    if (path1 == NULL) {
        cb->path = NULL;
        cb->fd = fd1;

        cb->f = fdopen(cb->fd, "w");
    } else {
        cb->path = strdup(path1);
        if (cb->path == NULL)
            return MINUS_ERRNO;
        cb->fd = -1;

        cb->f = fopen(cb->path, "w");
    }
    if (cb->f == NULL) {
        err = MINUS_ERRNO;
        goto err1;
    }

    if (path2 == NULL) {
        cb->datapath = NULL;
        cb->datafd = fd2;

        cb->dataf = fdopen(cb->datafd, "w");
    } else {
        cb->datapath = strdup(path2);
        if (cb->datapath == NULL) {
            err = MINUS_ERRNO;
            goto err2;
        }
        cb->datafd = -1;

        cb->dataf = fopen(cb->datapath, "w");
    }
    if (cb->dataf == NULL) {
        err = MINUS_ERRNO;
        goto err3;
    }

    return 0;

err3:
    free(cb->datapath);
err2:
    fclose(cb->f);
err1:
    free(cb->path);
    fprintf(stderr, "Error opening output file: %s\n", strerror(-err));
    return err;
}

static int
parse_cmdline(int argc, char **argv, struct ctx *ctx)
{
    char *sep1, *sep2;
    int err;
    int fd1, fd2;

    if (argc != 2) {
        fprintf(stderr, "%s\n",
                argc < 2
                ? "Must specify output files"
                : "Unrecognized arguments");
        return -EINVAL;
    }

    sep1 = argv[1] + strcspn(argv[1], "#:");
    if (*sep1 == '\0')
        return -EINVAL;
    fd1 = *sep1 == '#';
    *sep1++ = '\0';

    sep2 = strchr(sep1, ';');
    if (sep2 == NULL)
        return -EINVAL;
    *sep2++ = '\0';
    if (*sep2 == '#') {
        fd2 = 1;
        ++sep2;
    } else
        fd2 = 0;

    if (fd1) {
        fd1 = strtoimax(sep1, NULL, 10);
        sep1 = NULL;
    } else
        fd1 = -1;

    if (fd2) {
        fd2 = strtoimax(sep2, NULL, 10);
        sep2 = NULL;
    } else
        fd2 = -1;

    err = parse_elem_spec(sep1, fd1, sep2, fd2, &ctx->cb);
    if (!err)
        ctx->export = strcmp(argv[1], "e") == 0;

    return err;
}

static int
free_cb(struct cb *cb)
{
    int err = 0;

    if (fsync(fileno(cb->dataf)) == -1
        && errno != EBADF && errno != EINVAL && errno != ENOTSUP)
        err = MINUS_ERRNO;

    if (fclose(cb->dataf) == EOF)
        err = MINUS_ERRNO;

    if (err)
        fprintf(stderr, "Error closing output file: %s\n", strerror(-err));

    free(cb->datapath);

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
cvt_master_to_number(json_val_t *dst, matroska_metadata_t *src, size_t len,
                     const char *name)
{
    json_val_t ret;

    (void)src;
    (void)name;

    ret = json_val_new(JSON_TYPE_NUMBER);
    if (ret == NULL)
        return -ENOMEM;

    json_val_numeric_set(ret, len);

    *dst = ret;
    return 0;
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

    if (len > LEN_MAX) {
        json_val_t ret;

        ret = json_val_new(JSON_TYPE_NULL);
        if (ret == NULL)
            return -ENOMEM;
        *dst = ret;
        return 0;
    }

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
metadata_cb(const char *id, matroska_metadata_t *val, size_t len, size_t hdrlen,
            int flags, void *ctx)
{
    char *buf, *idbuf, *value;
    enum etype etype;
    int (*fn)(json_val_t *, matroska_metadata_t *, size_t, const char *);
    int incremental;
    int new_val;
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
        [ETYPE_MASTER]      = &cvt_master_to_number,
        [ETYPE_BINARY]      = &cvt_binary_to_string
    };

    if (ctxp->header && !(flags & MATROSKA_METADATA_FLAG_HEADER)) {
        ctxp->header = 0;

        jval = json_val_new(JSON_TYPE_NULL);
        if (jval == NULL)
            return -ENOMEM;

        res = json_val_array_insert_elem(ctxp->cb.jval, jval);
        json_val_free(jval);
        if (res != 0)
            return res;
    }

    buflen = strlen(id) + 1;

    idbuf = malloc(2 * buflen);
    if (idbuf == NULL)
        return MINUS_ERRNO;
    value = idbuf + buflen;

    if (sscanf(id, "%s -> %s", idbuf, value) != 2)
        goto end;

    new_val = ctxp->first_fragment;
    incremental = strcmp("Block", value) == 0
                  || strcmp("SimpleBlock", value) == 0;

    if (flags & MATROSKA_METADATA_FLAG_FRAGMENT) {
        if (len <= LEN_MAX) {
            if (new_val) {
                buf = realloc(ctxp->data, len);
                if (buf == NULL) {
                    res = MINUS_ERRNO;
                    goto err1;
                }
                ctxp->data = buf;
            } else
                buf = ctxp->data;

            valbuf.data = memcpy(buf + ctxp->len, val->data, val->len);
            valbuf.len = val->len;
        }

        ctxp->len += val->len;

        if (ctxp->len < len) {
            ctxp->first_fragment = 0;
            if (!incremental)
                goto end;
        } else {
            ctxp->len = 0;
            ctxp->first_fragment = 1;

            if (!incremental && len <= LEN_MAX) {
                valbuf.data = buf;
                valbuf.len = len;
            }
        }

        if (len <= LEN_MAX)
            val = &valbuf;
    }

    if (new_val && ctxp->cb.elem != NULL) {
        json_val_free(ctxp->cb.elem);
        ctxp->cb.elem = NULL;
    }

    res = parser_look_up(flags & MATROSKA_METADATA_FLAG_HEADER
                         ? EBML_PARSER : MATROSKA_PARSER,
                         idbuf, &id, &etype);
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

        id = ctxp->export ? idbuf : value;
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
    key = NULL;

    json_val_free(elem.value);

    if (!incremental) {
        elem.value = json_val_new(JSON_TYPE_NUMBER);
        if (elem.value == NULL) {
            res = -ENOMEM;
            goto err3;
        }
        json_val_numeric_set(elem.value, hdrlen);

        key = wcsdup(L"hdr_len");
        if (key == NULL) {
            res = MINUS_ERRNO;
            goto err4;
        }

        elem.key = key;

        res = json_val_object_insert_elem(jval, &elem);
        if (res != 0)
            goto err4;

        json_val_free(elem.value);

        if (etype != ETYPE_MASTER) {
            elem.value = json_val_new(JSON_TYPE_NUMBER);
            if (elem.value == NULL) {
                res = -ENOMEM;
                goto err3;
            }
            json_val_numeric_set(elem.value, len);

            key = wcsdup(L"data_len");
            if (key == NULL) {
                res = MINUS_ERRNO;
                goto err4;
            }

            elem.key = key;

            res = json_val_object_insert_elem(jval, &elem);
            if (res != 0)
                goto err4;
            key = NULL;

            json_val_free(elem.value);
        }
    }

    res = json_val_array_insert_elem(ctxp->cb.jval, jval);
    if (res != 0)
        goto err3;

    if (new_val && incremental)
        ctxp->cb.elem = jval;
    else
        json_val_free(jval);

end:
    free(idbuf);
    return 0;

err4:
    json_val_free(elem.value);
err3:
    json_val_free(jval);
err2:
    free(key);
err1:
    free(idbuf);
    return res;
}

static int
bitstream_cb(uint64_t trackno, const void *buf, size_t len, size_t totlen,
             size_t hdrlen, off_t off, int16_t ts, int keyframe, void *ctx)
{
    int err;
    json_object_elem_t elem;
    struct ctx *ctxp = ctx;
    wchar_t *key;

/*    fprintf(stderr, "trackno %" PRIu64 ", ts %" PRIi16 ", keyframe %d, %p\n",
            trackno, ts, keyframe, ctxp->cb.elem);
*/
    if (ctxp->cb.elem == NULL)
        goto end;

    elem.value = json_val_new(JSON_TYPE_NUMBER);
    if (elem.value == NULL)
        return -ENOMEM;
    json_val_numeric_set(elem.value, trackno);

    key = wcsdup(L"trackno");
    if (key == NULL)
        goto err1;
    elem.key = key;

    err = json_val_object_insert_elem(ctxp->cb.elem, &elem);
    json_val_free(elem.value);
    if (err)
        goto err2;

    elem.value = json_val_new(JSON_TYPE_NUMBER);
    if (elem.value == NULL)
        return -ENOMEM;
    json_val_numeric_set(elem.value, ts);

    key = wcsdup(L"ts");
    if (key == NULL)
        goto err1;
    elem.key = key;

    err = json_val_object_insert_elem(ctxp->cb.elem, &elem);
    json_val_free(elem.value);
    if (err)
        goto err2;

    elem.value = json_val_new(JSON_TYPE_BOOLEAN);
    if (elem.value == NULL)
        return -ENOMEM;
    json_val_boolean_set(elem.value, keyframe);

    key = wcsdup(L"keyframe");
    if (key == NULL)
        goto err1;
    elem.key = key;

    err = json_val_object_insert_elem(ctxp->cb.elem, &elem);
    json_val_free(elem.value);
    if (err)
        goto err2;

    elem.value = json_val_new(JSON_TYPE_NUMBER);
    if (elem.value == NULL)
        return -ENOMEM;
    json_val_numeric_set(elem.value, off);

    key = wcsdup(L"data_offset");
    if (key == NULL)
        goto err1;
    elem.key = key;

    err = json_val_object_insert_elem(ctxp->cb.elem, &elem);
    json_val_free(elem.value);
    if (err)
        goto err2;

    elem.value = json_val_new(JSON_TYPE_NUMBER);
    if (elem.value == NULL)
        return -ENOMEM;
    json_val_numeric_set(elem.value, hdrlen);

    key = wcsdup(L"hdr_len");
    if (key == NULL)
        goto err1;
    elem.key = key;

    err = json_val_object_insert_elem(ctxp->cb.elem, &elem);
    json_val_free(elem.value);
    if (err)
        goto err2;

    elem.value = json_val_new(JSON_TYPE_NUMBER);
    if (elem.value == NULL)
        return -ENOMEM;
    json_val_numeric_set(elem.value, totlen);

    key = wcsdup(L"data_len");
    if (key == NULL)
        goto err1;
    elem.key = key;

    err = json_val_object_insert_elem(ctxp->cb.elem, &elem);
    json_val_free(elem.value);
    if (err)
        goto err2;

    ctxp->cb.elem = NULL;
    json_val_free(ctxp->cb.elem);

end:
    off = ftello(ctxp->cb.dataf);
    if (off == -1)
        return MINUS_ERRNO;
    if (fwrite(buf, 1, len, ctxp->cb.dataf) != len) {
        fprintf(stderr, "Error writing output: %s\n", strerror(errno));
        return -EIO;
    }
    return 0;

err2:
    free(key);
    return err;

err1:
    json_val_free(elem.value);
    return -ENOMEM;
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
cvt_mkv(int infd, struct ctx *ctx)
{
    const char *errmsg;
    int res;
    json_val_t jval;
    matroska_hdl_t hdl;
    struct matroska_file_args args;

    errmsg = "Error initializing";

    errno = 0;
    if (isatty(fileno(ctx->cb.dataf)) == 1) {
        res = -EINVAL;
        errmsg = NULL;
        fputs("Standard output refers to a terminal device\n", stderr);
        goto err1;
    }
    switch (errno) {
    case ENOTTY:
    case 0:
        break;
    default:
        res = MINUS_ERRNO;
        goto err1;
    }

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
    res = matroska_open(&hdl, NULL, &metadata_cb, &bitstream_cb, &args, ctx);
    if (res != 0) {
        errmsg = "Error opening input file";
        goto err3;
    }

    ctx->header = 1;
    ctx->first_fragment = 1;
    ctx->cb.jval = jval;

    res = matroska_read(NULL, hdl,
                        MATROSKA_READ_FLAG_HEADER | MATROSKA_READ_FLAG_MASTER);
    if (ctx->cb.elem != NULL)
        json_val_free(ctx->cb.elem);
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
    if (errmsg != NULL)
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

    fprintf(stderr, "Metadata path %s, FD %d\n"
                    "Data path %s, FD %d\n",
            ctx.cb.path == NULL ? "NULL" : ctx.cb.path, ctx.cb.fd,
            ctx.cb.datapath == NULL ? "NULL" : ctx.cb.datapath, ctx.cb.datafd);

    err = cvt_mkv(STDIN_FILENO, &ctx);

    tmp = free_cb(&ctx.cb);
    if (tmp != 0)
        err = tmp;

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
