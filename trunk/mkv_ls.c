/*
 * mkv_ls.c
 */

#define _FILE_OFFSET_BITS 64

#include "common.h"
#include "debug.h"
#include "matroska.h"
#include "parser.h"
#include "std_sys.h"

#include <checksums.h>

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
    char            *path;
    int             fd;
    FILE            *f;
    json_value_t    jv;
    json_value_t    elm;
    char            *datapath;
    int             datafd;
    FILE            *dataf;
    char            *tracepath;
    int             tracefd;
    FILE            *tracef;
};

struct ctx {
    struct cb   cb;
    char        *data;
    size_t      len;
    size_t      remlen;
    off_t       baseoff;
    off_t       off;
    size_t      totmdlen;
    size_t      totlogbytes;
    char        *tracebuf;
    size_t      tracebuflen;
    size_t      tracebufsz;
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

#define TIME_GRAN INT64_C(1000000000)

int parser_look_up(const struct parser *, const char *,
                   const struct elem_data **, const struct elem_data **);

int matroska_print_err(FILE *, int);

static int parse_elem_spec(const char *, int, const char *, int, const char *,
                           int, struct cb *);

static int parse_cmdline(int, char **, struct ctx *);

static int syncf(int);

static int free_cb(struct cb *);

static int _cvt_utf8_to_string(json_value_t *, const char *, size_t);

static int cvt_integer_to_number(json_value_t *, matroska_metadata_t *, size_t,
                                 const char *);
static int cvt_uinteger_to_number(json_value_t *, matroska_metadata_t *, size_t,
                                  const char *);
static int cvt_float_to_number(json_value_t *, matroska_metadata_t *, size_t,
                               const char *);
static int cvt_utf8_to_string(json_value_t *, matroska_metadata_t *, size_t,
                              const char *);
static int cvt_date_to_string(json_value_t *, matroska_metadata_t *, size_t,
                              const char *);
static int cvt_master_to_number(json_value_t *, matroska_metadata_t *, size_t,
                                const char *);
static int cvt_binary_to_string(json_value_t *, matroska_metadata_t *, size_t,
                                const char *);

static matroska_metadata_output_cb_t metadata_cb;

static matroska_bitstream_output_cb_t bitstream_cb;

static size_t json_wr_cb(const void *, size_t, size_t, void *);

static int cvt_mkv(int, struct ctx *);

static int
parse_elem_spec(const char *path1, int fd1, const char *path2, int fd2,
                const char *path3, int fd3, struct cb *cb)
{
    int err;

    if (path1 != NULL) {
        cb->path = strdup(path1);
        if (cb->path == NULL)
            return MINUS_ERRNO;
        cb->fd = -1;

        cb->f = fopen(cb->path, "w");
    } else {
        cb->path = NULL;
        cb->fd = fd1;

        cb->f = fdopen(cb->fd, "w");
    }
    if (cb->f == NULL) {
        err = MINUS_ERRNO;
        goto err1;
    }

    if (path2 != NULL) {
        cb->datapath = strdup(path2);
        if (cb->datapath == NULL) {
            err = MINUS_ERRNO;
            goto err2;
        }
        cb->datafd = -1;

        cb->dataf = fopen(cb->datapath, "w");
    } else {
        cb->datapath = NULL;
        cb->datafd = fd2;

        cb->dataf = fdopen(cb->datafd, "w");
    }
    if (cb->dataf == NULL) {
        err = MINUS_ERRNO;
        goto err3;
    }

    if (path3 != NULL) {
        cb->tracepath = strdup(path3);
        if (cb->tracepath == NULL) {
            err = MINUS_ERRNO;
            goto err4;
        }
        cb->tracefd = -1;

        cb->tracef = fopen(cb->tracepath, "w");
    } else if (fd3 != -1) {
        cb->tracepath = NULL;
        cb->tracefd = fd3;

        cb->tracef = fdopen(cb->tracefd, "w");
    } else {
        cb->tracepath = NULL;
        cb->tracefd = -1;
        cb->tracef = NULL;
        goto end;
    }
    if (cb->tracef == NULL) {
        err = MINUS_ERRNO;
        goto err5;
    }

end:
    return 0;

err5:
    free(cb->tracepath);
err4:
    fclose(cb->dataf);
err3:
    free(cb->datapath);
err2:
    fclose(cb->f);
err1:
    free(cb->path);
    fprintf(stderr, "Error opening output file: %s\n", sys_strerror(-err));
    return err;
}

static int
parse_cmdline(int argc, char **argv, struct ctx *ctx)
{
    char *sep1, *sep2, *sep3;
    int err;
    int fd1, fd2, fd3;

    if (argc != 2) {
        fprintf(stderr, "%s\n",
                argc < 2
                ? "Must specify output files"
                : "Unrecognized arguments");
        return -E_INVAL;
    }

    sep1 = argv[1] + strcspn(argv[1], "#:");
    if (*sep1 == '\0')
        return -E_INVAL;
    fd1 = *sep1 == '#';
    *sep1++ = '\0';

    sep2 = strchr(sep1, ';');
    if (sep2 == NULL)
        return -E_INVAL;
    *sep2++ = '\0';
    if (*sep2 == '#') {
        fd2 = 1;
        ++sep2;
    } else
        fd2 = 0;

    sep3 = strchr(sep2, ';');
    if (sep3 == NULL)
        fd3 = 0;
    else {
        *sep3++ = '\0';
        if (*sep3 == '#') {
            fd3 = 1;
            ++sep3;
        } else
            fd3 = 0;
    }

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

    if (fd3) {
        fd3 = strtoimax(sep3, NULL, 10);
        sep3 = NULL;
    } else
        fd3 = -1;

    err = parse_elem_spec(sep1, fd1, sep2, fd2, sep3, fd3, &ctx->cb);
    if (!err)
        ctx->export = strcmp(argv[1], "e") == 0;

    return err;
}

static int
syncf(int fd)
{
    int err;

    if (sys_fsync_nocancel(fd) == -1) {
        err = sys_errno;
        if (err != E_BADF && err != E_INVAL && err != E_NOTSUP)
            return -err;
    }

    return 0;
}

static int
free_cb(struct cb *cb)
{
    int err = 0, tmp;

    if (cb->tracef != NULL) {
        err = syncf(fileno(cb->tracef));

        if (fclose(cb->tracef) == EOF)
            err = MINUS_ERRNO;

        if (err) {
            fprintf(stderr, "Error closing output file: %s\n",
                    sys_strerror(-err));
        }

        free(cb->tracepath);
    }

    tmp = syncf(fileno(cb->dataf));
    if (tmp != 0)
        err = tmp;

    if (fclose(cb->dataf) == EOF)
        err = MINUS_ERRNO;

    if (err)
        fprintf(stderr, "Error closing output file: %s\n", sys_strerror(-err));

    free(cb->datapath);

    tmp = syncf(fileno(cb->f));
    if (tmp != 0)
        err = tmp;

    if (fclose(cb->f) == EOF)
        err = MINUS_ERRNO;

    if (err)
        fprintf(stderr, "Error closing output file: %s\n", sys_strerror(-err));

    free(cb->path);

    return err;
}

static int
_cvt_utf8_to_string(json_value_t *dst, const char *data, size_t len)
{
    char *buf;
    const char *src;
    int err;
    json_value_t ret;
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

    err = json_value_init(&ret, JSON_STRING_T);
    if (err)
        goto end;

    err = json_string_set_value(ret, str);
    if (err)
        json_value_put(ret);
    else
        *dst = ret;

end:
    free(str);
    return -sys_maperror(-err);

err2:
    free(str);
err1:
    free(buf);
    return err;
}

static int
cvt_integer_to_number(json_value_t *dst, matroska_metadata_t *src, size_t len,
                      const char *name)
{
    int err;
    json_value_t ret;

    (void)len;
    (void)name;

    err = json_value_init(&ret, JSON_NUMBER_T);
    if (err)
        err = -sys_maperror(-err);
    else {
        json_numeric_set(ret, src->integer);
        *dst = ret;
    }

    return err;
}

static int
cvt_uinteger_to_number(json_value_t *dst, matroska_metadata_t *src, size_t len,
                       const char *name)
{
    int err;
    json_value_t ret;

    (void)len;
    (void)name;

    err = json_value_init(&ret, JSON_NUMBER_T);
    if (err)
        err = -sys_maperror(-err);
    else {
        json_numeric_set(ret, src->uinteger);
        *dst = ret;
    }

    return err;
}

static int
cvt_float_to_number(json_value_t *dst, matroska_metadata_t *src, size_t len,
                    const char *name)
{
    int err;
    json_value_t ret;

    (void)len;
    (void)name;

    err = json_value_init(&ret, JSON_NUMBER_T);
    if (err)
        err = -sys_maperror(-err);
    else {
        json_numeric_set(ret, src->dbl);
        *dst = ret;
    }

    return err;
}

static int
cvt_utf8_to_string(json_value_t *dst, matroska_metadata_t *src, size_t len,
                   const char *name)
{
    (void)len;
    (void)name;

    return _cvt_utf8_to_string(dst, src->data, src->len);
}

static int
cvt_date_to_string(json_value_t *dst, matroska_metadata_t *src, size_t len,
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
            return -E_OVERFLOW;
    } else if ((int64_t)(TIME_T_MIN - reftm) > s)
        return -E_OVERFLOW;

    date = reftm + s;

    gmtime_r(&date, &tm);

    len = strftime(buf, sizeof(buf), "%Y %m %d %H %M %S", &tm);
    len += snprintf(buf + len, sizeof(buf) - len, " %09" PRIi64,
                    src->integer % TIME_GRAN);

    return _cvt_utf8_to_string(dst, buf, len + 1);
}

static int
cvt_master_to_number(json_value_t *dst, matroska_metadata_t *src, size_t len,
                     const char *name)
{
    int err;
    json_value_t ret;

    (void)src;
    (void)name;

    err = json_value_init(&ret, JSON_NUMBER_T);
    if (err)
        err = -sys_maperror(-err);
    else {
        json_numeric_set(ret, len);
        *dst = ret;
    }

    return err;
}

static int
cvt_binary_to_string(json_value_t *dst, matroska_metadata_t *src, size_t len,
                     const char *name)
{
    char *s, *str;
    int err;
    size_t i;
    size_t slen;

    (void)name;

    if (len > LEN_MAX) {
        json_value_t ret;

        err = json_value_init(&ret, JSON_NULL_T);
        if (err)
            err = -sys_maperror(-err);
        else
            *dst = ret;
        return err;
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
            err = -E_NAMETOOLONG;
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
    const struct elem_data *data = NULL;
    int (*fn)(json_value_t *, matroska_metadata_t *, size_t, const char *);
    int block;
    int new_val;
    int res;
    json_kv_pair_t elm;
    json_value_t jv;
    matroska_metadata_t valbuf;
    mbstate_t s;
    size_t buflen;
    struct ctx *ctxp = ctx;
    wchar_t *k;

    static int (*const fns[])(json_value_t *, matroska_metadata_t *, size_t,
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

        res = json_value_init(&jv, JSON_NULL_T);
        if (res != 0)
            goto err1;

        res = json_array_push(ctxp->cb.jv, jv);
        json_value_put(jv);
        if (res != 0)
            goto err1;
    }

    buflen = strlen(id) + 1;

    idbuf = malloc(2 * buflen);
    if (idbuf == NULL)
        return MINUS_ERRNO;
    value = idbuf + buflen;

    if (sscanf(id, "%s -> %s", idbuf, value) != 2)
        goto end1;

    new_val = ctxp->first_fragment;
    block = strcmp("Block", value) == 0 || strcmp("SimpleBlock", value) == 0;

    if (flags & MATROSKA_METADATA_FLAG_FRAGMENT) {
        if (len <= LEN_MAX) {
            if (new_val) {
                buf = realloc(ctxp->data, len);
                if (buf == NULL) {
                    res = MINUS_ERRNO;
                    goto err5;
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
            if (!block)
                goto end2;
        } else {
            ctxp->len = 0;
            ctxp->first_fragment = 1;

            if (!block && len <= LEN_MAX) {
                valbuf.data = buf;
                valbuf.len = len;
            }
        }

        if (len <= LEN_MAX)
            val = &valbuf;
    }

    if (new_val && ctxp->cb.elm != NULL) {
        json_value_put(ctxp->cb.elm);
        ctxp->cb.elm = NULL;
    }

    res = parser_look_up(flags & MATROSKA_METADATA_FLAG_HEADER
                         ? EBML_PARSER : MATROSKA_PARSER,
                         idbuf, &data, NULL);
    if (res != 1) {
        if (res != 0)
            goto err5;
        goto end2;
    }

    if (data->etype >= ARRAY_SIZE(fns)) {
        res = -E_IO;
        goto err5;
    }
    fn = fns[data->etype];
    if (fn == NULL) {
        res = -E_IO;
        goto err5;
    }

    buflen = 16;
    k = malloc(buflen * sizeof(*k));
    if (k == NULL) {
        res = MINUS_ERRNO;
        goto err5;
    }

    for (;;) {
        wchar_t *tmp;

        id = ctxp->export ? idbuf : value;
        if (mbsrtowcs(k, &id, buflen, memset(&s, 0, sizeof(s))) == (size_t)-1) {
            res = MINUS_ERRNO;
            goto err6;
        }
        if (id == NULL)
            break;
        buflen *= 2;
        tmp = realloc(k, buflen * sizeof(*tmp));
        if (tmp == NULL) {
            res = MINUS_ERRNO;
            goto err6;
        }
        k = tmp;
    }

    res = json_value_init(&jv, JSON_OBJECT_T);
    if (res != 0)
        goto err2;

    res = (*fn)(&elm.v, val, len, value);
    if (res != 0)
        goto err7;

    elm.k = k;

    res = json_object_insert(jv, &elm);
    if (res != 0)
        goto err4;
    k = NULL;

    json_value_put(elm.v);

    if (!block) {
        res = json_value_init(&elm.v, JSON_NUMBER_T);
        if (res != 0)
            goto err3;
        json_numeric_set(elm.v, hdrlen);

        k = wcsdup(L"hdr_len");
        if (k == NULL) {
            res = MINUS_ERRNO;
            goto err8;
        }

        elm.k = k;

        res = json_object_insert(jv, &elm);
        if (res != 0)
            goto err4;

        json_value_put(elm.v);

        if (data->etype != ETYPE_MASTER) {
            res = json_value_init(&elm.v, JSON_NUMBER_T);
            if (res != 0)
                goto err3;
            json_numeric_set(elm.v, len);

            k = wcsdup(L"data_len");
            if (k == NULL) {
                res = MINUS_ERRNO;
                goto err8;
            }

            elm.k = k;

            res = json_object_insert(jv, &elm);
            if (res != 0)
                goto err4;
            k = NULL;

            json_value_put(elm.v);
        }
    }

    res = json_array_push(ctxp->cb.jv, jv);
    if (res != 0)
        goto err3;

    if (new_val && block)
        ctxp->cb.elm = jv;
    else
        json_value_put(jv);

end2:
    if (new_val && !block) {
        ctxp->totmdlen += hdrlen;
        if (data == NULL || data->etype != ETYPE_MASTER)
            ctxp->totmdlen += len;
    }
end1:
    free(idbuf);
    return 0;

err8:
    json_value_put(elm.v);
err7:
    json_value_put(jv);
err6:
    free(k);
err5:
    free(idbuf);
    return res;

err4:
    json_value_put(elm.v);
err3:
    json_value_put(jv);
err2:
    free(k);
    free(idbuf);
err1:
    return -sys_maperror(-res);
}

static int
bitstream_cb(uint64_t trackno, const void *buf, size_t len, size_t framelen,
             size_t totlen, size_t hdrlen, size_t num_logical_bytes, off_t off,
             int16_t ts, int new_frame, int keyframe, void *ctx)
{
    int err;
    json_kv_pair_t elm;
    json_value_t jv;
    struct ctx *ctxp = ctx;
    wchar_t *k;

    (void)totlen;

    jv = ctxp->cb.elm;

/*    fprintf(stderr, "trackno %" PRIu64 ", ts %" PRIi16 ", keyframe %d, %p\n",
            trackno, ts, keyframe, jv);
*/
    if (jv == NULL) {
        if (!new_frame)
            goto end;

        fprintf(stderr, "New frame in same block at %" PRIi64 " byte%s\n",
                PL(ctxp->off));

        err = json_value_init(&jv, JSON_OBJECT_T);
        if (err)
            goto err1;

        err = json_array_push(ctxp->cb.jv, jv);
        if (err)
            goto err1;

        err = json_value_init(&elm.v, JSON_BOOLEAN_T);
        if (err)
            goto err1;
        json_boolean_set(elm.v, 1);

        k = wcsdup(L"continued");
        if (k == NULL)
            goto err3;
        elm.k = k;

        err = json_object_insert(jv, &elm);
        json_value_put(elm.v);
        if (err)
            goto err2;
    } else
        new_frame = 0;

    if (ctxp->remlen != 0) {
        fputs("Synchronization error: total length of frames in block output "
              "too small\n",
              stderr);
        return -E_IO;
    }
    ctxp->remlen = framelen;

    err = json_value_init(&elm.v, JSON_NUMBER_T);
    if (err)
        goto err1;
    json_numeric_set(elm.v, trackno);

    k = wcsdup(L"trackno");
    if (k == NULL)
        goto err3;
    elm.k = k;

    err = json_object_insert(jv, &elm);
    json_value_put(elm.v);
    if (err)
        goto err2;

    err = json_value_init(&elm.v, JSON_NUMBER_T);
    if (err)
        goto err1;
    json_numeric_set(elm.v, ts);

    k = wcsdup(L"ts");
    if (k == NULL)
        goto err3;
    elm.k = k;

    err = json_object_insert(jv, &elm);
    json_value_put(elm.v);
    if (err)
        goto err2;

    err = json_value_init(&elm.v, JSON_BOOLEAN_T);
    if (err)
        goto err1;
    json_boolean_set(elm.v, keyframe);

    k = wcsdup(L"keyframe");
    if (k == NULL)
        goto err3;
    elm.k = k;

    err = json_object_insert(jv, &elm);
    json_value_put(elm.v);
    if (err)
        goto err2;

    err = json_value_init(&elm.v, JSON_NUMBER_T);
    if (err)
        goto err1;
    json_numeric_set(elm.v, ctxp->off);

    k = wcsdup(L"data_offset");
    if (k == NULL)
        goto err3;
    elm.k = k;

    err = json_object_insert(jv, &elm);
    json_value_put(elm.v);
    if (err)
        goto err2;

    err = json_value_init(&elm.v, JSON_NUMBER_T);
    if (err)
        goto err1;
    json_numeric_set(elm.v, hdrlen);

    k = wcsdup(L"hdr_len");
    if (k == NULL)
        goto err3;
    elm.k = k;

    err = json_object_insert(jv, &elm);
    json_value_put(elm.v);
    if (err)
        goto err2;

    if (!new_frame) {
        ctxp->totmdlen += hdrlen;

        off -= ctxp->totmdlen;
        off += ctxp->totlogbytes;
        if (ctxp->baseoff == -1) {
            if (off != 0) {
                fprintf(stderr, "Synchronization error: nonzero base offset (%"
                                PRIi64 " byte%s)\n",
                        PL(off));
                return -E_IO;
            }
            ctxp->baseoff = 0;
        }

        if (off != ctxp->off) {
            fprintf(stderr, "Synchronization error: offset %" PRIi64 " byte%s "
                            "(%+" PRIi64 " byte%s)\n",
                    PL(off), PL(off - ctxp->off));
            return -E_IO;
        }
    }

    err = json_value_init(&elm.v, JSON_NUMBER_T);
    if (err)
        goto err1;
    json_numeric_set(elm.v, framelen);

    k = wcsdup(L"data_len");
    if (k == NULL)
        goto err3;
    elm.k = k;

    err = json_object_insert(jv, &elm);
    json_value_put(elm.v);
    if (err)
        goto err2;

    ctxp->off += framelen;
    if (!new_frame)
        ctxp->totlogbytes += num_logical_bytes;

    ctxp->cb.elm = NULL;
    json_value_put(jv);

end:

    off = ftello(ctxp->cb.dataf);
    if (off == -1)
        return MINUS_ERRNO;
    if (fwrite(buf, 1, len, ctxp->cb.dataf) != len)
        goto err4;

    if (len > ctxp->remlen) {
        fputs("Synchronization error: total length of frames in block output "
              "too large\n",
              stderr);
        return -E_IO;
    }
    ctxp->remlen -= len;

    if (ctxp->cb.tracef == NULL)
        return 0;

    if (ctxp->tracebufsz < framelen) {
        char *tmp;

        tmp = realloc(ctxp->tracebuf, framelen);
        if (tmp == NULL)
            return MINUS_ERRNO;
        ctxp->tracebuf = tmp;
        ctxp->tracebufsz = framelen;
    }

    memcpy(ctxp->tracebuf + ctxp->tracebuflen, buf, len);

    ctxp->tracebuflen += len;
    assert(ctxp->tracebuflen <= framelen);

    if (ctxp->tracebuflen == framelen) {
        struct adler32_ctx *cctx;
        uint32_t sum;

        cctx = adler32_init();
        if (cctx == NULL)
            return -E_NOMEM;
        err = adler32_update(cctx, ctxp->tracebuf, ctxp->tracebuflen);
        if (err) {
            adler32_end(cctx, NULL);
            goto err1;
        }
        err = adler32_end(cctx, &sum);
        if (err)
            goto err1;

        if (fprintf(ctxp->cb.tracef,
                    "%10" PRIi64 "\t%7zu\t0x%08" PRIx32 "\n",
                    off + len - ctxp->tracebuflen, ctxp->tracebuflen, sum)
            < 0)
            goto err4;

        ctxp->tracebuflen = 0;
    }

    return 0;

err4:
    fprintf(stderr, "Error writing output: %s\n", strerror(errno));
    return -E_IO;

err3:
    json_value_put(elm.v);
    return -E_NOMEM;

err2:
    free(k);
err1:
    return -sys_maperror(-err);
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
cvt_mkv(int infd, struct ctx *ctx)
{
    const char *errmsg;
    int res;
    json_value_t jv;
    matroska_hdl_t hdl;
    matroska_bitstream_cb_t cb;
    matroska_metadata_cb_t metacb;
    struct matroska_file_args args;

    errmsg = "Error initializing";

    errno = 0;
    if (isatty(fileno(ctx->cb.dataf)) == 1) {
        res = -E_INVAL;
        errmsg = NULL;
        fputs("Standard output refers to a terminal device\n", stderr);
        goto err1;
    }
    res = en;
    switch (res) {
    case E_NOTTY:
    case E_NOSYS:
    case 0:
        break;
    default:
        res = -res;
        goto err1;
    }

    res = json_init();
    if (res != 0)
        goto err1;

    res = json_value_init(&jv, JSON_ARRAY_T);
    if (res != 0)
        goto err2;

    metacb.output_cb = &metadata_cb;
    cb.output_cb = &bitstream_cb;
    args.fd = infd;
    args.pathname = NULL;
    res = matroska_open(&hdl, NULL, &metacb, &cb, MATROSKA_OPEN_FLAG_RDONLY,
                        &args, ctx);
    if (res != 0) {
        errmsg = "Error opening input file";
        goto err3;
    }

    ctx->remlen = 0;
    ctx->baseoff = -1;
    ctx->off = 0;
    ctx->totmdlen = 0;
    ctx->totlogbytes = 0;

    ctx->tracebuf = NULL;
    ctx->tracebuflen = ctx->tracebufsz = 0;

    ctx->header = 1;
    ctx->first_fragment = 1;
    ctx->cb.jv = jv;

    res = matroska_read(NULL, hdl,
                        MATROSKA_READ_FLAG_HEADER | MATROSKA_READ_FLAG_MASTER);
    if (ctx->cb.elm != NULL)
        json_value_put(ctx->cb.elm);
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

    if (ctx->remlen != 0) {
        fputs("Synchronization error: total length of frames in block output "
              "too small\n",
              stderr);
        res = -E_IO;
        goto err3;
    }

    res = json_write_text(NULL, NULL, jv, &json_wr_cb, ctx->cb.f, 1);
    if (res != 0) {
        errmsg = "Error writing output";
        goto err2;
    }

    json_value_put(jv);

    json_deinit();

    return 0;

err4:
    matroska_close(hdl);
err3:
    json_value_put(jv);
err2:
    json_deinit();
err1:
    if (res > 0)
        res = matroska_print_err(stderr, res);
    if (errmsg != NULL)
        fprintf(stderr, "%s: %s\n", errmsg, sys_strerror(-res));
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
                    "Data path %s, FD %d\n"
                    "Trace path %s, FD %d\n",
            ctx.cb.path == NULL ? "NULL" : ctx.cb.path, ctx.cb.fd,
            ctx.cb.datapath == NULL ? "NULL" : ctx.cb.datapath, ctx.cb.datafd,
            ctx.cb.tracepath == NULL ? "NULL" : ctx.cb.tracepath,
            ctx.cb.tracefd);

    err = cvt_mkv(STDIN_FILENO, &ctx);

    tmp = free_cb(&ctx.cb);
    if (tmp != 0)
        err = tmp;

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
