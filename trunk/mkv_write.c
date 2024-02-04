/*
 * mkv_write.c
 */

#include "common.h"
#include "matroska.h"
#include "parser.h"
#include "util.h"

#include <json.h>

#include <json/filters.h>

#include <checksums.h>
#include <strings_ext.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <wchar.h>

#include <sys/param.h>
#include <sys/types.h>

enum op {
    MULTIPLEX = 1,
    SEPARATE
};

struct cb {
    char        *path;
    int         fd;
    FILE        *f;
    json_val_t  jval;
    char        *datapath;
    int         datafd;
    FILE        *dataf;
    char        *tracepath;
    int         tracefd;
    FILE        *tracef;
};

struct ctx {
    struct cb   cb;
    int         import;
    char        *basenm;
    size_t      len;
    off_t       lastoff;
    size_t      tothdrsz;
    size_t      lastsz;
    uint64_t    trackno;
    int16_t     ts;
    int         keyframe;
};

struct master_elem_data {
    size_t len;
};

struct cluster_state {
    struct master_elem_data *cluster_mdata;
    int                     new_cluster;
};

#define TM_YEAR(year) ((year) - 1900)

#define REFERENCE_TIME \
    { \
        .tm_mday    = 1, \
        .tm_mon     = 1, \
        .tm_year    = TM_YEAR(2001), \
        .tm_isdst   = -1 \
    }

#define TIME_GRAN 1000000000

#define _HASH_MD_ELEM(c0, len) ((unsigned char)(c0) * 16 + MIN(len, 15))

#define HASH_MD_ELEM(str) _HASH_MD_ELEM((str)[0], strlen(str))

static const char *const md_elem[] = {
    [1608] = "data_len",
    [1611] = "data_offset",
    [1671] = "hdr_len",
    [1720] = "keyframe",
    [1863] = "trackno",
    [1858] = "ts"
};

typedef int cvt_jval_to_metadata_fn_t(matroska_metadata_t *, size_t *,
                                      json_val_t, json_val_t, const char *,
                                      struct ctx *);

int parser_look_up(const struct parser *, const char *,
                   const struct elem_data **, const struct elem_data **);

int matroska_print_err(FILE *, int);

static int parse_file_spec(const char *, int, const char *, int, const char *,
                           int, struct cb *);

static int parse_cmdline(int, char **, enum op *, struct ctx *);

static unsigned char from_hex(char);

static int free_cb(struct cb *);

static size_t json_read_cb(char *, size_t, size_t, void *);

static int _cvt_string_to_utf8(char **, json_val_t);

static int cvt_block_data(json_val_t, struct ctx *);

static cvt_jval_to_metadata_fn_t cvt_number_to_integer;
static cvt_jval_to_metadata_fn_t cvt_number_to_uinteger;
static cvt_jval_to_metadata_fn_t cvt_number_to_float;
static cvt_jval_to_metadata_fn_t cvt_string_to_utf8;
static cvt_jval_to_metadata_fn_t cvt_string_to_date;
static cvt_jval_to_metadata_fn_t cvt_number_to_master;
static cvt_jval_to_metadata_fn_t cvt_string_to_binary;

static int master_cb(const char *, size_t, size_t, void *, void *);
static void master_free_cb(void *, void *);

static matroska_bitstream_input_cb_t bitstream_cb;

static int process_block_data(json_val_t, struct ctx *);

static int write_mkv(int, struct ctx *);

static int separate_data(int, struct ctx *);

static int
parse_file_spec(const char *path1, int fd1, const char *path2, int fd2,
                const char *path3, int fd3, struct cb *cb)
{
    int err;

    if (path1 != NULL) {
        cb->path = strdup(path1);
        if (cb->path == NULL)
            return MINUS_ERRNO;

        cb->fd = open(path1, O_WRONLY);
        if (cb->fd == -1) {
            err = MINUS_ERRNO;
            goto err1;
        }
    } else {
        cb->path = NULL;
        cb->fd = fd1;
    }

    if (path2 != NULL) {
        cb->datapath = strdup(path2);
        if (cb->datapath == NULL) {
            err = MINUS_ERRNO;
            goto err2;
        }
        cb->datafd = -1;

        cb->dataf = fopen(cb->datapath, "r");
    } else {
        cb->datapath = NULL;
        cb->datafd = fd2;

        cb->dataf = fdopen(cb->datafd, "r");
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
    if (cb->fd != -1)
        close(cb->fd);
err1:
    free(cb->path);
    fprintf(stderr, "Error opening input file: %s\n", strerror(-err));
    return err;
}

static int
parse_cmdline(int argc, char **argv, enum op *op, struct ctx *ctx)
{
    char *sep1, *sep2, *sep3;
    int err;
    int fd1, fd2, fd3;

    static const enum op ops[256] = {
        [(unsigned char)'m'] = MULTIPLEX,
        [(unsigned char)'s'] = SEPARATE
    };

    for (;;) {
        int opt = getopt(argc, argv, "ms:");

        if (opt == -1)
            break;

        if (opt == 's') {
            free(ctx->basenm);
            ctx->basenm = strdup(optarg);
            if (ctx->basenm == NULL)
                return MINUS_ERRNO;
        }
        *op = ops[opt];
    }
    argc -= optind;
    argv += optind;

    if (argc != 1) {
        fprintf(stderr, "%s\n",
                argc < 1
                ? "Must specify input files"
                : "Unrecognized arguments");
        return -EINVAL;
    }

    sep1 = argv[0] + strcspn(argv[0], "#:");
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

    err = parse_file_spec(sep1, fd1, sep2, fd2, sep3, fd3, &ctx->cb);
    if (!err)
        ctx->import = strcmp(argv[0], "i") == 0;

    return err;
}

static unsigned char
from_hex(char c)
{
    return c - (isdigit(c) ? '0' : 'a' - 10);
}

static int
free_cb(struct cb *cb)
{
    int err = 0;

    if (cb->tracef != NULL) {
        if (fsync(fileno(cb->tracef)) == -1
            && errno != EBADF && errno != EINVAL && errno != ENOTSUP)
            err = MINUS_ERRNO;

        if (fclose(cb->tracef) == EOF)
            err = MINUS_ERRNO;

        if (err)
            fprintf(stderr, "Error closing output file: %s\n", strerror(-err));

        free(cb->tracepath);
    }

    fclose(cb->dataf);
    free(cb->datapath);

    if (cb->fd != -1)
        close(cb->fd);
    free(cb->path);

    return err;
}

static size_t
json_read_cb(char *buf, size_t off, size_t len, void *ctx)
{
    FILE *f = ctx;
    size_t ret;

    (void)off;

    ret = fread(buf, 1, len, f);
    return ret == 0 && !feof(f) ? (size_t)-1 : ret;
}

static int
_cvt_string_to_utf8(char **dst, json_val_t src)
{
    char *str;
    int err;
    size_t slen;
    wchar_t *val;

    if (json_val_get_type(src) != JSON_TYPE_STRING)
        return -EILSEQ;

    val = json_val_string_get(src);
    if (val == NULL)
        return MINUS_ERRNO;

    slen = 16;
    str = malloc(slen);
    if (str == NULL) {
        err = MINUS_ERRNO;
        goto err1;
    }

    for (;;) {
        char *tmp;
        const wchar_t *srcp;
        mbstate_t s;

        srcp = val;
        if (wcsrtombs(str, &srcp, slen, memset(&s, 0, sizeof(s)))
            == (size_t)-1) {
            err = MINUS_ERRNO;
            goto err2;
        }
        if (srcp == NULL)
            break;
        slen *= 2;
        tmp = realloc(str, slen);
        if (tmp == NULL) {
            err = MINUS_ERRNO;
            goto err2;
        }
        str = tmp;
    }

    free(val);

    *dst = str;
    return 0;

err2:
    free(str);
err1:
    free(val);
    return err;
}

static int
cvt_block_data(json_val_t jval, struct ctx *ctx)
{
    int res;
    json_object_elem_t elem;
    uint64_t off;
    uint64_t hdrsz, sz;

    res = json_val_object_get_elem_by_key(jval, L"trackno", &elem);
    if (res != 0)
        return res == -EINVAL ? 1 : res;
    if (json_val_get_type(elem.value) != JSON_TYPE_NUMBER)
        return -EILSEQ;
    ctx->trackno = json_val_numeric_get(elem.value);
    json_val_free(elem.value);

    fprintf(stderr, "Track number: %" PRIu64 "\n", ctx->trackno);

    res = json_val_object_get_elem_by_key(jval, L"hdr_len", &elem);
    if (res != 0)
        return res;
    if (json_val_get_type(elem.value) != JSON_TYPE_NUMBER)
        return -EILSEQ;
    hdrsz = json_val_numeric_get(elem.value);
    json_val_free(elem.value);

    fprintf(stderr, "Header length: %" PRIu64 " byte%s\n", PL(hdrsz));

    res = json_val_object_get_elem_by_key(jval, L"data_offset", &elem);
    if (res != 0)
        return res;
    if (json_val_get_type(elem.value) != JSON_TYPE_NUMBER)
        return -EILSEQ;
    off = json_val_numeric_get(elem.value);
    json_val_free(elem.value);

    if (ctx->lastoff >= 0) {
        size_t disp = off - ctx->lastoff;
        size_t lastsz = ctx->lastsz;

        if (disp != lastsz) {
            fprintf(stderr, "Synchronization error: displacement %zu byte%s "
                            "(%+" PRIi64 " byte%s)\n",
                    PL(disp), PL((int64_t)disp - (int64_t)lastsz));
            return -EILSEQ;
        }
    }

    fprintf(stderr, "Data offset: %" PRIu64 " byte%s\n", PL(off));

    res = json_val_object_get_elem_by_key(jval, L"data_len", &elem);
    if (res != 0)
        return res;
    if (json_val_get_type(elem.value) != JSON_TYPE_NUMBER)
        return -EILSEQ;
    sz = json_val_numeric_get(elem.value);
    json_val_free(elem.value);

    fprintf(stderr, "Data length: %" PRIu64 " byte%s\n", PL(sz));

    res = json_val_object_get_elem_by_key(jval, L"keyframe", &elem);
    if (res != 0)
        return res;
    if (json_val_get_type(elem.value) != JSON_TYPE_BOOLEAN)
        return -EILSEQ;
    ctx->keyframe = json_val_numeric_get(elem.value);
    json_val_free(elem.value);

    fprintf(stderr, "Keyframe: %d\n", ctx->keyframe);

    res = json_val_object_get_elem_by_key(jval, L"ts", &elem);
    if (res != 0)
        return res;
    if (json_val_get_type(elem.value) != JSON_TYPE_NUMBER)
        return -EILSEQ;
    ctx->ts = json_val_numeric_get(elem.value);
    json_val_free(elem.value);

    fprintf(stderr, "Timestamp: %" PRIi16 "\n", ctx->ts);

    ctx->lastoff = off;
    ctx->tothdrsz += hdrsz;
    ctx->lastsz = sz;

    return 0;
}

static int
cvt_number_to_integer(matroska_metadata_t *dst, size_t *len, json_val_t obj,
                      json_val_t src, const char *name, struct ctx *ctx)
{
    (void)len;
    (void)obj;
    (void)name;
    (void)ctx;

    if (json_val_get_type(src) != JSON_TYPE_NUMBER)
        return -EILSEQ;

    dst->integer = json_val_numeric_get(src);

    return 0;
}

static int
cvt_number_to_uinteger(matroska_metadata_t *dst, size_t *len, json_val_t obj,
                       json_val_t src, const char *name, struct ctx *ctx)
{
    (void)len;
    (void)obj;
    (void)name;
    (void)ctx;

    if (json_val_get_type(src) != JSON_TYPE_NUMBER)
        return -EILSEQ;

    dst->uinteger = json_val_numeric_get(src);

    return 0;
}

static int
cvt_number_to_float(matroska_metadata_t *dst, size_t *len, json_val_t obj,
                    json_val_t src, const char *name, struct ctx *ctx)
{
    (void)len;
    (void)obj;
    (void)name;
    (void)ctx;

    if (json_val_get_type(src) != JSON_TYPE_NUMBER)
        return -EILSEQ;

    dst->dbl = json_val_numeric_get(src);

    return 0;
}

static int
cvt_string_to_utf8(matroska_metadata_t *dst, size_t *len, json_val_t obj,
                   json_val_t src, const char *name, struct ctx *ctx)
{
    char *str;
    int err;

    (void)len;
    (void)obj;
    (void)name;
    (void)ctx;

    err = _cvt_string_to_utf8(&str, src);
    if (!err) {
        dst->data = str;
        dst->len = strlen(str);
    }

    return err;
}

static int
cvt_string_to_date(matroska_metadata_t *dst, size_t *len, json_val_t obj,
                   json_val_t src, const char *name, struct ctx *ctx)
{
    char *str;
    int err;
    int64_t s;
    size_t slen;
    struct tm rtm = REFERENCE_TIME, tm;

    (void)len;
    (void)obj;
    (void)name;
    (void)ctx;

    err = _cvt_string_to_utf8(&str, src);
    if (err)
        return err;

    slen = strlen(str);

    slen -= 9;
    if (sscanf(str + slen, "%09" PRIi64, &s) != 1)
        goto err;
    str[slen] = '\0';

    if (_strptime(str, "%Y %m %d %H %M %S", memset(&tm, 0, sizeof(tm))) == NULL)
        goto err;

    free(str);

    dst->integer = (timegm(&tm) - mktime(&rtm)) * TIME_GRAN + s;

    return 0;

err:
    free(str);
    return -EILSEQ;
}

static int
cvt_number_to_master(matroska_metadata_t *dst, size_t *len, json_val_t obj,
                     json_val_t src, const char *name, struct ctx *ctx)
{
    (void)obj;
    (void)name;
    (void)ctx;

    if (json_val_get_type(src) != JSON_TYPE_NUMBER)
        return -EILSEQ;

    dst->len = *len = json_val_numeric_get(src);
    return 0;
}

static int
cvt_string_to_binary(matroska_metadata_t *dst, size_t *len, json_val_t obj,
                     json_val_t src, const char *name, struct ctx *ctx)
{
    char *s, *str;
    char *val;
    int res;
    size_t i;
    size_t vallen;

    (void)len;

    if (strcmp("SimpleBlock", name) == 0 || strcmp("Block", name) == 0) {
        res = cvt_block_data(obj, ctx);
        if (res == 0)
            dst->len = ctx->lastsz;
        return res;
    }

    res = _cvt_string_to_utf8(&str, src);
    if (res != 0)
        return res;

    vallen = strlen(str) / 2;

    val = malloc(vallen);
    if (val == NULL) {
        res = MINUS_ERRNO;
        goto err;
    }

    i = 0;
    s = str;
    for (;;) {
        char *b = &val[i];

        *b = from_hex(s[0]) << CHAR_BIT / 2 | from_hex(s[1]);

        if (++i == vallen)
            break;

        s += 2;
    }

    free(str);

    dst->data = val;
    dst->len = i;

    return 0;

err:
    free(str);
    return res;
}

static int
master_cb(const char *value, size_t hdrlen, size_t len, void *mdata, void *ctx)
{
    const struct master_elem_data *md = mdata;
    struct cluster_state *cstate = ctx;

    len -= hdrlen;

    if (len != md->len) {
        fprintf(stderr, "%s: length %zu byte%s (%+" PRIi64 " byte%s)\n",
                value, PL(len), PL((int64_t)len - (int64_t)md->len));
    }

    if (strcmp("pNvET -> Cluster", value) == 0 && !cstate->new_cluster)
        cstate->cluster_mdata = NULL;

    return 0;
}

static void
master_free_cb(void *mdata, void *ctx)
{
    (void)ctx;

    free(mdata);
}

static int
bitstream_cb(uint64_t *trackno, void *buf, ssize_t *nbytes, int16_t *ts,
             int *keyframe, void *ctx)
{
    FILE *f;
    int err;
    off_t off;
    size_t numread, toread;
    size_t ret;
    struct ctx *ctxp = ctx;

    toread = ctxp->lastsz;

    if (buf == NULL)
        goto end;

    f = ctxp->cb.dataf;

    off = ctxp->lastoff;

    if (fseeko(f, off, SEEK_SET) == -1)
        return MINUS_ERRNO;

    for (numread = 0; numread < toread; numread += ret) {
        ret = fread((char *)buf + numread, 1, toread - numread, f);
        if (ret == 0)
            return feof(f) ? -EILSEQ : MINUS_ERRNO;
    }

    if (ctxp->cb.tracef != NULL) {
        struct adler32_ctx *cctx;
        uint32_t sum;

        cctx = adler32_init();
        if (cctx == NULL)
            return -ENOMEM;
        err = adler32_update(cctx, buf, toread);
        if (err) {
            adler32_end(cctx, NULL);
            return err;
        }
        err = adler32_end(cctx, &sum);
        if (err)
            return err;

        if (fprintf(ctxp->cb.tracef, "%10" PRIi64 "\t%7zu\t0x%08" PRIx32 "\n",
                    off, toread, sum)
            < 0)
            return -EIO;
    }

    fprintf(stderr, "Offset: %" PRIi64 " byte%s\n"
                    "Length: %zu byte%s\n",
            PL(off), PL(toread));

end:
    if (trackno != NULL)
        *trackno = ctxp->trackno;
    *nbytes = toread;
    if (ts != NULL)
        *ts = ctxp->ts;
    if (keyframe != NULL)
        *keyframe = ctxp->keyframe;
    return 0;
}

static int
process_block_data(json_val_t jval, struct ctx *ctx)
{
    int res;
    json_object_elem_t elem;
    uint64_t off, sz;

    res = json_val_object_get_elem_by_key(jval, L"trackno", &elem);
    if (res != 0)
        return res == -EINVAL ? 0 : res;
    if (json_val_get_type(elem.value) != JSON_TYPE_NUMBER)
        return -EILSEQ;
    res = json_val_numeric_get(elem.value);
    json_val_free(elem.value);

    fprintf(stderr, "Track number: %d\n", res);

    res = json_val_object_get_elem_by_key(jval, L"hdr_len", &elem);
    if (res != 0)
        return res;
    if (json_val_get_type(elem.value) != JSON_TYPE_NUMBER)
        return -EILSEQ;
    sz = json_val_numeric_get(elem.value);
    json_val_free(elem.value);

    fprintf(stderr, "Header length: %" PRIu64 " byte%s\n", PL(sz));

    res = json_val_object_get_elem_by_key(jval, L"data_offset", &elem);
    if (res != 0)
        return res;
    if (json_val_get_type(elem.value) != JSON_TYPE_NUMBER)
        return -EILSEQ;
    off = json_val_numeric_get(elem.value);
    json_val_free(elem.value);

    if (ctx->lastoff >= 0) {
        size_t disp = off - ctx->lastoff;
        size_t lastsz = ctx->lastsz + sz;

        if (disp != lastsz) {
            fprintf(stderr, "Synchronization error: displacement %zu byte%s "
                            "(%+" PRIi64 " byte%s)\n",
                    PL(disp), PL((int64_t)disp - (int64_t)lastsz));
            return -EILSEQ;
        }
    }

    fprintf(stderr, "Data offset: %" PRIu64 " byte%s\n", PL(off));

    res = json_val_object_get_elem_by_key(jval, L"data_len", &elem);
    if (res != 0)
        return res;
    if (json_val_get_type(elem.value) != JSON_TYPE_NUMBER)
        return -EILSEQ;
    sz = json_val_numeric_get(elem.value);
    json_val_free(elem.value);

    fprintf(stderr, "Data length: %" PRIu64 " byte%s\n", PL(sz));

    res = json_val_object_get_elem_by_key(jval, L"keyframe", &elem);
    if (res != 0)
        return res;
    if (json_val_get_type(elem.value) != JSON_TYPE_BOOLEAN)
        return -EILSEQ;
    res = json_val_numeric_get(elem.value);
    json_val_free(elem.value);

    fprintf(stderr, "Keyframe: %d\n", res);

    res = json_val_object_get_elem_by_key(jval, L"ts", &elem);
    if (res != 0)
        return res;
    if (json_val_get_type(elem.value) != JSON_TYPE_NUMBER)
        return -EILSEQ;
    res = json_val_numeric_get(elem.value);
    json_val_free(elem.value);

    fprintf(stderr, "Timestamp: %d\n", res);

    ctx->lastoff = off;
    ctx->lastsz = sz;

    return 0;
}

static int
write_mkv(int infd, struct ctx *ctx)
{
    char *buf;
    const char *errmsg;
    const char *lastvalue;
    enum etype lastetype;
    FILE *f;
    int header;
    int i, j, m, n;
    int res;
    json_object_elem_t elem, obje;
    json_val_t e, jval;
    matroska_bitstream_cb_t cb;
    matroska_hdl_t hdl;
    struct cluster_state cstate;
    struct json_read_cb_ctx rctx;
    struct master_elem_data *mdata;
    struct matroska_file_args args;

    if (!ctx->import) {
        fputs("Only import operation is currently implemented\n", stderr);
        return -ENOSYS;
    }

    errno = 0;
    if (isatty(STDOUT_FILENO) == 1) {
        res = -EINVAL;
        errmsg = NULL;
        fputs("Standard output refers to a terminal device\n", stderr);
        goto err1;
    }
    switch (errno) {
    case ENOTTY:
    case ENOSYS:
    case 0:
        break;
    default:
        res = MINUS_ERRNO;
        errmsg = "Error initializing";
        goto err1;
    }

    errmsg = "Error opening input";

    infd = dup(infd);
    if (infd == -1) {
        res = MINUS_ERRNO;
        goto err1;
    }

    f = fdopen(infd, "r");
    if (f == NULL) {
        res = MINUS_ERRNO;
        close(infd);
        goto err1;
    }

    res = json_init();
    if (res != 0) {
        errmsg = "Error initializing";
        goto err2;
    }

    errmsg = "Error parsing input";

    json_read_cb_ctx_init(&rctx);
    rctx.read_cb = &json_read_cb;
    rctx.ctx = f;

    res = json_parse(NULL, 0, &json_read_cb_strip_comments, &rctx, &jval);
    if (res != 0)
        goto err3;

    if (json_val_get_type(jval) != JSON_TYPE_ARRAY) {
        res = -EILSEQ;
        goto err4;
    }

    cb.input_cb = &bitstream_cb;
    args.fd = STDOUT_FILENO;
    args.pathname = NULL;
    res = matroska_open(&hdl, NULL, NULL, &cb, 0, &args, ctx);
    if (res != 0)
        goto err4;

    ctx->lastoff = -1;
    header = 1;

    ctx->trackno = 0;
    ctx->ts = 0;
    ctx->keyframe = 1;

    buf = NULL;

    cstate.cluster_mdata = NULL;

    lastvalue = NULL;
    lastetype = ETYPE_NONE;

    m = json_val_array_get_num_elem(jval);

    for (i = 0; i < m; i++) {
        char *name;
        const char *value;
        const struct elem_data *data;
        cvt_jval_to_metadata_fn_t *fn;
        enum etype etype;
        int block, cluster, continued;
        matroska_metadata_t val;
        size_t buflen, hdrlen;
        size_t len;

        static cvt_jval_to_metadata_fn_t *const fns[] = {
            [ETYPE_INTEGER]     = &cvt_number_to_integer,
            [ETYPE_UINTEGER]    = &cvt_number_to_uinteger,
            [ETYPE_FLOAT]       = &cvt_number_to_float,
            [ETYPE_STRING]      = &cvt_string_to_utf8,
            [ETYPE_UTF8]        = &cvt_string_to_utf8,
            [ETYPE_DATE]        = &cvt_string_to_date,
            [ETYPE_MASTER]      = &cvt_number_to_master,
            [ETYPE_BINARY]      = &cvt_string_to_binary
        };

        e = json_val_array_get_elem(jval, i);
        if (e == NULL) {
            res = -EIO;
            goto err5;
        }

        switch (json_val_get_type(e)) {
        case JSON_TYPE_OBJECT:
            break;
        case JSON_TYPE_NULL:
            json_val_free(e);
            if (header) {
                header = 0;
                continue;
            }
            /* fallthrough */
        default:
            res = -EILSEQ;
            goto err5;
        }

        continued = 1;

        n = json_val_object_get_num_elem(e);

        for (j = 0; j < n; j++) {
            mbstate_t s;
            size_t idx;

            res = json_val_object_get_elem_by_idx(e, j, &elem);
            if (res != 0)
                goto err6;

            if (awcstombs(&buf, elem.key, memset(&s, 0, sizeof(s)))
                == (size_t)-1) {
                res = MINUS_ERRNO;
                goto err7;
            }

            idx = HASH_MD_ELEM(buf);
            if (idx >= ARRAY_SIZE(md_elem)) {
                continued = 0;
                break;
            }
            value = md_elem[idx];
            if (value == NULL || strcmp(value, buf) != 0) {
                continued = 0;
                break;
            }

            free(buf);
            buf = NULL;
            json_val_free(elem.value);
        }

        if (continued) {
            value = lastvalue;
            etype = lastetype;
        } else {
            res = parser_look_up(header ? EBML_PARSER : MATROSKA_PARSER, buf,
                                 &data, NULL);
            if (res != 1) {
                if (res == 0)
                    res = -EILSEQ;
                goto err7;
            }

            free(buf);
            buf = NULL;

            lastvalue = value = data->val;
            lastetype = etype = data->etype;
        }

        if (etype >= ARRAY_SIZE(fns)) {
            res = -EIO;
            goto err7;
        }
        fn = fns[etype];
        if (fn == NULL) {
            res = -EIO;
            goto err7;
        }

        buflen = strlen(value) + 1;

        buf = malloc(2 * buflen);
        if (buf == NULL) {
            res = MINUS_ERRNO;
            goto err7;
        }
        name = buf + buflen;

        if (sscanf(value, "%s -> %s", buf, name) != 2) {
            res = -EIO;
            goto err7;
        }

        res = (*fn)(&val, &len, e, elem.value, name, ctx);
        if (res < 0)
            goto err7;

        cluster = strcmp("Cluster", name) == 0;
        block = cluster
                ? 0
                : strcmp("SimpleBlock", name) == 0
                  || strcmp("Block", name) == 0;

        cstate.new_cluster = 0;
        if (etype == ETYPE_MASTER) {
            mdata = malloc(sizeof(*mdata));
            if (mdata == NULL) {
                res = MINUS_ERRNO;
                goto err7;
            }
            if (cluster) {
                mdata->len = 0;
                cstate.cluster_mdata = mdata;
                cstate.new_cluster = 1;
            } else
                mdata->len = len;
        } else
            mdata = NULL;

        if (!block) {
            res = json_val_object_get_elem_by_key(e, L"hdr_len", &obje);
            if (res != 0)
                goto err8;
            if (json_val_get_type(obje.value) != JSON_TYPE_NUMBER) {
                res = -EILSEQ;
                goto err9;
            }
            json_val_free(obje.value);

            if (etype != ETYPE_MASTER) {
                res = json_val_object_get_elem_by_key(e, L"data_len", &obje);
                if (res == 0) {
                    if (json_val_get_type(obje.value) != JSON_TYPE_NUMBER) {
                        res = -EILSEQ;
                        goto err9;
                    }
                    json_val_free(obje.value);
                } else if (res != -EINVAL)
                    goto err8;
            }
        }

        if (res == 0) {
            res = matroska_write(hdl, buf, &val, &len, &hdrlen, &master_cb,
                                 &master_free_cb, mdata, &cstate,
                                 header ? MATROSKA_WRITE_FLAG_HEADER : 0);
            if (res != 0)
                goto err8;

            if (!cluster && cstate.cluster_mdata != NULL)
                cstate.cluster_mdata->len += hdrlen + len;
        }

        free(buf);
        buf = NULL;
        if (!continued)
            json_val_free(elem.value);

        json_val_free(e);
    }

    res = matroska_close(hdl);
    ctx->cb.fd = -1;
    if (res != 0)
        goto err4;

    json_val_free(jval);

    json_end();

    fclose(f);

    return 0;

err9:
    json_val_free(obje.value);
err8:
    free(mdata);
err7:
    json_val_free(elem.value);
    free(buf);
err6:
    json_val_free(e);
err5:
    matroska_close(hdl);
    ctx->cb.fd = -1;
err4:
    json_val_free(jval);
err3:
    json_end();
err2:
    fclose(f);
err1:
    if (res > 0)
        res = matroska_print_err(stderr, res);
    if (errmsg != NULL)
        fprintf(stderr, "%s: %s\n", errmsg, strerror(-res));
    return res;
}

static int
separate_data(int infd, struct ctx *ctx)
{
    char *buf;
    const char *errmsg;
    FILE *f;
    int header;
    int i, j, m, n;
    int res;
    json_object_elem_t elem;
    json_val_t e, jval;
    struct json_read_cb_ctx rctx;

    (void)ctx;

    errmsg = "Error opening input";

    infd = dup(infd);
    if (infd == -1) {
        res = MINUS_ERRNO;
        goto err1;
    }

    f = fdopen(infd, "r");
    if (f == NULL) {
        res = MINUS_ERRNO;
        close(infd);
        goto err1;
    }

    res = json_init();
    if (res != 0) {
        errmsg = "Error initializing";
        goto err2;
    }

    errmsg = "Error parsing input";

    json_read_cb_ctx_init(&rctx);
    rctx.read_cb = &json_read_cb;
    rctx.ctx = f;

    res = json_parse(NULL, 0, &json_read_cb_strip_comments, &rctx, &jval);
    if (res != 0)
        goto err3;

    if (json_val_get_type(jval) != JSON_TYPE_ARRAY) {
        res = -EILSEQ;
        goto err4;
    }

    ctx->lastoff = -1;
    header = 1;

    m = json_val_array_get_num_elem(jval);

    for (i = 0; i < m; i++) {
        char *name;
        const char *value;
        const struct elem_data *data;
        size_t buflen;

        e = json_val_array_get_elem(jval, i);
        if (e == NULL) {
            res = -EIO;
            goto err4;
        }

        switch (json_val_get_type(e)) {
        case JSON_TYPE_OBJECT:
            break;
        case JSON_TYPE_NULL:
            json_val_free(e);
            if (header) {
                header = 0;
                continue;
            }
            /* fallthrough */
        default:
            res = -EILSEQ;
            goto err4;
        }

        n = json_val_object_get_num_elem(e);

        for (j = 0; j < n; j++) {
            mbstate_t s;
            size_t idx;

            res = json_val_object_get_elem_by_idx(e, j, &elem);
            if (res != 0)
                goto err6;

            if (awcstombs(&buf, elem.key, memset(&s, 0, sizeof(s)))
                == (size_t)-1) {
                res = MINUS_ERRNO;
                json_val_free(elem.value);
                goto err6;
            }

            idx = HASH_MD_ELEM(buf);
            if (idx >= ARRAY_SIZE(md_elem))
                break;
            value = md_elem[idx];
            if (value == NULL || strcmp(value, buf) != 0)
                break;

            free(buf);
            json_val_free(elem.value);
        }

        res = parser_look_up(header ? EBML_PARSER : MATROSKA_PARSER, buf, &data,
                             NULL);
        free(buf);
        if (res != 1) {
            if (res == 0)
                res = -EILSEQ;
            goto err5;
        }
        value = data->val;

        buflen = strlen(value) + 1;

        buf = malloc(2 * buflen);
        if (buf == NULL) {
            res = MINUS_ERRNO;
            goto err5;
        }
        name = buf + buflen;

        if (sscanf(value, "%s -> %s", buf, name) != 2) {
            res = -EIO;
            goto err6;
        }

        if (strcmp("SimpleBlock", name) == 0 || strcmp("Block", name) == 0) {
            res = process_block_data(e, ctx);
            if (res != 0)
                goto err6;
        } else {
            res = json_val_object_get_elem_by_key(e, L"hdr_len", &elem);
            if (res != 0)
                goto err6;
            if (json_val_get_type(elem.value) != JSON_TYPE_NUMBER) {
                res = -EILSEQ;
                goto err7;
            }
            json_val_free(elem.value);

            res = json_val_object_get_elem_by_key(e, L"data_len", &elem);
            if (res == 0) {
                if (json_val_get_type(elem.value) != JSON_TYPE_NUMBER) {
                    res = -EILSEQ;
                    goto err7;
                }
                json_val_free(elem.value);
            } else if (res != -EINVAL)
                goto err6;
        }

        free(buf);

        json_val_free(e);
    }

    json_val_free(jval);

    json_end();

    fclose(f);

    return 0;

err7:
    json_val_free(elem.value);
err6:
    free(buf);
err5:
    json_val_free(e);
err4:
    json_val_free(jval);
err3:
    json_end();
err2:
    fclose(f);
err1:
    fprintf(stderr, "%s: %s\n", errmsg, strerror(-res));
    return res;
}

int
main(int argc, char **argv)
{
    enum op op = MULTIPLEX;
    int err, tmp;
    struct ctx ctx = {0};

    if (parse_cmdline(argc, argv, &op, &ctx) != 0)
        return EXIT_FAILURE;

    err = (op == MULTIPLEX ? write_mkv : separate_data)(STDIN_FILENO, &ctx);

    tmp = free_cb(&ctx.cb);
    if (tmp != 0)
        err = tmp;

    return err ? EXIT_FAILURE : EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
