/*
 * mkv_catalog.c
 */

#define _FILE_OFFSET_BITS 64

#include "common.h"
#include "debug.h"
#include "util.h"

#include <json.h>

#include <json/filters.h>

#include <dbm_high_level.h>
#include <malloc_ext.h>
#include <strings_ext.h>

#include <files/acc_ctl.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <wchar.h>

#include <sys/param.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>

enum op {
    INDEX_JSON = 1,
    OUTPUT_JSON,
    UPDATE_INDEX,
    DELETE_FROM_INDEX,
    LIST_INDEX_ENTRIES,
    SEARCH_INDEX,
    PREFIX_SEARCH_INDEX,
    WALK_INDEX,
    DUMP_INDEX
};

struct config_args {
    const char *pathname;
};

struct config_ctx {
    int fd;
};

#define ROOT_ID 1

#define STRING_MAX 255

struct index_key_ctx {
    void    *last_key;
    int     last_key_valid;
};

struct index_ctx {
    struct dbh              *dbh;
    size_t                  key_size;
    db_hl_key_cmp_t         key_cmp;
    struct index_key_ctx    *key_ctx;
};

struct index_iter {
    db_hl_iter_t        iter;
    void                *srch_key;
    int                 srch_status;
    struct index_ctx    *ctx;
};

enum index_obj_type {
    TYPE_HEADER = 1,
    TYPE_INTERNAL,          /* look up by id */
    TYPE_EXTERNAL_NUMERIC,  /* look up by {id, numeric key} */
    TYPE_EXTERNAL_STRING,   /* look up by {id, string key} */
    TYPE_FREE_ID            /* look up by id */
};

struct index_key {
    uint32_t type;
    uint64_t id;
    union {
        uint64_t    numeric;
        uint8_t     string[STRING_MAX+1];
    };
} __attribute__((packed));

#define FMT_VERSION 1

struct index_obj_header {
    uint64_t    version;
    uint8_t     reserved[120];
} __attribute__((packed));

enum index_obj_subtype {
    TYPE_NULL = 1,
    TYPE_BOOLEAN,
    TYPE_OBJECT,
    TYPE_ARRAY,
    TYPE_NUMERIC,
    TYPE_STRING
};

struct index_obj_ent {
    uint32_t subtype;
    uint64_t id;
} __attribute__((packed));

struct index_obj_ent_data {
    uint64_t subtype;
    union {
        uint64_t    numeric;
        uint8_t     string[STRING_MAX+1];
    };
} __attribute__((packed));

#define FREE_ID_RANGE_SZ 2048

#define FREE_ID_LAST_USED 1 /* values in all following ranges are free */

struct index_obj_free_id {
    uint64_t    used_id[FREE_ID_RANGE_SZ/UINT64_BIT];
    uint8_t     flags;
} __attribute__((packed));

struct entry {
    struct index_key k;
    union {
        struct index_obj_ent        e;
        struct index_obj_ent_data   d;
    };
};

struct walk_index_ctx {
    FILE                *f;
    struct index_ctx    *ctx;
    int                 level;
};

struct output_json_ctx {
    struct walk_index_ctx   wctx;
    json_val_t              jval;
};

struct filter_state {
    int         state;
    uint64_t    start;
    uint64_t    end;
    json_val_t  jval;
    json_val_t  e[2];
};

struct attr_output_args {
    FILE    *f;
    int     fwidth;
};

#define METADATA_FILE_TEMPLATE "metadata_XXXXXX"

#define INDEX_PATHNAME "mkv_index.db"

#define INDEX_PATH_SEP "/"

static volatile sig_atomic_t sigpipe_recv;

static const struct {
    const char  *typestr;
    char        typechar;
} typedescs[] = {
    [TYPE_NULL]     = {"null",      't'},
    [TYPE_BOOLEAN]  = {"Boolean",   'b'},
    [TYPE_OBJECT]   = {"object",    'o'},
    [TYPE_ARRAY]    = {"array",     'a'},
    [TYPE_NUMERIC]  = {"numeric",   'n'},
    [TYPE_STRING]   = {"string",    's'}
};

static int enable_debugging_features(void);

static void pipe_handler(int);

static int set_up_signal_handlers(void);

static void print_usage(const char *);

static int parse_cmdline(int, char **, enum op *, char **, char **, int *);

static int print_verbose(FILE *, const char *, ...);

static int syncf(FILE *);

static int print_err(int);
static void clear_err(int);

static size_t json_read_cb(char *, size_t, size_t, void *);

static int uint64_cmp(uint64_t, uint64_t);

static int index_key_cmp(const void *, const void *, void *);

static int do_index_create(struct index_ctx **, const char *, mode_t, size_t,
                           db_hl_key_cmp_t);
static int do_index_open(struct index_ctx **, const char *, size_t,
                         db_hl_key_cmp_t, int);
static int do_index_close(struct index_ctx *);

static int do_index_insert(struct index_ctx *, const void *, const void *,
                           size_t);
static int do_index_replace(struct index_ctx *, const void *, const void *,
                            size_t);
static int do_index_look_up(struct index_ctx *, const void *, void *, void *,
                            size_t *);
static int do_index_delete(struct index_ctx *, const void *);

static int do_index_walk(struct index_ctx *, db_hl_walk_cb_t fn, void *);

static int do_index_iter_new(struct index_iter **, struct index_ctx *);
static int do_index_iter_free(struct index_iter *);
static int do_index_iter_get(struct index_iter *, void *, void *, size_t *);
static int do_index_iter_next(struct index_iter *);
/*static int do_index_iter_prev(struct index_iter *);*/
static int do_index_iter_search(struct index_iter *, const void *);

static int do_index_trans_new(struct index_ctx *);
static int do_index_trans_abort(struct index_ctx *);
static int do_index_trans_commit(struct index_ctx *);
static int do_index_sync(struct index_ctx *);

static int open_or_create(struct index_ctx **, const char *);

static void used_id_set(uint64_t *, uint64_t, uint64_t, int);
static uint64_t free_id_find(uint64_t *, uint64_t);

static int get_id(struct index_ctx *, uint64_t *);
/*static int release_id(struct index_ctx *, uint64_t, uint64_t);*/

static const char *tabs(int);

static int create_xref_marker(json_val_t *, struct filter_state *);

static int _index_object_value(struct index_ctx *, struct entry *, json_val_t,
                               int, int, struct filter_state *, int);

static int index_null_value(struct index_ctx *, struct entry *, json_val_t, int,
                            int, struct filter_state *, int);
static int index_boolean_value(struct index_ctx *, struct entry *, json_val_t,
                               int, int, struct filter_state *, int);
static int index_object_value(struct index_ctx *, struct entry *, json_val_t,
                              int, int, struct filter_state *, int);
static int index_array_value(struct index_ctx *, struct entry *, json_val_t,
                             int, int, struct filter_state *, int);
static int index_number_value(struct index_ctx *, struct entry *, json_val_t,
                              int, int, struct filter_state *, int);
static int index_string_value(struct index_ctx *, struct entry *, json_val_t,
                              int, int, struct filter_state *, int);

static int index_value(struct index_ctx *, struct entry *, json_val_t, int,
                       int, struct filter_state *, int);

static int path_look_up(struct index_ctx *, const char *, uint64_t *,
                        struct entry *, int, FILE *);

static int path_list_possible(struct index_ctx *, const struct index_key *,
                              FILE *);

static int get_ents(struct index_ctx *, uint64_t, uint64_t, int,
                    int (*)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                            uint64_t, const char *, const char *, void *),
                    void *);

static void print_attr(const struct attr_output_args *, const char *,
                       const char *, ...);

static size_t json_write_cb(const char *, size_t, size_t, void *);

static int list_index_entries_cb(uint64_t, uint64_t, uint64_t, uint64_t,
                                 uint64_t, uint64_t, const char *, const char *,
                                 void *);

static int delete_from_index_cb(uint64_t, uint64_t, uint64_t, uint64_t,
                                uint64_t, uint64_t, const char *, const char *,
                                void *);

static int output_index_cb(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                           uint64_t, const char *, const char *, void *);

static int walk_index_cb(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                         uint64_t, const char *, const char *, void *);

static int dump_index_cb(const void *, const void *, size_t, void *);

static int index_json(int, const char *, const char *);

static int output_json(const char *, const char *, int, int);

static int modify_index(const char *, const char *, int,
                        int (*)(struct index_ctx *, const char *, FILE *,
                                const char **));

static int output_index(const char *, const char *, int,
                        int (*)(struct index_ctx *, const char *, FILE *,
                                const char **));

static int delete_from_index(struct index_ctx *, const char *, FILE *,
                             const char **);

static int update_index(struct index_ctx *, const char *, FILE *,
                        const char **);

static int list_index_entries(struct index_ctx *, const char *, FILE *,
                              const char **);

static int search_index(struct index_ctx *, const char *, FILE *,
                        const char **);

static int prefix_search_index(struct index_ctx *, const char *, FILE *,
                               const char **);

static int walk_index(struct index_ctx *, const char *, FILE *, const char **);

static int dump_index(struct index_ctx *, const char *, FILE *, const char **);

static int
enable_debugging_features()
{
    int err;

    static const struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY
    };

    if (setrlimit(RLIMIT_CORE, &rlim) == -1) {
        err = MINUS_ERRNO;
        fprintf(stderr, "Couldn't set resource limit: %s\n", strerror(-err));
        return err;
    }

    return 0;
}

static void
pipe_handler(int signum)
{
    sigpipe_recv = 1;
    signal(signum, SIG_IGN);
}

static int
set_up_signal_handlers()
{
    int err;
    struct sigaction sa = {.sa_handler = &pipe_handler};

    if (sigaction(SIGPIPE, &sa, NULL) == -1) {
        err = MINUS_ERRNO;
        fprintf(stderr, "Couldn't set signal handler: %s\n", strerror(-err));
        return err;
    }

    return 0;
}

static void
print_usage(const char *prognm)
{
    printf("Usage: %s [options]\n"
           "       <{-D PATH|-d|-i NAME|-L PATH|-l PATH|-o NAME|-P PATH|-u PATH"
           "|-w}>\n"
           "\n"
           "    -D PATH recursively delete specified objects in index\n"
           "    -d      output all contents of index in linear format\n"
           "    -f PATH access index referenced by given pathname\n"
           "    -h      output help\n"
           "    -i NAME index JSON metadata under given filename\n"
           "    -L PATH list entries in specified JSON object or array\n"
           "    -l PATH search for specified object in index\n"
           "    -o NAME output entries under given filename as JSON\n"
           "    -P PATH list entries with specified prefix\n"
           "    -u PATH update specified object in index\n"
           "    -v      increase verbosity\n"
           "    -w      output all contents of index in hierarchical format\n",
           prognm);
}

static int
parse_cmdline(int argc, char **argv, enum op *op, char **index_pathname,
              char **pathname, int *verbose)
{
    enum op index_op = 0;
    int err = -1;

    static const enum op opmap[] = {
#define E(opt, op) \
        [(unsigned char)(opt)] = op
        E('D', DELETE_FROM_INDEX),
        E('d', DUMP_INDEX),
        E('i', INDEX_JSON),
        E('L', LIST_INDEX_ENTRIES),
        E('l', SEARCH_INDEX),
        E('o', OUTPUT_JSON),
        E('P', PREFIX_SEARCH_INDEX),
        E('u', UPDATE_INDEX),
        E('w', WALK_INDEX)
#undef E
    };

    for (;;) {
        int opt = getopt(argc, argv, "D:df:hi:L:l:o:P:u:vw");

        if (opt == -1)
            break;

        switch (opt) {
        case 'f':
            free(*index_pathname);
            *index_pathname = strdup(optarg);
            if (*index_pathname == NULL)
                goto err1;
            break;
        case 'h':
            print_usage(argv[0]);
            err = -2;
            goto err2;
        case 'v':
            *verbose = 1;
            break;
        case 'D':
        case 'i':
        case 'L':
        case 'l':
        case 'o':
        case 'P':
        case 'u':
            free(*pathname);
            *pathname = strdup(optarg);
            if (*pathname == NULL)
                goto err3;
            /* fallthrough */
        case 'd':
        case 'w':
            index_op = opmap[(unsigned char)opt];
            break;
        default:
            goto err2;
        }
    }

    if (argc != optind) {
        fputs("Unrecognized arguments\n", stderr);
        goto err2;
    }

    if (index_op != 0)
        *op = index_op;

    return 0;

err3:
    free(*index_pathname);
    return err;

err2:
    free(*index_pathname);
err1:
    free(*pathname);
    return err;
}

static int
print_verbose(FILE *f, const char *fmt, ...)
{
    int ret;
    va_list ap;

    if (f == NULL)
        return 0;

    va_start(ap, fmt);
    ret = vfprintf(f, fmt, ap);
    va_end(ap);

    return ret;
}

static int
syncf(FILE *f)
{
    static const int fsync_na_errs[] = {
        [EBADF]     = 1,
        [EINVAL]    = 1,
        [ENOTSUP]   = 1
    };

    return fflush(f) == EOF
           || (fsync(fileno(f)) == -1
               && (errno < 0 || errno >= (int)ARRAY_SIZE(fsync_na_errs)
                   || !fsync_na_errs[errno]))
           ? MINUS_ERRNO : 0;
}

static int
print_err(int errdes)
{
    int errcode;
    int i;
    struct err_info_bt *inf;

    errcode = errdes;

    inf = err_get_bt(&errcode);
    if (inf == NULL)
        return errdes;

    if (errcode != errdes) {
        if (fprintf(stderr, "Error at %s:%d\n", inf->file, inf->line) < 0)
            goto end;

        for (i = 1; i < inf->len; i++) {
            if (fprintf(stderr, "%s\n", inf->bt[i]) < 0)
                goto end;
        }

        fprintf(stderr, "%s\n", strerror(-errcode));
    }

end:
    err_info_free(inf, 1);
    return errcode;
}

static void
clear_err(int errdes)
{
    int errcode;
    struct err_info_bt *inf;

    errcode = errdes;

    inf = err_get_bt(&errcode);
    if (inf != NULL)
        err_info_free(inf, 1);
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
uint64_cmp(uint64_t n1, uint64_t n2)
{
    return (n1 > n2) - (n1 < n2);
}

static int
index_key_cmp(const void *k1, const void *k2, void *key_ctx)
{
    const struct index_key *key1 = k1;
    const struct index_key *key2 = k2;
    int cmp;

    if (key_ctx != NULL) {
        struct index_key_ctx *ctx = key_ctx;

        memcpy(ctx->last_key, k2, sizeof(struct index_key));
        ctx->last_key_valid = 1;
    }

    cmp = uint64_cmp(key1->type, key2->type);
    if (cmp != 0 || key1->type == TYPE_HEADER)
        return cmp;

    cmp = uint64_cmp(key1->id, key2->id);
    if (cmp != 0)
        return cmp;

    switch (key1->type) {
    case TYPE_EXTERNAL_NUMERIC:
        cmp = uint64_cmp(key1->numeric, key2->numeric);
        break;
    case TYPE_EXTERNAL_STRING:
        cmp = strcmp((const char *)key1->string, (const char *)key2->string);
        /* fallthrough */
    case TYPE_INTERNAL:
    case TYPE_FREE_ID:
        break;
    default:
        abort();
    }

    return cmp;
}

static int
do_index_create(struct index_ctx **ctx, const char *pathname, mode_t mode,
                size_t key_size, db_hl_key_cmp_t key_cmp)
{
    int err;
    struct index_ctx *ret;

    if (omalloc(&ret) == NULL)
        return ERR_TAG(errno);
    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    if (omalloc(&ret->key_ctx) == NULL) {
        err = ERR_TAG(errno);
        goto err1;
    }

    ret->key_ctx->last_key = malloc(key_size);
    if (ret->key_ctx->last_key == NULL) {
        err = ERR_TAG(errno);
        goto err2;
    }
    ret->key_ctx->last_key_valid = 0;

    err = db_hl_create(&ret->dbh, pathname, mode, key_size, key_cmp,
                       ret->key_ctx, 0);
    if (err) {
        err = ERR_TAG(-err);
        goto err3;
    }

    *ctx = ret;
    return 0;

err3:
    free(ret->key_ctx->last_key);
err2:
    free(ret->key_ctx);
err1:
    free(ret);
    return err;
}

static int
do_index_open(struct index_ctx **ctx, const char *pathname, size_t key_size,
              db_hl_key_cmp_t key_cmp, int ro)
{
    int err;
    int fl;
    struct index_ctx *ret;

    if (omalloc(&ret) == NULL)
        return ERR_TAG(errno);
    ret->key_size = key_size;
    ret->key_cmp = key_cmp;

    if (omalloc(&ret->key_ctx) == NULL) {
        err = ERR_TAG(errno);
        goto err1;
    }

    ret->key_ctx->last_key = malloc(key_size);
    if (ret->key_ctx->last_key == NULL) {
        err = ERR_TAG(errno);
        goto err2;
    }
    ret->key_ctx->last_key_valid = 0;

    fl = DB_HL_NDELAY;
    if (ro)
        fl |= DB_HL_RDONLY;

    err = db_hl_open(&ret->dbh, pathname, key_size, key_cmp, ret->key_ctx, fl);
    if (err) {
        if (err != -EROFS) {
            err = ERR_TAG(-err);
            goto err3;
        }

        err = db_hl_open(&ret->dbh, pathname, key_size, key_cmp, ret->key_ctx,
                         fl & ~DB_HL_RDONLY);
        if (err) {
            err = ERR_TAG(-err);
            goto err3;
        }
        err = db_hl_close(ret->dbh);
        if (err) {
            err = ERR_TAG(-err);
            goto err3;
        }
        err = db_hl_open(&ret->dbh, pathname, key_size, key_cmp, ret->key_ctx,
                         fl);
        if (err) {
            err = ERR_TAG(-err);
            goto err3;
        }
    }

    *ctx = ret;
    return 0;

err3:
    free(ret->key_ctx->last_key);
err2:
    free(ret->key_ctx);
err1:
    free(ret);
    return err;
}

static int
do_index_close(struct index_ctx *ctx)
{
    int err;

    err = db_hl_close(ctx->dbh);
    if (err)
        err = ERR_TAG(-err);

    free(ctx->key_ctx->last_key);

    free(ctx->key_ctx);

    free(ctx);

    return err;
}

static int
do_index_insert(struct index_ctx *ctx, const void *key, const void *data,
                size_t datasize)
{
    int err;

    err = db_hl_insert(ctx->dbh, key, data, datasize);
    return err ? ERR_TAG(err < 0 ? -err : err) : 0;
}

static int
do_index_replace(struct index_ctx *ctx, const void *key, const void *data,
                 size_t datasize)
{
    int err;

    err = db_hl_replace(ctx->dbh, key, data, datasize);
    return err ? ERR_TAG(err < 0 ? -err : err) : 0;
}

static int
do_index_look_up(struct index_ctx *ctx, const void *key, void *retkey,
                 void *retdata, size_t *retdatasize)
{
    int res;
    size_t datalen;

    if (retdatasize == NULL)
        retdatasize = &datalen;

    ctx->key_ctx->last_key_valid = 0;

    res = db_hl_search(ctx->dbh, key, retkey, retdata, retdatasize);
    return res < 0 ? ERR_TAG(-res) : res;
}

static int
do_index_delete(struct index_ctx *ctx, const void *key)
{
    int err;

    err = db_hl_delete(ctx->dbh, key);
    return err ? ERR_TAG(err < 0 ? -err : err) : 0;
}

static int
do_index_walk(struct index_ctx *ctx, db_hl_walk_cb_t fn, void *wctx)
{
    int err;

    err = db_hl_walk(ctx->dbh, fn, wctx);
    return err ? ERR_TAG(-err) : 0;
}

static int
do_index_iter_new(struct index_iter **iter, struct index_ctx *ctx)
{
    int err;
    struct index_iter *ret;

    if (omalloc(&ret) == NULL)
        return ERR_TAG(errno);

    err = db_hl_iter_new(&ret->iter, ctx->dbh);
    if (err) {
        err = ERR_TAG(-err);
        goto err1;
    }

    ret->ctx = ctx;

    ret->srch_key = malloc(ctx->key_size);
    if (ret->srch_key == NULL) {
        err = ERR_TAG(errno);
        goto err2;
    }
    ret->srch_status = -EINVAL;

    *iter = ret;
    return 0;

err2:
    db_hl_iter_free(ret->iter);
err1:
    free(ret);
    return err;
}

static int
do_index_iter_free(struct index_iter *iter)
{
    int err;

    free(iter->srch_key);

    err = db_hl_iter_free(iter->iter);
    if (err)
        err = ERR_TAG(-err);

    free(iter);

    return err;
}

static int
do_index_iter_get(struct index_iter *iter, void *retkey, void *retdata,
                  size_t *retdatasize)
{
    db_hl_iter_t idxiter;
    int res;
    size_t datalen;
    struct index_ctx *ctx;

    idxiter = iter->iter;
    ctx = iter->ctx;

    if (retdatasize == NULL)
        retdatasize = &datalen;

    if (iter->srch_status == 0) {
        assert(ctx->key_ctx->last_key_valid);

        res = db_hl_iter_search(idxiter, ctx->key_ctx->last_key);
        assert(res != 0);
        if (res < 0)
            return ERR_TAG(-res);

        if ((*ctx->key_cmp)(ctx->key_ctx->last_key, iter->srch_key, NULL) < 0) {
            res = db_hl_iter_next(idxiter);
            if (res != 0)
                return ERR_TAG(-res);
        }

        iter->srch_status = 1;
    }

    res = db_hl_iter_get(idxiter, retkey, retdata, retdatasize);
    return res == 0 ? 0 : ERR_TAG(-res);
}

static int
do_index_iter_next(struct index_iter *iter)
{
    int err;

    err = db_hl_iter_next(iter->iter);
    if (err)
        iter->srch_status = err = ERR_TAG(-err);
    else
        iter->srch_status = 1;

    return err;
}

/*static int
do_index_iter_prev(struct index_iter *iter)
{
    int err;

    err = db_hl_iter_prev(iter->iter);
    if (err)
        iter->srch_status = err = ERR_TAG(-err);
    else
        iter->srch_status = 1;

    return err;
}
*/
static int
do_index_iter_search(struct index_iter *iter, const void *key)
{
    struct index_ctx *ctx;

    ctx = iter->ctx;

    ctx->key_ctx->last_key_valid = 0;

    iter->srch_status = db_hl_iter_search(iter->iter, key);

    if (iter->srch_status == 0)
        memcpy(iter->srch_key, key, ctx->key_size);

    return iter->srch_status;
}

static int
do_index_trans_new(struct index_ctx *ctx)
{
    int err;

    err = db_hl_trans_new(ctx->dbh);
    return err ? ERR_TAG(-err) : 0;
}

static int
do_index_trans_abort(struct index_ctx *ctx)
{
    int err;

    err = db_hl_trans_abort(ctx->dbh);
    return err ? ERR_TAG(-err) : 0;
}

static int
do_index_trans_commit(struct index_ctx *ctx)
{
    int err;

    err = db_hl_trans_commit(ctx->dbh);
    return err ? ERR_TAG(err < 0 ? -err : err) : 0;
}

static int
do_index_sync(struct index_ctx *ctx)
{
    int err;

    err = db_hl_sync(ctx->dbh);
    return err ? ERR_TAG(-err) : 0;
}

static int
open_or_create(struct index_ctx **ctx, const char *pathname)
{
    const char *errmsg;
    int err, tmp;
    struct index_ctx *ret;
    struct index_key k;
    struct index_obj_free_id freeid;
    struct index_obj_header hdr;

    err = do_index_open(&ret, pathname, sizeof(struct index_key),
                        &index_key_cmp, 0);
    if (err) {
        tmp = err_get_code(err);
        if (tmp != -ENOENT) {
            errmsg = "opening";
            goto err1;
        }
        clear_err(err);

        errmsg = "creating";

        err = do_index_create(&ret, pathname, ACC_MODE_DEFAULT,
                              sizeof(struct index_key), &index_key_cmp);
        if (err)
            goto err2;

        k.type = TYPE_HEADER;
        hdr.version = FMT_VERSION;
        err = do_index_insert(ret, &k, &hdr, sizeof(hdr));
        if (err)
            goto err3;

        k.type = TYPE_FREE_ID;
        k.id = ROOT_ID;
        memset(freeid.used_id, 0, sizeof(freeid.used_id));
        freeid.flags = FREE_ID_LAST_USED;
        err = do_index_insert(ret, &k, &freeid, sizeof(freeid));
        if (err)
            goto err3;

        err = do_index_sync(ret);
        if (err)
            goto err3;
    }

    *ctx = ret;
    return 0;

err3:
    do_index_close(ret);
err2:
    tmp = err_get_code(err);
err1:
    fprintf(stderr, "Error %s index file %s: %s\n", errmsg, pathname,
            strerror(-tmp));
    return err;
}

static void
used_id_set(uint64_t *used_id, uint64_t base, uint64_t id, int val)
{
    int idx, wordidx;
    uint64_t mask;

    idx = id - base;
    wordidx = idx / UINT64_BIT;
    mask = UINT64_C(1) << idx % UINT64_BIT;

    if (val)
        used_id[wordidx] |= mask;
    else
        used_id[wordidx] &= ~mask;
}

static uint64_t
free_id_find(uint64_t *used_id, uint64_t base)
{
    int idx;
    int maxidx;
    static const uint64_t filled = ~UINT64_C(0);
    uint64_t id;
    uint64_t word;

    maxidx = FREE_ID_RANGE_SZ / UINT64_BIT - 1;
    for (idx = 0;; idx++) {
        if (used_id[idx] != filled)
            break;
        if (idx == maxidx)
            return 0;
    }
    id = base + idx * UINT64_BIT;
    word = ~used_id[idx];

    idx = 0;
    if (!(word & 0xffffffff)) {
        word >>= 32;
        idx += 32;
    }
    if (!(word & 0xffff)) {
        word >>= 16;
        idx += 16;
    }
    if (!(word & 0xff)) {
        word >>= 8;
        idx += 8;
    }
    if (!(word & 0xf)) {
        word >>= 4;
        idx += 4;
    }
    if (!(word & 0x3)) {
        word >>= 2;
        idx += 2;
    }
    if (!(word & 0x1))
        idx += 1;

    return id + idx;
}

static int
get_id(struct index_ctx *ctx, uint64_t *id)
{
    int res;
    struct index_iter *iter = NULL;
    struct index_key k;
    struct index_obj_free_id freeid;
    uint64_t ret;

    res = do_index_iter_new(&iter, ctx);
    if (res != 0)
        return res;

    k.type = TYPE_FREE_ID;
    k.id = 0;
    res = do_index_iter_search(iter, &k);
    if (res != 0 && res != 1) {
        do_index_iter_free(iter);
        return res;
    }

    res = do_index_iter_get(iter, &k, &freeid, NULL);
    do_index_iter_free(iter);
    if (res != 0) {
        if (err_get_code(res) == -EADDRNOTAVAIL) {
            clear_err(res);
            return ERR_TAG(ENOSPC);
        }
        return res;
    }
    if (k.type != TYPE_FREE_ID)
        return ERR_TAG(ENOSPC);

    ret = free_id_find(freeid.used_id, k.id);
    if (ret == 0) {
        if (!(freeid.flags & FREE_ID_LAST_USED))
            return ERR_TAG(EILSEQ);
        if (ULONG_MAX - k.id < FREE_ID_RANGE_SZ)
            return ERR_TAG(ENOSPC);

        res = do_index_delete(ctx, &k);
        if (res != 0)
            return res;

        k.id += FREE_ID_RANGE_SZ;
        memset(freeid.used_id, 0, sizeof(freeid.used_id));
        used_id_set(freeid.used_id, k.id, k.id, 1);
        freeid.flags = FREE_ID_LAST_USED;
        res = do_index_insert(ctx, &k, &freeid, sizeof(freeid));
        if (res != 0)
            return res;

        *id = k.id;
        return 0;
    }

    used_id_set(freeid.used_id, k.id, ret, 1);
    res = memcchr(freeid.used_id, 0xff, sizeof(freeid.used_id)) == NULL
          && !(freeid.flags & FREE_ID_LAST_USED)
          ? do_index_delete(ctx, &k)
          : do_index_replace(ctx, &k, &freeid, sizeof(freeid));
    if (res != 0)
        return res;

    *id = ret;
    return 0;
}

#if 0
static int
release_id(struct index_ctx *ctx, uint64_t root_id, uint64_t id)
{
    int res;
    struct index_key k;
    struct index_obj_free_id freeid;

    k.type = TYPE_FREE_ID;
    k.id = (id - root_id) / FREE_ID_RANGE_SZ * FREE_ID_RANGE_SZ + root_id;
    res = do_index_look_up(ctx, &k, &k, &freeid, NULL);
    if (res != 1) {
        if (res != 0)
            return res;

        /* insert new free ID information object */
        memset(freeid.used_id, 0xff, sizeof(freeid.used_id));
        used_id_set(freeid.used_id, k.id, id, 0);
        freeid.flags = 0;
        res = do_index_insert(ctx, &k, &freeid, sizeof(freeid));
    } else {
        used_id_set(freeid.used_id, k.id, id, 0);
        res = do_index_replace(ctx, &k, &freeid, sizeof(freeid));
    }

    return res;
}

#endif

static const char *
tabs(int n)
{
    static const char tabstr[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

    return &tabstr[sizeof(tabstr) - 1 - MIN(n, (int)(sizeof(tabstr) - 1))];
}

static int
create_xref_marker(json_val_t *jval, struct filter_state *state)
{
    int err;
    json_object_elem_t elem;
    json_val_t estart;
    json_val_t e, ret;
    wchar_t *key;

    ret = json_val_new(JSON_TYPE_OBJECT);
    if (ret == NULL)
        return ERR_TAG(ENOMEM);

    key = wcsdup(L"xref_marker");
    if (key == NULL) {
        err = ERR_TAG(errno);
        goto err1;
    }
    elem.key = key;

    elem.value = json_val_new(JSON_TYPE_ARRAY);
    if (elem.value == NULL) {
        err = ERR_TAG(ENOMEM);
        goto err2;
    }

    e = json_val_new(JSON_TYPE_NUMBER);
    if (e == NULL) {
        err = ERR_TAG(ENOMEM);
        goto err3;
    }

    err = json_val_array_insert_elem(elem.value, e);
    if (err) {
        err = ERR_TAG(-err);
        goto err4;
    }

    estart = e;

    e = json_val_new(JSON_TYPE_NUMBER);
    if (e == NULL) {
        err = ERR_TAG(ENOMEM);
        goto err3;
    }

    err = json_val_array_insert_elem(elem.value, e);
    if (err) {
        err = ERR_TAG(-err);
        goto err4;
    }

    err = json_val_object_insert_elem(ret, &elem);
    if (err) {
        err = ERR_TAG(-err);
        goto err3;
    }

    *jval = ret;
    state->e[0] = estart;
    state->e[1] = e;
    return 0;

err4:
    json_val_free(e);
err3:
    json_val_free(elem.value);
err2:
    free(key);
err1:
    json_val_free(ret);
    return err;
}

static int
_index_object_value(struct index_ctx *ctx, struct entry *parent_ent,
                    json_val_t jval, int level, int elem,
                    struct filter_state *filter_state, int output_state)
{
    int i, n;
    int res;
    json_object_elem_t elm;
    struct entry ent;
    struct index_key k;
    struct index_obj_ent e;
    uint64_t id;

    n = json_val_object_get_num_elem(jval);
    if (n == 0)
        return 0;

    res = json_val_object_get_elem_by_idx(jval, 0, &elm);
    json_val_free(elm.value);
    if (res != 0)
        return res;

    res = do_index_trans_new(ctx);
    if (res != 0)
        return res;

    if (parent_ent == NULL) {
        k.type = TYPE_INTERNAL;
        k.id = ROOT_ID;
        res = do_index_look_up(ctx, &k, &k, NULL, NULL);
        if (res != 1) {
            if (res != 0)
                goto err;

            res = get_id(ctx, &id);
            if (res != 0)
                goto err;
            if (id != ROOT_ID) {
                res = ERR_TAG(EIO);
                goto err;
            }

            k.type = TYPE_INTERNAL;
            k.id = id;
            res = do_index_insert(ctx, &k, NULL, 0);
            if (res != 0)
                goto err;
        } else
            id = k.id;
    } else {
        res = do_index_look_up(ctx, &parent_ent->k, &k, &e, NULL);
        if (res != 1) {
            if (res != 0)
                goto err;

            res = get_id(ctx, &id);
            if (res != 0)
                goto err;

            parent_ent->e.subtype = TYPE_OBJECT;
            parent_ent->e.id = id;
            res = do_index_insert(ctx, &parent_ent->k, &parent_ent->e,
                                  sizeof(parent_ent->e));
            if (res != 0)
                goto err;
        } else
            id = e.id;
    }

    res = do_index_trans_commit(ctx);
    if (res != 0)
        goto err;

    ent.k.type = TYPE_EXTERNAL_STRING;
    ent.k.id = id;

    for (i = 0; i < n; i++) {
        const wchar_t *src;
        mbstate_t s;
        size_t n;

        res = json_val_object_get_elem_by_idx(jval, i, &elm);
        if (res != 0)
            return ERR_TAG(res == -EADDRNOTAVAIL ? EIO : -res);

        src = elm.key;
        n = wcsrtombs((char *)ent.k.string, &src, sizeof(ent.k.string),
                      memset(&s, 0, sizeof(s)));
        if (n == (size_t)-1)
            return ERR_TAG(errno);
        if (src != NULL)
            return ERR_TAG(ENAMETOOLONG);

        fprintf(stderr, "%s%ls: ", elem ? "" : tabs(level), elm.key);

        res = index_value(ctx, &ent, elm.value, level, 1, filter_state,
                          output_state);
        json_val_free(elm.value);
        if (res != 0)
            return res;
    }

    return 0;

err:
    do_index_trans_abort(ctx);
    return res;
}

static int
index_null_value(struct index_ctx *ctx, struct entry *parent_ent,
                 json_val_t jval, int level, int elem,
                 struct filter_state *filter_state, int output_state)
{
    int err;

    (void)jval;
    (void)filter_state;
    (void)output_state;

    err = do_index_trans_new(ctx);
    if (err)
        return err;

    parent_ent->d.subtype = TYPE_NULL;
    parent_ent->d.numeric = 0;
    err = do_index_insert(ctx, &parent_ent->k, &parent_ent->d,
                          sizeof(parent_ent->d));
    if (err)
        goto err;

    err = do_index_trans_commit(ctx);
    if (err)
        goto err;

    fprintf(stderr, "%snull\n", elem ? "" : tabs(level));

    return 0;

err:
    do_index_trans_abort(ctx);
    return err;
}

static int
index_boolean_value(struct index_ctx *ctx, struct entry *parent_ent,
                    json_val_t jval, int level, int elem,
                    struct filter_state *filter_state, int output_state)
{
    int err;
    int val;

    (void)filter_state;
    (void)output_state;

    err = do_index_trans_new(ctx);
    if (err)
        return err;

    parent_ent->d.subtype = TYPE_BOOLEAN;
    parent_ent->d.numeric = val = json_val_boolean_get(jval);
    err = do_index_insert(ctx, &parent_ent->k, &parent_ent->d,
                          sizeof(parent_ent->d));
    if (err)
        goto err;

    err = do_index_trans_commit(ctx);
    if (err)
        goto err;

    fprintf(stderr, "%s%d\n", elem ? "" : tabs(level), val);

    return 0;

err:
    do_index_trans_abort(ctx);
    return err;
}

static int
index_object_value(struct index_ctx *ctx, struct entry *parent_ent,
                   json_val_t jval, int level, int elem,
                   struct filter_state *filter_state, int output_state)
{
    int i;
    int res;

    static const wchar_t *const filtered_keys[] = {
        L"continued",
        L"Cluster",     L"pNvET",
        L"SimpleBlock", L"X0",
        L"Timestamp",   L"b1"
    };

    i = 0;
    for (;;) {
        json_object_elem_t tmpe;

        res = json_val_object_get_elem_by_key(jval, filtered_keys[i], &tmpe);
        if (res != -EINVAL) {
            if (res != 0)
                return res;
            if (filter_state->state == 0) {
                res = create_xref_marker(&filter_state->jval, filter_state);
                if (res != 0)
                    return res;
            }
            filter_state->state = 1;
            return 1;
        }
        ++i;
        if (i == (int)ARRAY_SIZE(filtered_keys))
            break;
    }
    if (filter_state->state == 1) {
        json_val_numeric_set(filter_state->e[0], filter_state->start);
        json_val_numeric_set(filter_state->e[1], filter_state->end);
        res = _index_object_value(ctx, parent_ent, filter_state->jval, level,
                                  elem, filter_state, output_state);
        if (res != 0)
            return res;
        ++parent_ent->k.numeric;
        filter_state->state = 0;
    }

    return _index_object_value(ctx, parent_ent, jval, level, elem, filter_state,
                               output_state);
}

static int
index_array_value(struct index_ctx *ctx, struct entry *parent_ent,
                  json_val_t jval, int level, int elem,
                  struct filter_state *filter_state, int output_state)
{
    int i, n;
    int init_output_state;
    int nelem;
    int res;
    struct entry ent;
    struct index_key k;
    struct index_obj_ent e;
    uint64_t id;

    n = json_val_array_get_num_elem(jval);
    if (n == 0)
        return 0;

    res = do_index_trans_new(ctx);
    if (res != 0)
        return res;

    res = do_index_look_up(ctx, &parent_ent->k, &k, &e, NULL);
    if (res != 1) {
        if (res != 0)
            goto err;

        res = get_id(ctx, &id);
        if (res != 0)
            goto err;

        parent_ent->e.subtype = TYPE_ARRAY;
        parent_ent->e.id = id;
        res = do_index_insert(ctx, &parent_ent->k, &parent_ent->e,
                              sizeof(parent_ent->e));
        if (res != 0)
            goto err;
    } else
        id = e.id;

    res = do_index_trans_commit(ctx);
    if (res != 0)
        goto err;

    ent.k.type = TYPE_EXTERNAL_NUMERIC;
    ent.k.id = id;

    init_output_state = output_state;
    nelem = 0;
    for (i = 0; i < n; i++) {
        int prev_state;
        json_val_t val;

        val = json_val_array_get_elem(jval, i);
        if (val == NULL)
            return ERR_TAG(EIO);

        ent.k.numeric = nelem;

        if (output_state == 0)
            fprintf(stderr, "%s[%d]: ", elem ? "" : tabs(level), nelem);

        prev_state = filter_state->state;
        if (prev_state == 1)
            filter_state->end = i;

        res = index_value(ctx, &ent, val, level, 1, filter_state, output_state);
        json_val_free(val);
        switch (res) {
        case 0:
            nelem = ent.k.numeric + 1;
            output_state = init_output_state;
            break;
        case 1:
            output_state = 1;
            break;
        default:
            return res;
        }

        if (prev_state == 0 && filter_state->state == 1)
            filter_state->start = i;
    }

    return 0;

err:
    do_index_trans_abort(ctx);
    return res;
}

static int
index_number_value(struct index_ctx *ctx, struct entry *parent_ent,
                   json_val_t jval, int level, int elem,
                   struct filter_state *filter_state, int output_state)
{
    int err;

    (void)filter_state;
    (void)output_state;

    parent_ent->d.numeric = json_val_numeric_get(jval);

    err = do_index_trans_new(ctx);
    if (err)
        return err;

    parent_ent->d.subtype = TYPE_NUMERIC;
    err = do_index_insert(ctx, &parent_ent->k, &parent_ent->d,
                          sizeof(parent_ent->d));
    if (err)
        goto err;

    err = do_index_trans_commit(ctx);
    if (err)
        goto err;

    fprintf(stderr, "%s%" PRIu64 "\n", elem ? "" : tabs(level),
            parent_ent->d.numeric);

    return 0;

err:
    do_index_trans_abort(ctx);
    return err;
}

static int
index_string_value(struct index_ctx *ctx, struct entry *parent_ent,
                   json_val_t jval, int level, int elem,
                   struct filter_state *filter_state, int output_state)
{
    const wchar_t *src;
    int err;
    mbstate_t s;
    size_t n;
    wchar_t *str;

    (void)filter_state;
    (void)output_state;

    str = json_val_string_get(jval);
    if (str == NULL)
        return ERR_TAG(ENOMEM);

    src = str;
    n = wcsrtombs((char *)parent_ent->d.string, &src,
                  sizeof(parent_ent->d.string), memset(&s, 0, sizeof(s)));
    if (n == (size_t)-1) {
        err = ERR_TAG(errno);
        goto err1;
    }

    err = do_index_trans_new(ctx);
    if (err)
        goto err1;

    parent_ent->d.subtype = TYPE_STRING;
    err = do_index_insert(ctx, &parent_ent->k, &parent_ent->d,
                          sizeof(parent_ent->d));
    if (err)
        goto err2;

    err = do_index_trans_commit(ctx);
    if (err)
        goto err2;

    fprintf(stderr, "%s\"%ls\"\n", elem ? "" : tabs(level), str);

    free(str);

    return 0;

err2:
    do_index_trans_abort(ctx);
err1:
    free(str);
    return err;
}

static int
index_value(struct index_ctx *ctx, struct entry *parent_ent, json_val_t jval,
            int level, int elem, struct filter_state *filter_state,
            int output_state)
{
    int (*fn)(struct index_ctx *, struct entry *, json_val_t, int, int,
              struct filter_state *, int);
    json_val_type_t type;

    static int (*const fns[])(struct index_ctx *, struct entry *, json_val_t,
                              int, int, struct filter_state *, int) = {
        [JSON_TYPE_NULL]    = &index_null_value,
        [JSON_TYPE_BOOLEAN] = &index_boolean_value,
        [JSON_TYPE_OBJECT]  = &index_object_value,
        [JSON_TYPE_ARRAY]   = &index_array_value,
        [JSON_TYPE_NUMBER]  = &index_number_value,
        [JSON_TYPE_STRING]  = &index_string_value
    };

    type = json_val_get_type(jval);
    if (type == JSON_TYPE_NONE)
        return ERR_TAG(EIO);

    if ((size_t)type >= ARRAY_SIZE(fns))
        return ERR_TAG(EILSEQ);
    fn = fns[type];
    if (fn == NULL)
        return ERR_TAG(EILSEQ);

    if (type == JSON_TYPE_OBJECT || type == JSON_TYPE_ARRAY) {
        ++level;
        if (output_state == 0 && level > 0)
            fputc('\n', stderr);
        elem = 0;
    }

    return (*fn)(ctx, parent_ent, jval, level, elem, filter_state,
                 output_state);
}

static int
path_look_up(struct index_ctx *ctx, const char *pathname, uint64_t *id,
             struct entry *e, int prefix, FILE *f)
{
    char *path, *saveptr;
    const char *elem;
    int res;
    int terminal;
    struct index_key k;
    union {
        struct index_obj_ent        e;
        struct index_obj_ent_data   d;
    } ent;

    path = strdup(pathname);
    if (path == NULL) {
        res = ERR_TAG(errno);
        goto err1;
    }

    elem = strtok_r(path, INDEX_PATH_SEP, &saveptr);
    if (elem == NULL) {
        terminal = 0;
        ent.e = (struct index_obj_ent){TYPE_OBJECT, ROOT_ID};
        res = 1;
        goto end2;
    }

    k.id = ROOT_ID;
    k.type = TYPE_EXTERNAL_STRING;

    for (;;) {
        const char *nextelem;
        size_t datasize;

        nextelem = strtok_r(NULL, INDEX_PATH_SEP, &saveptr);
        if (prefix && nextelem == NULL) {
            if (k.type == TYPE_EXTERNAL_NUMERIC) {
                res = 0;
                goto end1;
            }
            if (strlcpy((char *)k.string, elem, sizeof(k.string))
                >= sizeof(k.string)) {
                res = ERR_TAG(ENAMETOOLONG);
                goto err2;
            }

            res = path_list_possible(ctx, &k, f);
            if (res != 1 && res != 0) {
                res = ERR_TAG(-res);
                goto err2;
            }

            goto end1;
        }

        fprintf(stderr, "Looking up {%" PRIu64 ", %s}\n", k.id, elem);

        if (k.type == TYPE_EXTERNAL_NUMERIC)
            k.numeric = strtoumax(elem, NULL, 10);
        else if (strlcpy((char *)k.string, elem, sizeof(k.string))
                 >= sizeof(k.string)) {
            res = ERR_TAG(ENAMETOOLONG);
            goto err2;
        }

        res = do_index_look_up(ctx, &k, &k, &ent, &datasize);
        if (res != 1) {
            if (res != 0) {
                res = ERR_TAG(-res);
                goto err2;
            }
            goto end1;
        }

        switch (datasize) {
        case sizeof(struct index_obj_ent):
        case sizeof(struct index_obj_ent_data):
            terminal = datasize == sizeof(struct index_obj_ent_data);
            break;
        default:
            res = ERR_TAG(EILSEQ);
            goto err2;
        }

        if (nextelem == NULL)
            break;
        elem = nextelem;

        if (terminal) {
            res = 0;
            goto end1;
        }

        k.type = ent.e.subtype == TYPE_ARRAY
                 ? TYPE_EXTERNAL_NUMERIC : TYPE_EXTERNAL_STRING;
        k.id = ent.e.id;
    }

end2:
    if (id != NULL)
        *id = terminal ? 0 : ent.e.id;
    if (e != NULL) {
        if (!terminal) {
            uint32_t subtype;

            subtype = ent.e.subtype;
            memset(&ent.d, 0, sizeof(ent.d));
            ent.d.subtype = subtype;
        }
        e->k = k;
        e->d = ent.d;
    }
end1:
    free(path);
    return res;

err2:
    free(path);
err1:
    assert(res < 0 || res >= ERRDES_MIN);
    return res;
}

static int
path_list_possible(struct index_ctx *ctx, const struct index_key *key, FILE *f)
{
    int res, ret;
    size_t keylen;
    struct index_iter *iter;
    struct index_key k;

    res = do_index_iter_new(&iter, ctx);
    if (res != 0)
        return res;

    res = do_index_iter_search(iter, key);
    if (res < 0)
        goto end;

    keylen = strlen((const char *)key->string);
    ret = 0;
    for (;;) {
        res = do_index_iter_get(iter, &k, NULL, NULL);
        if (res != 0)
            goto end;

        if (strncmp((const char *)key->string, (const char *)k.string, keylen)
            != 0)
            break;
        ret = 1;

        res = fprintf(f, "%s\n", (const char *)k.string);
        if (res < 0) {
            res = -EIO;
            goto end;
        }

        res = do_index_iter_next(iter);
        if (res != 0) {
            if (res != -ENOENT)
                goto end;
            break;
        }
    }

    res = ret;

end:
    do_index_iter_free(iter);
    return res;
}

static int
get_ents(struct index_ctx *ctx, uint64_t type, uint64_t id, int allow_deletes,
         int (*cb)(uint64_t, uint64_t, uint64_t, uint64_t, uint64_t,
                   uint64_t, const char *, const char *, void *),
         void *cbctx)
{
    int res;
    struct index_iter *iter;
    struct index_key k;
    uint64_t parent_id;
    uint64_t typ;

    res = do_index_iter_new(&iter, ctx);
    if (res != 0)
        return res;

    if (type == TYPE_OBJECT) {
        k.type = typ = TYPE_EXTERNAL_STRING;
        k.string[0] = '\0';
    } else {
        k.type = typ = TYPE_EXTERNAL_NUMERIC;
        k.numeric = 0;
    }
    k.id = id;
    res = do_index_iter_search(iter, &k);
    if (res != 0 && res != 1) {
        do_index_iter_free(iter);
        return res;
    }

    parent_id = id;

    for (;;) {
        const char *sval1, *sval2;
        size_t datasize;
        uint64_t nval1, nval2;
        uint64_t subtype;
        union {
            struct index_obj_ent        e;
            struct index_obj_ent_data   d;
        } ent;

        res = do_index_iter_get(iter, &k, NULL, NULL);
        if (res != 0) {
            if (err_get_code(res) == -EADDRNOTAVAIL) {
                clear_err(res);
                res = ERR_TAG(ENOENT);
            }
            goto err;
        }
        if (k.type != typ || k.id != parent_id)
            break;

        res = do_index_iter_get(iter, &k, &ent, &datasize);
        if (res != 0) {
            if (err_get_code(res) == -EADDRNOTAVAIL) {
                clear_err(res);
                res = ERR_TAG(EIO);
            }
            goto err;
        }
        if (k.type != typ || k.id != parent_id) {
            res = ERR_TAG(EIO);
            goto err;
        }

        if (type == TYPE_OBJECT) {
            nval1 = 0;
            sval1 = (const char *)k.string;
        } else {
            nval1 = k.numeric;
            sval1 = NULL;
        }

        switch (datasize) {
        case sizeof(struct index_obj_ent):
            subtype = ent.e.subtype;
            id = ent.e.id;
            nval2 = 0;
            sval2 = NULL;
            break;
        case sizeof(struct index_obj_ent_data):
            subtype = ent.d.subtype;
            id = 0;
            if (subtype == TYPE_BOOLEAN || subtype == TYPE_NUMERIC) {
                nval2 = ent.d.numeric;
                sval2 = NULL;
            } else {
                nval2 = 0;
                sval2 = (const char *)ent.d.string;
            }
            break;
        default:
            res = ERR_TAG(EILSEQ);
            goto err;
        }

        do_index_iter_free(iter);

        res = (*cb)(type, parent_id, subtype, id, nval1, nval2, sval1, sval2,
                    cbctx);
        if (res != 0)
            return res;

        res = do_index_iter_new(&iter, ctx);
        if (res != 0)
            return res;

        res = do_index_iter_search(iter, &k);
        if (res != 1) {
            if (res != 0)
                goto err;
            if (!allow_deletes) {
                res = ERR_TAG(EIO);
                goto err;
            }
            continue;
        }

        res = do_index_iter_next(iter);
        if (res != 0) {
            if (err_get_code(res) != -ENOENT)
                goto err;
            clear_err(res);
            break;
        }
    }

    do_index_iter_free(iter);

    return 0;

err:
    do_index_iter_free(iter);
    return res;
}

static void
print_attr(const struct attr_output_args *args, const char *fmt,
           const char *name, ...)
{
    va_list ap;

    fprintf(args->f, "\t%*s: ", args->fwidth, name);

    va_start(ap, name);
    vfprintf(args->f, fmt, ap);
    va_end(ap);

    fputc('\n', args->f);
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
list_index_entries_cb(uint64_t type, uint64_t parent_id, uint64_t subtype,
                      uint64_t id, uint64_t nval1, uint64_t nval2,
                      const char *sval1, const char *sval2, void *ctx)
{
    char typechar;
    FILE *f = ctx;

    (void)parent_id;
    (void)id;

    if (subtype >= ARRAY_SIZE(typedescs))
        return ERR_TAG(EILSEQ);
    typechar = typedescs[subtype].typechar;
    if (typechar == '\0')
        return ERR_TAG(EILSEQ);

    if (fprintf(f, "%c\t", typechar) < 0)
        return ERR_TAG(EIO);

    if (type == TYPE_OBJECT)
        fprintf(f, "%s", sval1);
    else if (type == TYPE_ARRAY)
        fprintf(f, "[%" PRIu64 "]", nval1);
    fputc('\t', f);

    if (ferror(f))
        return ERR_TAG(EIO);

    switch (subtype) {
    case TYPE_NULL:
        if (fputs("null", f) == EOF)
            return ERR_TAG(EIO);
        break;
    case TYPE_BOOLEAN:
        if (fprintf(f, "%d", nval2 != 0) < 0)
            return ERR_TAG(EIO);
        break;
    case TYPE_NUMERIC:
        if (fprintf(f, "%" PRIu64, nval2) < 0)
            return ERR_TAG(EIO);
        break;
    case TYPE_STRING:
        if (fputs(sval2, f) == EOF)
            return ERR_TAG(EIO);
        /* fallthrough */
    default:
        break;
    }

    return fputc('\n', f) == EOF ? ERR_TAG(EIO) : 0;
}

static int
delete_from_index_cb(uint64_t type, uint64_t parent_id, uint64_t subtype,
                     uint64_t id, uint64_t nval1, uint64_t nval2,
                     const char *sval1, const char *sval2, void *ctx)
{
    FILE *f;
    int res;
    struct index_key k;
    struct walk_index_ctx *wctx = ctx;

    f = wctx->f;

    fprintf(f, "%sContainer ID: %" PRIu64 "\n", tabs(wctx->level), parent_id);

    ++wctx->level;
    fprintf(f, "%s", tabs(wctx->level));

    if (type == TYPE_OBJECT || type == TYPE_ARRAY) {
        if (type == TYPE_OBJECT)
            fprintf(f, "%s", sval1);
        else if (type == TYPE_ARRAY)
            fprintf(f, "[%" PRIu64 "]", nval1);
        fputs(" -> ", f);
    }

    switch (subtype) {
    case TYPE_NULL:
        fputs("Null value\n", f);
        break;
    case TYPE_BOOLEAN:
        fprintf(f, "Boolean value: %d\n", nval2 != 0);
        break;
    case TYPE_OBJECT:
    case TYPE_ARRAY:
        fprintf(f, "%s value: %" PRIu64 "\n", typedescs[subtype].typestr, id);
        ++wctx->level;
        res = get_ents(wctx->ctx, subtype, id, 1, &delete_from_index_cb, wctx);
        --wctx->level;
        if (res != 0)
            return res;
        break;
    case TYPE_NUMERIC:
        fprintf(f, "Numeric value: %" PRIu64 "\n", nval2);
        break;
    case TYPE_STRING:
        fprintf(f, "String value: %s\n", sval2);
        break;
    default:
        return ERR_TAG(EILSEQ);
    }

    --wctx->level;

    switch (type) {
    case TYPE_OBJECT:
    case TYPE_STRING:
        k.type = TYPE_EXTERNAL_STRING;
        strlcpy((char *)k.string, type == TYPE_OBJECT ? sval1 : sval2,
                sizeof(k.string));
        break;
    default:
        k.type = TYPE_EXTERNAL_NUMERIC;
        k.numeric = type == TYPE_ARRAY ? nval1 : nval2;
        break;
    }
    k.id = parent_id;

    return do_index_delete(wctx->ctx, &k);
}

static int
output_index_cb(uint64_t type, uint64_t parent_id, uint64_t subtype,
                uint64_t id, uint64_t nval1, uint64_t nval2, const char *sval1,
                const char *sval2, void *ctx)
{
    FILE *f;
    int res;
    json_val_t jval, parent_jval;
    mbstate_t s;
    size_t len;
    struct output_json_ctx *octx = ctx;
    struct walk_index_ctx *wctx = &octx->wctx;
    wchar_t *str;

    static const json_val_type_t types[] = {
        [TYPE_NULL]    = JSON_TYPE_NULL,
        [TYPE_BOOLEAN] = JSON_TYPE_BOOLEAN,
        [TYPE_OBJECT]  = JSON_TYPE_OBJECT,
        [TYPE_ARRAY]   = JSON_TYPE_ARRAY,
        [TYPE_NUMERIC] = JSON_TYPE_NUMBER,
        [TYPE_STRING]  = JSON_TYPE_STRING
    };

    f = wctx->f;

    print_verbose(f, "%sContainer ID: %" PRIu64 "\n", tabs(wctx->level),
                  parent_id);

    jval = json_val_new(types[subtype]);
    if (jval == NULL)
        return ERR_TAG(ENOMEM);

    ++wctx->level;
    print_verbose(f, "%s", tabs(wctx->level));

    if (type == TYPE_OBJECT || type == TYPE_ARRAY) {
        if (type == TYPE_OBJECT)
            print_verbose(f, "%s", sval1);
        else if (type == TYPE_ARRAY)
            print_verbose(f, "[%" PRIu64 "]", nval1);
        print_verbose(f, " -> ");
    }

    parent_jval = octx->jval;

    switch (subtype) {
    case TYPE_NULL:
        print_verbose(f, "Null value\n");
        break;
    case TYPE_BOOLEAN:
        json_val_boolean_set(jval, nval2);
        print_verbose(f, "Boolean value: %d\n", nval2 != 0);
        break;
    case TYPE_OBJECT:
    case TYPE_ARRAY:
        print_verbose(f, "%s value: %" PRIu64 "\n", typedescs[subtype].typestr,
                      id);
        ++wctx->level;
        octx->jval = jval;
        res = get_ents(wctx->ctx, subtype, id, 0, &output_index_cb, wctx);
        octx->jval = parent_jval;
        --wctx->level;
        if (res != 0)
            goto err1;
        break;
    case TYPE_NUMERIC:
        json_val_numeric_set(jval, nval2);
        print_verbose(f, "Numeric value: %" PRIu64 "\n", nval2);
        break;
    case TYPE_STRING:
        len = strlen(sval2) + 1;
        if (oallocarray(&str, len) == NULL) {
            res = ERR_TAG(errno);
            goto err1;
        }
        if (mbsrtowcs(str, &sval2, len, memset(&s, 0, sizeof(s)))
            == (size_t)-1) {
            res = ERR_TAG(errno);
            goto err2;
        }
        res = json_val_string_set(jval, str);
        free(str);
        if (res != 0)
            goto err1;
        print_verbose(f, "String value: %s\n", sval2);
        break;
    default:
        res = ERR_TAG(EILSEQ);
        goto err1;
    }

    --wctx->level;

    if (parent_jval == NULL)
        octx->jval = jval;
    else {
        json_object_elem_t elem;

        switch (type) {
        case TYPE_OBJECT:
            len = strlen(sval1) + 1;
            if (oallocarray(&str, len) == NULL) {
                res = ERR_TAG(errno);
                goto err1;
            }
            if (mbsrtowcs(str, &sval1, len, memset(&s, 0, sizeof(s)))
                == (size_t)-1) {
                res = ERR_TAG(errno);
                goto err2;
            }
            elem.key = str;
            elem.value = jval;
            res = json_val_object_insert_elem(parent_jval, &elem);
            if (res != 0)
                goto err2;
            break;
        case TYPE_ARRAY:
            res = json_val_array_insert_elem(parent_jval, jval);
            if (res != 0)
                goto err1;
            /* fallthrough */
        default:
            break;
        }
    }

    return 0;

err2:
    free(str);
err1:
    json_val_free(jval);
    return res;
}

static int
walk_index_cb(uint64_t type, uint64_t parent_id, uint64_t subtype, uint64_t id,
              uint64_t nval1, uint64_t nval2, const char *sval1,
              const char *sval2, void *ctx)
{
    FILE *f;
    int res;
    struct walk_index_ctx *wctx = ctx;

    f = wctx->f;

    fprintf(f, "%sContainer ID: %" PRIu64 "\n", tabs(wctx->level), parent_id);

    ++wctx->level;
    fprintf(f, "%s", tabs(wctx->level));

    if (type == TYPE_OBJECT || type == TYPE_ARRAY) {
        if (type == TYPE_OBJECT)
            fprintf(f, "%s", sval1);
        else if (type == TYPE_ARRAY)
            fprintf(f, "[%" PRIu64 "]", nval1);
        fputs(" -> ", f);
    }

    if (ferror(f))
        return ERR_TAG(EIO);

    switch (subtype) {
    case TYPE_NULL:
        if (fputs("Null value\n", f) == EOF)
            return ERR_TAG(EIO);
        break;
    case TYPE_BOOLEAN:
        if (fprintf(f, "Boolean value: %d\n", nval2 != 0) < 0)
            return ERR_TAG(EIO);
        break;
    case TYPE_OBJECT:
    case TYPE_ARRAY:
        if (fprintf(f, "%s value: %" PRIu64 "\n", typedescs[subtype].typestr,
                    id)
            < 0)
            return ERR_TAG(EIO);
        ++wctx->level;
        res = get_ents(wctx->ctx, subtype, id, 0, &walk_index_cb, wctx);
        --wctx->level;
        if (res != 0)
            return res;
        break;
    case TYPE_NUMERIC:
        if (fprintf(f, "Numeric value: %" PRIu64 "\n", nval2) < 0)
            return ERR_TAG(EIO);
        break;
    case TYPE_STRING:
        if (fprintf(f, "String value: %s\n", sval2) < 0)
            return ERR_TAG(EIO);
        break;
    default:
        return ERR_TAG(EILSEQ);
    }

    --wctx->level;

    return 0;
}

#define FWIDTH 12

static int
dump_index_cb(const void *key, const void *data, size_t datasize, void *ctx)
{
    const char *str;
    const struct index_key *k = key;
    FILE *f = ctx;
    mbstate_t s;
    struct attr_output_args args;
    uint64_t subtype;
    union {
        const struct index_obj_header   *hdr;
        const struct index_obj_ent      *ent;
        const struct index_obj_ent_data *ent_data;
    } obj;
    wchar_t wcs[STRING_MAX+1];

    static const char *const typemap[] = {
        [TYPE_HEADER]           = "Header",
        [TYPE_INTERNAL]         = "",
        [TYPE_EXTERNAL_NUMERIC] = "Array entry",
        [TYPE_EXTERNAL_STRING]  = "Object entry",
        [TYPE_FREE_ID]          = ""
    };

    if (k->type >= ARRAY_SIZE(typemap))
        return ERR_TAG(EILSEQ);
    str = typemap[k->type];
    if (str == NULL)
        return ERR_TAG(EILSEQ);
    if (str[0] == '\0')
        return 0;

    fprintf(f, "%s\n", str);

    args.f = f;
    args.fwidth = FWIDTH;

    if (k->type != TYPE_HEADER)
        print_attr(&args, "%" PRIu64, "Container ID", k->id);

    switch (k->type) {
    case TYPE_HEADER:
        obj.hdr = data;
        print_attr(&args, "%" PRIu64, "Version", obj.hdr->version);
        goto end;
    case TYPE_EXTERNAL_NUMERIC:
        print_attr(&args, "%" PRIu64, "Index", k->numeric);
        break;
    case TYPE_EXTERNAL_STRING:
        str = (const char *)k->string;
        if (mbsrtowcs(wcs, &str, ARRAY_SIZE(wcs), memset(&s, 0, sizeof(s)))
            == (size_t)-1)
            return ERR_TAG(errno);
        if (str != NULL)
            return ERR_TAG(ENAMETOOLONG);
        print_attr(&args, "%ls", "Key", wcs);
        break;
    default:
        abort();
    }

    switch (datasize) {
    case sizeof(struct index_obj_ent):
        obj.ent = data;
        subtype = obj.ent->subtype;
        break;
    case sizeof(struct index_obj_ent_data):
        obj.ent_data = data;
        subtype = obj.ent->subtype;
        break;
    default:
        return ERR_TAG(EILSEQ);
    }

    if (subtype >= ARRAY_SIZE(typedescs))
        return ERR_TAG(EILSEQ);
    str = typedescs[subtype].typestr;
    if (str == NULL)
        return ERR_TAG(EILSEQ);
    print_attr(&args, "%s", "Type", str);

    switch (subtype) {
    case TYPE_BOOLEAN:
        print_attr(&args, "%s", "Value",
                   obj.ent_data->numeric == 0 ? "false" : "true");
        break;
    case TYPE_OBJECT:
    case TYPE_ARRAY:
        print_attr(&args, "%" PRIu64, "ID", obj.ent->id);
        break;
    case TYPE_NUMERIC:
        print_attr(&args, "%" PRIu64, "Value", obj.ent_data->numeric);
        break;
    case TYPE_STRING:
        str = (const char *)obj.ent_data->string;
        if (mbsrtowcs(wcs, &str, ARRAY_SIZE(wcs), memset(&s, 0, sizeof(s)))
            == (size_t)-1)
            return ERR_TAG(errno);
        if (str != NULL)
            return ERR_TAG(ENAMETOOLONG);
        print_attr(&args, "%ls", "Value", wcs);
        /* fallthrough */
    case TYPE_NULL:
        break;
    default:
        return ERR_TAG(EILSEQ);
    }

end:
    return ferror(f) ? ERR_TAG(EIO) : 0;
}

#undef FWIDTH

static int
index_json(int infd, const char *index_pathname, const char *filename)
{
    const char *errmsg;
    const char *src;
    FILE *f;
    int err;
    json_object_elem_t elem;
    json_val_t jval, new_jval;
    mbstate_t s;
    size_t len;
    size_t ret;
    struct filter_state filter_state;
    struct index_ctx *ctx = NULL;
    struct json_read_cb_ctx rctx;
    wchar_t *key;

    errmsg = "Error opening input";

    infd = dup(infd);
    if (infd == -1) {
        err = MINUS_ERRNO;
        goto err1;
    }

    f = fdopen(infd, "r");
    if (f == NULL) {
        err = MINUS_ERRNO;
        close(infd);
        goto err1;
    }

    err = json_init();
    if (err) {
        errmsg = "Error initializing";
        goto err2;
    }

    json_read_cb_ctx_init(&rctx);
    rctx.read_cb = &json_read_cb;
    rctx.ctx = f;

    err = json_parse(NULL, 0, &json_read_cb_strip_comments, &rctx, &jval);
    if (err) {
        errmsg = "Error parsing input";
        goto err3;
    }

    err = open_or_create(&ctx, index_pathname);
    if (err) {
        errmsg = "Error opening index";
        goto err4;
    }

    errmsg = "Error generating index";

    new_jval = json_val_new(JSON_TYPE_OBJECT);
    if (new_jval == NULL) {
        err = -ENOMEM;
        goto err5;
    }

    len = strlen(filename) + 1;
    if (oallocarray(&key, len) == NULL) {
        err = MINUS_ERRNO;
        goto err6;
    }

    src = filename;
    ret = mbsrtowcs(key, &src, len, memset(&s, 0, sizeof(s)));
    if (ret == (size_t)-1) {
        err = MINUS_ERRNO;
        goto err7;
    }
    if (ret == len) {
        err = -EIO;
        goto err7;
    }

    elem.key = key;
    elem.value = jval;
    err = json_val_object_insert_elem(new_jval, &elem);
    if (err)
        goto err6;
    json_val_free(jval);
    jval = new_jval;

    filter_state.state = 0;

    err = index_value(ctx, NULL, jval, -1, 0, &filter_state, 0);
    if (err)
        goto err5;

    err = do_index_close(ctx);

    json_val_free(jval);

    json_end();

    fclose(f);

    return err;

err7:
    free(key);
err6:
    json_val_free(new_jval);
err5:
    do_index_close(ctx);
err4:
    json_val_free(jval);
err3:
    json_end();
err2:
    fclose(f);
err1:
    if (!sigpipe_recv) {
        if (err > 0)
            err = print_err(err);
        fprintf(stderr, "%s: %s\n", errmsg, strerror(-err));
    }
    return err;
}

static int
output_json(const char *index_pathname, const char *filename, int outfd,
            int verbose)
{
    const char *errmsg;
    FILE *f;
    int err;
    struct index_ctx *ctx;
    struct output_json_ctx octx;

    (void)filename;

    outfd = dup(outfd);
    if (outfd == -1) {
        err = MINUS_ERRNO;
        goto err1;
    }

    f = fdopen(outfd, "w");
    if (f == NULL) {
        err = MINUS_ERRNO;
        close(outfd);
        goto err1;
    }

    if (setvbuf(f, NULL, _IOLBF, 0) == EOF) {
        err = -ENOMEM;
        goto err2;
    }

    err = json_init();
    if (err) {
        errmsg = "Error initializing";
        goto err2;
    }

    err = do_index_open(&ctx, index_pathname, sizeof(struct index_key),
                        &index_key_cmp, 1);
    if (err) {
        errmsg = "Error opening index";
        goto err3;
    }

    octx.wctx.f = verbose ? stderr : NULL;
    octx.wctx.ctx = ctx;
    octx.wctx.level = 0;
    octx.jval = NULL;
    err = get_ents(ctx, TYPE_OBJECT, ROOT_ID, 0, &output_index_cb, &octx);
    if (err)
        goto err4;

    err = do_index_close(ctx);
    if (err) {
        errmsg = "Error closing index";
        goto err3;
    }

    if (octx.jval != NULL) {
        err = json_generate(octx.jval, &json_write_cb, f, NULL, NULL, 1);
        if (err)
            goto err3;

        err = syncf(f);
        if (err)
            goto err3;
    }

    json_end();

    if (fclose(f) == EOF) {
        err = MINUS_ERRNO;
        goto err1;
    }

    return 0;

err4:
    do_index_close(ctx);
err3:
    json_end();
err2:
    fclose(f);
err1:
    if (!sigpipe_recv) {
        if (err > 0)
            err = print_err(err);
        fprintf(stderr, "%s: %s\n", errmsg, strerror(-err));
    }
    return err;
}

static int
modify_index(const char *index_pathname, const char *pathname, int infd,
             int (*op)(struct index_ctx *, const char *, FILE *, const char **))
{
    const char *errmsg;
    FILE *f;
    int err;
    struct index_ctx *ctx;

    errmsg = "Error opening input";

    infd = dup(infd);
    if (infd == -1) {
        err = MINUS_ERRNO;
        goto err1;
    }

    f = fdopen(infd, "r");
    if (f == NULL) {
        err = MINUS_ERRNO;
        close(infd);
        goto err1;
    }

    err = do_index_open(&ctx, index_pathname, sizeof(struct index_key),
                        &index_key_cmp, 0);
    if (err) {
        errmsg = "Error opening index";
        goto err2;
    }

    err = (*op)(ctx, pathname, f, &errmsg);
    if (err)
        goto err3;

    err = do_index_close(ctx);
    if (err) {
        errmsg = "Error closing index";
        goto err2;
    }

    errmsg = "Error writing output";

    fclose(f);

    return 0;

err3:
    do_index_close(ctx);
err2:
    fclose(f);
err1:
    if (!sigpipe_recv) {
        if (err > 0)
            err = print_err(err);
        if (errmsg != NULL)
            fprintf(stderr, "%s: ", errmsg);
        fprintf(stderr, "%s\n", strerror(-err));
    }
    return err;
}

static int
output_index(const char *index_pathname, const char *pathname, int outfd,
             int (*op)(struct index_ctx *, const char *, FILE *, const char **))
{
    const char *errmsg;
    FILE *f;
    int err;
    struct index_ctx *ctx;

    errmsg = "Error opening output";

    outfd = dup(outfd);
    if (outfd == -1) {
        err = MINUS_ERRNO;
        goto err1;
    }

    f = fdopen(outfd, "w");
    if (f == NULL) {
        err = MINUS_ERRNO;
        close(outfd);
        goto err1;
    }

    if (setvbuf(f, NULL, _IOLBF, 0) == EOF) {
        err = -ENOMEM;
        goto err2;
    }

    err = do_index_open(&ctx, index_pathname, sizeof(struct index_key),
                        &index_key_cmp, 1);
    if (err) {
        errmsg = "Error opening index";
        goto err2;
    }

    err = (*op)(ctx, pathname, f, &errmsg);
    if (err)
        goto err3;

    err = do_index_close(ctx);
    if (err) {
        errmsg = "Error closing index";
        goto err2;
    }

    errmsg = "Error writing output";

    err = syncf(f);
    if (err)
        goto err2;

    if (fclose(f) == EOF) {
        err = MINUS_ERRNO;
        goto err1;
    }

    return 0;

err3:
    do_index_close(ctx);
err2:
    fclose(f);
err1:
    if (!sigpipe_recv) {
        if (err > 0)
            err = print_err(err);
        if (errmsg != NULL)
            fprintf(stderr, "%s: ", errmsg);
        fprintf(stderr, "%s\n", strerror(-err));
    }
    return err;
}

static int
delete_from_index(struct index_ctx *ctx, const char *pathname, FILE *f,
                  const char **errmsg)
{
    const char *sval1, *sval2;
    int res;
    struct entry e;
    struct index_key *k;
    struct walk_index_ctx walkctx;
    uint32_t subtype, type;
    uint64_t id;
    uint64_t nval1, nval2;

    (void)f;

    res = path_look_up(ctx, pathname, &id, &e, 0, NULL);
    if (res != 1) {
        if (res == 0)
            res = -ENOENT;
        goto err1;
    }

    k = &e.k;

    if (id != 0) {
        subtype = e.e.subtype;
        if (k->type == TYPE_EXTERNAL_STRING) {
            type = TYPE_OBJECT;
            nval1 = 0;
            sval1 = (const char *)k->string;
        } else {
            type = TYPE_ARRAY;
            nval1 = k->numeric;
            sval1 = NULL;
        }
        nval2 = 0;
        sval2 = NULL;
    } else {
        struct index_obj_ent_data *d = &e.d;

        type = subtype = d->subtype;
        nval1 = k->numeric;
        sval1 = NULL;
        if (subtype == TYPE_BOOLEAN || subtype == TYPE_NUMERIC) {
            nval2 = d->numeric;
            sval2 = NULL;
        } else {
            nval2 = 0;
            sval2 = (const char *)d->string;
        }
    }

    res = do_index_trans_new(ctx);
    if (res != 0)
        goto err1;

    walkctx.f = stderr;
    walkctx.ctx = ctx;
    walkctx.level = 0;
    res = delete_from_index_cb(type, k->id, subtype, id, nval1, nval2, sval1,
                               sval2, &walkctx);
    if (res != 0)
        goto err2;

    res = do_index_trans_commit(ctx);
    if (res != 0)
        goto err2;

    return 0;

err2:
    do_index_trans_abort(ctx);
err1:
    *errmsg = "Error deleting from index";
    return res;
}

static int
update_index(struct index_ctx *ctx, const char *pathname, FILE *f,
             const char **errmsg)
{
    char *line;
    int res;
    size_t linecap;
    ssize_t ret;
    struct entry e;
    struct index_obj_ent_data *d;

    res = path_look_up(ctx, pathname, NULL, &e, 0, NULL);
    if (res == 1) {
        d = &e.d;
        if (d->subtype == TYPE_BOOLEAN || d->subtype == TYPE_NUMERIC
            || d->subtype == TYPE_STRING) {
            fputs("Old value: ", stderr);
            if (d->subtype == TYPE_BOOLEAN)
                fprintf(stderr, "%d", d->numeric != 0);
            else if (d->subtype == TYPE_NUMERIC)
                fprintf(stderr, "%" PRIu64, d->numeric);
            else
                fprintf(stderr, "%s", d->string);
            fputc('\n', stderr);
        } else
            fprintf(stderr, "Type: %c\n", typedescs[d->subtype].typechar);
    } else {
        if (res != 0)
            goto err;
        fprintf(stderr, "%s not found\n", pathname);
        return 0;
    }

    line = NULL;
    linecap = 0;
    errno = 0;
    ret = getline(&line, &linecap, f);
    if (ret == -1) {
        if (errno != 0) {
            res = MINUS_ERRNO;
            goto err;
        }
        return 0;
    }

    if (d->subtype == TYPE_BOOLEAN)
        d->numeric = strtoumax(line, NULL, 10) != 0;
    else if (d->subtype == TYPE_NUMERIC)
        d->numeric = strtoumax(line, NULL, 10);
    else if (d->subtype == TYPE_STRING) {
        size_t len;

        len = strlcpy((char *)d->string, line, sizeof(d->string));
        if (len >= sizeof(d->string)) {
            res = -ENAMETOOLONG;
            free(line);
            goto err;
        }
        if (len > 0) {
            --len;
            if (d->string[len] == '\n')
                d->string[len] = '\0';
        }
    }

    free(line);

    return do_index_replace(ctx, &e.k, d, sizeof(*d));

err:
    *errmsg = "Error updating index";
    return res;
}

static int
list_index_entries(struct index_ctx *ctx, const char *pathname, FILE *f,
                   const char **errmsg)
{
    int res;
    struct entry e;
    uint64_t id;

    res = path_look_up(ctx, pathname, &id, &e, 0, NULL);
    if (res != 1) {
        if (res == 0) {
            res = -ENOENT;
            *errmsg = NULL;
            fprintf(stderr, "%s not found\n", pathname);
        } else
            *errmsg = "Error looking up in index";
    } else {
        res = get_ents(ctx, e.d.subtype, id, 0, &list_index_entries_cb, f);
        if (res != 0)
            *errmsg = "Error reading index";
    }

    return res;
}

static int
search_index(struct index_ctx *ctx, const char *pathname, FILE *f,
             const char **errmsg)
{
    int res;
    struct entry e;

    res = path_look_up(ctx, pathname, NULL, &e, 0, NULL);
    if (res == 1) {
        struct index_obj_ent_data *d = &e.d;

        if (d->subtype == TYPE_BOOLEAN || d->subtype == TYPE_NUMERIC
            || d->subtype == TYPE_STRING) {
            fputs("Value: ", f);
            if (d->subtype == TYPE_BOOLEAN)
                fprintf(f, "%d", d->numeric != 0);
            else if (d->subtype == TYPE_NUMERIC)
                fprintf(f, "%" PRIu64, d->numeric);
            else
                fprintf(f, "%s", d->string);
            fputc('\n', f);
        } else
            fprintf(f, "Type: %c\n", typedescs[d->subtype].typechar);
        if (ferror(f)) {
            res = -EIO;
            goto err;
        }
    } else {
        if (res != 0)
            goto err;
        fprintf(stderr, "%s not found\n", pathname);
    }

    return 0;

err:
    *errmsg = "Error looking up in index";
    return res;
}

static int
prefix_search_index(struct index_ctx *ctx, const char *pathname, FILE *f,
                    const char **errmsg)
{
    int res;

    res = path_look_up(ctx, pathname, NULL, NULL, 1, f);
    if (res != 1) {
        if (res != 0) {
            *errmsg = "Error looking up in index";
            return res;
        }
        fprintf(stderr, "%s not found as object, Boolean value, or string\n",
                pathname);
    }

    return 0;
}

static int
walk_index(struct index_ctx *ctx, const char *pathname, FILE *f,
           const char **errmsg)
{
    int err;
    struct walk_index_ctx wctx;

    (void)pathname;

    wctx.f = f;
    wctx.ctx = ctx;
    wctx.level = 0;
    err = get_ents(ctx, TYPE_OBJECT, ROOT_ID, 0, &walk_index_cb, &wctx);
    if (err)
        *errmsg = "Error reading index";

    return err;
}

static int
dump_index(struct index_ctx *ctx, const char *pathname, FILE *f,
           const char **errmsg)
{
    int err;

    (void)pathname;

    err = do_index_walk(ctx, &dump_index_cb, f);
    if (err)
        *errmsg = "Error reading index";

    return err;
}

int
main(int argc, char **argv)
{
    char *index_pathname_buf = NULL;
    char *pathname = NULL;
    const char *index_pathname;
    enum op op = WALK_INDEX;
    int ret;
    int verbose = 0;

    static int (*const ops[])(struct index_ctx *, const char *, FILE *,
                              const char **) = {
        [DELETE_FROM_INDEX]     = &delete_from_index,
        [UPDATE_INDEX]          = &update_index,
        [LIST_INDEX_ENTRIES]    = &list_index_entries,
        [SEARCH_INDEX]          = &search_index,
        [PREFIX_SEARCH_INDEX]   = &prefix_search_index,
        [WALK_INDEX]            = &walk_index,
        [DUMP_INDEX]            = &dump_index
    };

    ret = parse_cmdline(argc, argv, &op, &index_pathname_buf, &pathname,
                        &verbose);
    if (ret != 0)
        return ret == -2 ? EXIT_SUCCESS : EXIT_FAILURE;

    ret = enable_debugging_features();
    if (ret != 0)
        goto end;

    ret = set_up_signal_handlers();
    if (ret != 0)
        goto end;

    index_pathname = index_pathname_buf == NULL
                     ? INDEX_PATHNAME : index_pathname_buf;

    switch (op) {
    case INDEX_JSON:
        ret = index_json(STDIN_FILENO, index_pathname, pathname);
        break;
    case OUTPUT_JSON:
        ret = output_json(index_pathname, pathname, STDOUT_FILENO, verbose);
        break;
    case DELETE_FROM_INDEX:
    case UPDATE_INDEX:
        ret = modify_index(index_pathname, pathname, STDIN_FILENO, ops[op]);
        break;
    case LIST_INDEX_ENTRIES:
    case SEARCH_INDEX:
    case PREFIX_SEARCH_INDEX:
    case WALK_INDEX:
    case DUMP_INDEX:
        ret = output_index(index_pathname, pathname, STDOUT_FILENO, ops[op]);
        break;
    default:
        abort();
    }

end:
    free(index_pathname_buf);
    free(pathname);
    if (sigpipe_recv) {
        if (signal(SIGPIPE, SIG_DFL) == SIG_ERR)
            return EXIT_FAILURE;
        raise(SIGPIPE);
        for (;;)
            pause();
    }
    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */