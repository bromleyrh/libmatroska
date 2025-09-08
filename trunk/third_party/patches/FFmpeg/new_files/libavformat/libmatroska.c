/*
 * libmatroska.c
 */

#include "libmatroska_codecs.h"

#include "avformat.h"
#include "avio.h"
#include "internal.h"
#include "zlib_stream.h"

#include "libavcodec/codec_id.h"
#include "libavcodec/codec_par.h"
#include "libavcodec/defs.h"
#include "libavcodec/packet.h"

#include "libavutil/avutil.h"
#include "libavutil/dict.h"
#include "libavutil/error.h"
#include "libavutil/mem.h"
#include "libavutil/opt.h"
#include "libavutil/rational.h"
#include "libavutil/version.h"

#include <matroska.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <regex.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/types.h>

struct stream_ctx {
    int comp_algo;
};

struct libmatroska_demux_ctx {
    const AVClass   *class;
    AVFormatContext *s;
    AVStream        *cur_st;
    AVPacket        *pkt;
    matroska_hdl_t  hdl;
    regex_t         id_regex;
    AVRational      ts_scale;
    int64_t         duration;
    int             pdim[2];
    int             ddim[2];
    char            *title;
    char            *buf;
    int64_t         pkt_duration;
    size_t          len;
    size_t          off;
    uint64_t        base_ts;
    AVBufferRef     *st_data;
    size_t          num_st;
    size_t          tot_bytes[3];
    int             debug;
};

struct zlib_ctx {
    AVPacket    *pkt;
    AVBufferRef *buf;
    size_t      len;
    size_t      sz;
};

typedef int metadata_handler_t(matroska_metadata_t *, size_t,
                               struct libmatroska_demux_ctx *);

#ifndef NDEBUG
#define DEBUG_OUTPUT
#endif

static const AVOption libmatroska_demuxer_options[] = {
    {
        .name          = "debug",
        .help          = "enable debugging features",
        .offset        = offsetof(struct libmatroska_demux_ctx, debug),
        .type          = AV_OPT_TYPE_INT,
        .default_val   = {.i64 = 0},
        .min           = 0,
        .max           = 1,
        .flags         = AV_OPT_FLAG_DECODING_PARAM
    },
    {NULL}
};

static const AVClass libmatroska_demuxer_class = {
    .class_name = "libmatroska demuxer",
    .item_name  = av_default_item_name,
    .option     = libmatroska_demuxer_options,
    .version    = LIBAVUTIL_VERSION_INT
};

#define MATROSKA_TYPE_MASTER 0

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#ifdef DEBUG_OUTPUT
#define debug_printf(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)
#else
#define debug_printf(fmt, ...)
#endif

#define PLURAL(val, suffix) ((val) == 1 ? "" : suffix)

static unsigned hash_str(const void *, size_t);
static unsigned hash_id(const char *);

static int io_open(void **, int, void *);
static int io_close(void *);
static int io_read(void *, void *, ssize_t *);
static int io_get_fpos(void *, int64_t *);

static void adjust_ar(struct libmatroska_demux_ctx *);

static int handle_dimension(matroska_metadata_t *, int *, int,
                            struct libmatroska_demux_ctx *);

static metadata_handler_t handle_TimestampScale;
static metadata_handler_t handle_Duration;
static metadata_handler_t handle_Title;
static metadata_handler_t handle_Timestamp;
static metadata_handler_t handle_TrackNumber;
static metadata_handler_t handle_TrackType;
static metadata_handler_t handle_DefaultDuration;
static metadata_handler_t handle_CodecID;
static metadata_handler_t handle_CodecPrivate;
static metadata_handler_t handle_PixelWidth;
static metadata_handler_t handle_PixelHeight;
static metadata_handler_t handle_DisplayWidth;
static metadata_handler_t handle_DisplayHeight;
static metadata_handler_t handle_SamplingFrequency;
static metadata_handler_t handle_Channels;

static matroska_metadata_output_cb_t metadata_cb;
static matroska_bitstream_output_cb_t bitstream_cb;

static int zlib_stream_cb(const void *, size_t, void *);

static int libmatroska_read_probe(const AVProbeData *);
static int libmatroska_read_header(struct AVFormatContext *);
static int libmatroska_read_packet(struct AVFormatContext *, AVPacket *);
static int libmatroska_read_close(struct AVFormatContext *);

#ifdef NO_TIMESTAMPS
#define FLAG_NOTIMESTAMPS AVFMT_NOTIMESTAMPS
#else
#define FLAG_NOTIMESTAMPS 0
#endif

const AVInputFormat ff_libmatroska_demuxer = {
    .name           = "libmatroska",
    .long_name      = NULL_IF_CONFIG_SMALL("Matroska (libmatroska)"),
    .priv_class     = &libmatroska_demuxer_class,
    .flags          = FLAG_NOTIMESTAMPS,
    .read_probe     = &libmatroska_read_probe,
    .read_header    = &libmatroska_read_header,
    .read_packet    = &libmatroska_read_packet,
    .read_close     = &libmatroska_read_close
};

#define UNSIGNED_BIT (sizeof(unsigned) * CHAR_BIT)

static unsigned
hash_str(const void *str, size_t len)
{
    const char *s = str;
    unsigned i, ret = 0;

    if (len == (size_t)-1) {
        for (i = 0; s[i] != '\0'; i++) {
            ret = ret << 9 | ret >> (UNSIGNED_BIT - 9);
            ret += (unsigned)s[i];
        }
    } else {
        for (i = 0; i < len && s[i] != '\0'; i++) {
            ret = ret << 9 | ret >> (UNSIGNED_BIT - 9);
            ret += (unsigned)s[i];
        }
    }

    return ret == 0 ? ~0u : ret;
}

#undef UNSIGNED_BIT

static unsigned
hash_id(const char *id)
{
    unsigned h1, h2, h3 = 0;

    h1 = hash_str(id, (size_t)-1);
    h2 = (h1 & 30) >> 1;

    switch (h2) {
    case 9:
        h3 = (h1 & 1) << 4;
        break;
    case 12:
        h3 = (h1 & 768) >> 4;
        /* fallthrough */
    default:
        break;
    }

    return h2 | h3;
}

static int
io_open(void **ctx, int ro, void *args)
{
    (void)ro;

    *ctx = args;
    return 0;
}

static int
io_close(void *ctx)
{
    (void)ctx;

    return 0;
}

static int
io_read(void *ctx, void *buf, ssize_t *nbytes)
{
    AVIOContext *s = ctx;
    int ret;

    ret = avio_read(s, buf, *nbytes);
    if (ret < 0) {
        if (ret != AVERROR_EOF)
            return -EIO;
        *nbytes = 0;
    } else
        *nbytes = ret;

    return 0;
}

static int
io_get_fpos(void *ctx, int64_t *offset)
{
    AVIOContext *s = ctx;
    int64_t ret;

    ret = avio_tell(s);
    if (ret < 0)
        return -EIO;

    *offset = ret;
    return 0;
}

static void
adjust_ar(struct libmatroska_demux_ctx *ctx)
{
    AVRational *ar;

    if (ctx->pdim[0] == -1 || ctx->pdim[1] == -1 || ctx->ddim[0] == -1
        || ctx->ddim[1] == -1)
        return;

    ar = &ctx->cur_st->sample_aspect_ratio;

    av_reduce(&ar->num, &ar->den, ctx->ddim[0] * ctx->pdim[1],
              ctx->ddim[1] * ctx->pdim[0], INT_MAX);
}

static int
handle_dimension(matroska_metadata_t *val, int *dim, int which,
                 struct libmatroska_demux_ctx *ctx)
{
    AVCodecParameters *codecpar;
    int *d;

    codecpar = ctx->cur_st->codecpar;
    d = which == 0 ? &codecpar->width : &codecpar->height;
    *d = dim[which] = val->uinteger;
    adjust_ar(ctx);

    return 0;
}

static int
handle_TimestampScale(matroska_metadata_t *val, size_t len,
                      struct libmatroska_demux_ctx *ctx)
{
    (void)len;

    ctx->ts_scale.num = val->uinteger;
    ctx->ts_scale.den = 1000000000;

    return 0;
}

static int
handle_Duration(matroska_metadata_t *val, size_t len,
                struct libmatroska_demux_ctx *ctx)
{
    (void)len;

    ctx->duration = val->dbl;

    return 0;
}

static int
handle_Title(matroska_metadata_t *val, size_t len,
             struct libmatroska_demux_ctx *ctx)
{
    char *title;

    (void)len;

    title = strdup(val->data);
    if (title == NULL)
        return -errno;

    free(ctx->title);
    ctx->title = title;

    return 0;
}

static int
handle_Timestamp(matroska_metadata_t *val, size_t len,
                 struct libmatroska_demux_ctx *ctx)
{
    (void)len;

    ctx->base_ts = val->uinteger;

    debug_printf("Timestamp %" PRIu64 "\n", ctx->base_ts);

    return 0;
}

static int
handle_TrackNumber(matroska_metadata_t *val, size_t len,
                   struct libmatroska_demux_ctx *ctx)
{
    AVStream *st;
    size_t stream_index;
    struct stream_ctx *sctx;
    void *ptr;

    (void)len;

    st = avformat_new_stream(ctx->s, NULL);
    if (st == NULL)
        return -ENOMEM;

    stream_index = ctx->num_st++;
    if (av_buffer_realloc(&ctx->st_data,
                          ctx->num_st * sizeof(struct stream_ctx))
        != 0) {
        ctx->num_st = stream_index;
        return -ENOMEM;
    }
    ptr = ctx->st_data->data;
    sctx = ptr;
    sctx[stream_index].comp_algo = -1;

    st->id = val->uinteger;

    st->codecpar = avcodec_parameters_alloc();
    if (st->codecpar == NULL)
        return -ENOMEM;

    if (ctx->ts_scale.den != 0)
        avpriv_set_pts_info(st, 64, ctx->ts_scale.num, ctx->ts_scale.den);
    if (ctx->duration != -1)
        st->duration = ctx->duration;

    if (ctx->title != NULL) {
        if (av_dict_set(&st->metadata, "title", ctx->title, 0) < 0) {
            avcodec_parameters_free(&st->codecpar);
            return -ENOMEM;
        }
        free(ctx->title);
        ctx->title = NULL;
    }

    ctx->cur_st = st;

    return 0;
}

#define ENTRY(track_typ, media_typ) [track_typ] = (media_typ) + 1

static int
handle_TrackType(matroska_metadata_t *val, size_t len,
                 struct libmatroska_demux_ctx *ctx)
{
    enum AVMediaType *type;

    static const enum AVMediaType codec_type_map[] = {
        ENTRY(1, AVMEDIA_TYPE_VIDEO),
        ENTRY(2, AVMEDIA_TYPE_AUDIO),
        ENTRY(17, AVMEDIA_TYPE_SUBTITLE)
    };

    (void)len;

    type = &ctx->cur_st->codecpar->codec_type;

    if (val->uinteger < ARRAY_SIZE(codec_type_map)) {
        enum AVMediaType typ = codec_type_map[val->uinteger];

        *type = typ == 0 ? AVMEDIA_TYPE_UNKNOWN : typ - 1;
    } else
        *type = AVMEDIA_TYPE_UNKNOWN;

    return 0;
}

#undef ENTRY

static int
handle_DefaultDuration(matroska_metadata_t *val, size_t len,
                       struct libmatroska_demux_ctx *ctx)
{
    AVRational framerate;
    AVStream *st = ctx->cur_st;

    (void)len;

    framerate.num = 1000000000;
    framerate.den = val->uinteger;
    st->avg_frame_rate = st->r_frame_rate = framerate;

    return 0;
}

static int
handle_CodecID(matroska_metadata_t *val, size_t len,
               struct libmatroska_demux_ctx *ctx)
{
    const struct libmatroska_codec *codec;

    (void)len;

    codec = libmatroska_codec_id_find(val->data, val->len);
    ctx->cur_st->codecpar->codec_id = codec == NULL
                                      ? AV_CODEC_ID_NONE : codec->codec_id;

    return 0;
}

static int
handle_CodecPrivate(matroska_metadata_t *val, size_t len,
                    struct libmatroska_demux_ctx *ctx)
{
    AVCodecParameters *codecpar;
    uint8_t *extradata;

    (void)len;

    extradata = av_malloc(val->len + AV_INPUT_BUFFER_PADDING_SIZE);
    if (extradata == NULL)
        return -ENOMEM;

    memcpy(extradata, val->data, val->len);
    memset(extradata + val->len, 0, AV_INPUT_BUFFER_PADDING_SIZE);

    codecpar = ctx->cur_st->codecpar;

    codecpar->extradata = extradata;
    codecpar->extradata_size = val->len;

    return 0;
}

static int
handle_PixelWidth(matroska_metadata_t *val, size_t len,
                  struct libmatroska_demux_ctx *ctx)
{
    (void)len;

    return handle_dimension(val, ctx->pdim, 0, ctx);
}

static int
handle_PixelHeight(matroska_metadata_t *val, size_t len,
                   struct libmatroska_demux_ctx *ctx)
{
    (void)len;

    return handle_dimension(val, ctx->pdim, 1, ctx);
}

static int
handle_DisplayWidth(matroska_metadata_t *val, size_t len,
                    struct libmatroska_demux_ctx *ctx)
{
    (void)len;

    return handle_dimension(val, ctx->ddim, 0, ctx);
}

static int
handle_DisplayHeight(matroska_metadata_t *val, size_t len,
                     struct libmatroska_demux_ctx *ctx)
{
    (void)len;

    return handle_dimension(val, ctx->ddim, 1, ctx);
}

static int
handle_SamplingFrequency(matroska_metadata_t *val, size_t len,
                         struct libmatroska_demux_ctx *ctx)
{
    (void)len;

    ctx->cur_st->codecpar->sample_rate = val->dbl;

    return 0;
}

static int
handle_Channels(matroska_metadata_t *val, size_t len,
                struct libmatroska_demux_ctx *ctx)
{
    AVChannelLayout *ch;

    (void)len;

    ch = &ctx->cur_st->codecpar->ch_layout;
    ch->order = AV_CHANNEL_ORDER_UNSPEC;
    ch->nb_channels = val->uinteger;

    return 0;
}

static int
handle_BlockDuration(matroska_metadata_t *val, size_t len,
                     struct libmatroska_demux_ctx *ctx)
{
    (void)len;

    ctx->pkt_duration = val->uinteger;

    return 0;
}

static int
handle_ContentCompression(matroska_metadata_t *val, size_t len,
                          struct libmatroska_demux_ctx *ctx)
{
    struct stream_ctx *sctx;
    void *ptr;

    (void)val;
    (void)len;

    ptr = ctx->st_data->data;

    sctx = ptr;
    sctx[ctx->cur_st->index].comp_algo = 0;

    return 0;
}

#define POSSIBLE_MATCH(name, type) \
    {#name, MATROSKA_TYPE_##type, &handle_##name}

#define ENTRY(hash, name, type) \
    [hash] = {POSSIBLE_MATCH(name, type)}

static int
metadata_cb(const char *id, matroska_metadata_t *val, size_t len, size_t hdrlen,
            int flags, void *ctx)
{
    int err;
    matroska_metadata_t full_val;
    regmatch_t match[2];
    size_t i;
    struct libmatroska_demux_ctx *dctx = ctx;

    static const struct ent {
        const char                  *id;
        enum matroska_metadata_type type;
        metadata_handler_t          *fn;
    } idtbl[64][2] = {
        ENTRY(9,            TimestampScale,     UINTEGER),
        ENTRY(1,            Duration,           DOUBLE),
        ENTRY(4,            Title,              BYTES),
        [28] = {
            POSSIBLE_MATCH( Timestamp,          UINTEGER),
            POSSIBLE_MATCH( ContentCompression, MASTER)
        },
        ENTRY(44,           TrackNumber,        UINTEGER),
        ENTRY(8,            TrackType,          UINTEGER),
        ENTRY(15,           DefaultDuration,    UINTEGER),
        ENTRY(3,            CodecID,            BYTES),
        [2] = {
            POSSIBLE_MATCH( BlockDuration,      UINTEGER),
            POSSIBLE_MATCH( CodecPrivate,       BYTES)
        },
        ENTRY(11,           PixelWidth,         UINTEGER),
        ENTRY(13,           PixelHeight,        UINTEGER),
        ENTRY(25,           DisplayWidth,       UINTEGER),
        ENTRY(0,            DisplayHeight,      UINTEGER),
        ENTRY(5,            SamplingFrequency,  DOUBLE),
        ENTRY(60,           Channels,           UINTEGER)
    };
    const struct ent *ent;

    (void)hdrlen;

    if (flags & MATROSKA_METADATA_FLAG_HEADER)
        return 0;

    if (regexec(&dctx->id_regex, id, ARRAY_SIZE(match), match, 0) != 0)
        return -EILSEQ;
    id += match[1].rm_so;

    if (flags & MATROSKA_METADATA_FLAG_FRAGMENT) {
        if (strcmp(id, "Block") == 0 || strcmp(id, "SimpleBlock") == 0)
            return 0;
        if (dctx->buf == NULL) {
            dctx->buf = malloc(len + 1);
            if (dctx->buf == NULL)
                return -errno;
        }
        memcpy(dctx->buf + dctx->len, val->data, val->len);
        dctx->buf[dctx->len + val->len] = '\0';
        dctx->len += val->len;
        if (dctx->len < len)
            return 0;
        full_val.type = val->type;
        full_val.data = dctx->buf;
        full_val.len = len;
        val = &full_val;
    }

    debug_printf("%s\n", id);

    for (i = 0; i < ARRAY_SIZE(idtbl[0]); i++) {
        ent = &idtbl[hash_id(id)][i];

        if (ent->id != NULL && strcmp(ent->id, id) == 0) {
            if (val->type != ent->type)
                return -EIO;
            err = (*ent->fn)(val, len, dctx);
            if (err)
                return err;
        }
    }

    if (dctx->len == len) {
        free(dctx->buf);
        dctx->buf = NULL;
        dctx->len = 0;
    }

    return 0;
}

#undef ENTRY

#undef POSSIBLE_MATCH

static int
bitstream_cb(uint64_t trackno, const void *buf, size_t len, size_t framelen,
             size_t totlen, size_t hdrlen, size_t num_logical_bytes,
             int64_t off, int16_t ts, int new_frame, int keyframe, void *ctx)
{
    AVPacket *pkt;
    struct libmatroska_demux_ctx *dctx = ctx;

    (void)hdrlen;
    (void)num_logical_bytes;
    (void)new_frame;

    debug_printf("Track %" PRIu64 ": %zu byte%s (total %zu byte%s), offset "
                 "%" PRIi64 " byte%s%s\n",
                 trackno, len, PLURAL(len, "s"), totlen, PLURAL(totlen, "s"),
                 off, PLURAL(off, "s"), keyframe ? " (keyframe)" : "");

    pkt = dctx->pkt;

    if (pkt->buf == NULL) {
        pkt->buf = av_buffer_alloc(totlen + AV_INPUT_BUFFER_PADDING_SIZE);
        if (pkt->buf == NULL)
            return -ENOMEM;
        memset(pkt->buf->data + totlen, 0, AV_INPUT_BUFFER_PADDING_SIZE);
        dctx->off = 0;

#ifndef NO_TIMESTAMPS
        pkt->pts = dctx->base_ts + ts;
#endif
        pkt->data = pkt->buf->data;
        pkt->size = totlen;
        pkt->stream_index = trackno - 1;
        if (keyframe)
            pkt->flags |= AV_PKT_FLAG_KEY;
        pkt->pos = off;

        fprintf(stderr, "Track %" PRIu64 ": %" PRIi64 " == %" PRIu64 " + %"
                        PRIi16 " ms%s\n",
                trackno, pkt->pts, dctx->base_ts, ts, keyframe ? " (I)" : "");
    }

    memcpy(pkt->buf->data + dctx->off, buf, len);
    dctx->off += len;

    return dctx->off == framelen;
}

static int
zlib_stream_cb(const void *buf, size_t len, void *ctx)
{
    size_t newlen, newsz;
    struct zlib_ctx *zctx = ctx;

    newlen = zctx->len + len;

    if (newlen > zctx->sz) {
        newsz = newlen * 2;
        if (av_buffer_realloc(&zctx->buf, newsz) != 0)
            return -ENOMEM;
        zctx->sz = newsz;
    }

    memcpy(zctx->buf->data + zctx->len, buf, len);

    zctx->len = newlen;

    return 0;
}

static int
libmatroska_read_probe(const AVProbeData *p)
{
    (void)p;

    return 0;
}

static int
libmatroska_read_header(struct AVFormatContext *s)
{
    int err;
    matroska_bitstream_cb_t cb;
    matroska_io_fns_t fns;
    matroska_metadata_cb_t metacb;
    struct libmatroska_demux_ctx *ctx;

    ctx = av_mallocz(sizeof(*ctx));
    if (ctx == NULL)
        return AVERROR(ENOMEM);

    ctx->class = ff_libmatroska_demuxer.priv_class;

    fns.open = &io_open;
    fns.close = &io_close;
    fns.read = &io_read;
    fns.get_fpos = &io_get_fpos;

    metacb.output_cb = &metadata_cb;
    cb.output_cb = &bitstream_cb;
    err = matroska_open(&ctx->hdl, &fns, &metacb, &cb,
                        MATROSKA_OPEN_FLAG_RDONLY, s->pb, ctx);
    if (err)
        goto err1;

    if (regcomp(&ctx->id_regex, "[^ ]+ +-> +([^ ]+)", REG_EXTENDED) != 0) {
        err = -ENOMEM;
        goto err2;
    }

    err = matroska_read_header(NULL, ctx->hdl, 0);
    if (err)
        goto err3;

    ctx->s = s;

    ctx->duration = -1;

    ctx->pdim[0] = ctx->pdim[1] = -1;
    ctx->ddim[0] = ctx->ddim[1] = -1;

    ctx->st_data = NULL;
    ctx->num_st = 0;

    s->priv_data = ctx;
    s->ctx_flags = AVFMTCTX_NOHEADER;
    s->probesize = 64 * 1024 * 1024;

    return 0;

err3:
    regfree(&ctx->id_regex);
err2:
    matroska_close(ctx->hdl);
err1:
    av_free(ctx);
    return AVERROR(-err);
}

static int
libmatroska_read_packet(struct AVFormatContext *s, AVPacket *pkt)
{
    int res;
    size_t sz, tot_bytes;
    struct libmatroska_demux_ctx *ctx = s->priv_data;
    struct stream_ctx *sctx;
    void *ptr;
    zlib_stream_hdl_t hdl;

    ctx->pkt = pkt;

    ctx->pkt_duration = 0;

    res = matroska_read_body(NULL, ctx->hdl, MATROSKA_READ_FLAG_MASTER);
    if (res != 1)
        return res == 0 ? AVERROR_EOF : AVERROR(-res);

    pkt->duration = ctx->pkt_duration;

    if (pkt->buf != NULL && pkt->stream_index < ARRAY_SIZE(ctx->tot_bytes)) {
        sz = pkt->buf->size;
        ctx->tot_bytes[pkt->stream_index] += sz;
    } else
        sz = 0;

    tot_bytes = ctx->tot_bytes[pkt->stream_index];

    debug_printf("Stream %d: %zu byte%s (%zu byte%s total)\n",
                 pkt->stream_index, sz, PLURAL(sz, "s"), tot_bytes,
                 PLURAL(tot_bytes, "s"));

    (void)tot_bytes;

    if (ctx->off != pkt->size) {
        int64_t sz_error = ctx->off - pkt->size;

        fprintf(stderr, "Synchronization error: offset %zu byte%s "
                        "(%+" PRIi64 " byte%s)\n",
                ctx->off, PLURAL(ctx->off, "s"), sz_error,
                PLURAL(sz_error, "s"));
        abort();
    }

    ptr = ctx->st_data->data;
    sctx = ptr;

    if (sctx[pkt->stream_index].comp_algo == 0
        && ctx->s->streams[pkt->stream_index]->codecpar->codec_type
           == AVMEDIA_TYPE_SUBTITLE) {
        size_t remlen;
        struct zlib_ctx zctx;

        zctx.sz = pkt->size;
        zctx.buf = av_buffer_alloc(zctx.sz);
        if (zctx.buf == NULL)
            return AVERROR(ENOMEM);
        zctx.len = 0;

        res = zlib_stream_init(&hdl, &zlib_stream_cb, &zctx);
        if (res != 0)
            return AVERROR(-res);

        res = zlib_stream_inflate(hdl, pkt->data, pkt->size, &remlen);
        if (res != 0 && res != 1) {
            res = AVERROR(-res);
            goto err;
        }

        zlib_stream_destroy(hdl);

        res = av_buffer_realloc(&zctx.buf, zctx.len);
        if (res != 0)
            return res;

        av_buffer_unref(&pkt->buf);
        pkt->buf = zctx.buf;
        pkt->data = pkt->buf->data;
        pkt->size = zctx.len;
    }

    return 0;

err:
    zlib_stream_destroy(hdl);
    return res;
}

static int
libmatroska_read_close(struct AVFormatContext *s)
{
    int err;
    struct libmatroska_demux_ctx *ctx = s->priv_data;

    err = matroska_close(ctx->hdl);
    regfree(&ctx->id_regex);
    return err ? AVERROR(-err) : 0;
}

/* vi: set expandtab sw=4 ts=4: */
