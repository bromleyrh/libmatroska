/*
 * mkv_decode.c
 *
 * Based on tools/decode_simple.c in FFmpeg distribution
 */

#include "libavcodec/avcodec.h"
#include "libavcodec/packet.h"

#include "libavformat/avformat.h"

#include "libavutil/frame.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

struct decode_ctx {
    AVFormatContext *fmt;
    AVStream        *st;
    int             stream_idx;
    AVCodecContext  *codec;
    AVPacket        *pkt;
    AVFrame         *frame;
};

static int decode_cb(AVFrame *, void *);

static int init_decode_ctx(struct decode_ctx *, const char *, int);
static void destroy_decode_ctx(struct decode_ctx *);

static int receive_frames(struct decode_ctx *, int (*)(AVFrame *, void *),
                          void *);

static int process_decode(struct decode_ctx *, int (*)(AVFrame *, void *),
                          void *);

static int
decode_cb(AVFrame *frame, void *ctx)
{
    (void)ctx;

    if (frame != NULL) {
        fprintf(stderr, "Coded picture number %d\n",
                frame->coded_picture_number);
    }

    return 0;
}

static int
init_decode_ctx(struct decode_ctx *ctx, const char *url, int stream_idx)
{
    const AVInputFormat *fmt;
    int ret;

    fmt = av_find_input_format("libmatroska");
    if (fmt == NULL)
        return -EIO;

    ctx->fmt = NULL;
    ret = avformat_open_input(&ctx->fmt, url, fmt, NULL);
    if (ret != 0)
        return ret;

    ctx->stream_idx = stream_idx;

    ctx->pkt = av_packet_alloc();
    if (ctx->pkt == NULL) {
        ret = -ENOMEM;
        goto err1;
    }

    ctx->frame = av_frame_alloc();
    if (ctx->frame == NULL) {
        ret = -ENOMEM;
        goto err2;
    }

    return 0;

err2:
    av_packet_free(&ctx->pkt);
err1:
    avformat_close_input(&ctx->fmt);
    return ret;
}

static void
destroy_decode_ctx(struct decode_ctx *ctx)
{
    av_frame_free(&ctx->frame);
    av_packet_free(&ctx->pkt);

    avformat_close_input(&ctx->fmt);
}

static int
receive_frames(struct decode_ctx *dctx, int (*cb)(AVFrame *, void *), void *ctx)
{
    int ret;

    for (;;) {
        ret = avcodec_receive_frame(dctx->codec, dctx->frame);
        if (ret != 0) {
            if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
                break;
            return ret;
        }

        ret = (*cb)(dctx->frame, ctx);
        av_frame_unref(dctx->frame);
        if (ret != 0)
            return ret;
    }

    return 0;
}

static int
process_decode(struct decode_ctx *dctx, int (*cb)(AVFrame *, void *), void *ctx)
{
    const AVCodec *codec;
    int init = 0;
    int ret, tmp;

    ret = av_read_frame(dctx->fmt, dctx->pkt);
    if (ret != 0)
        return ret == AVERROR_EOF ? 0 : -EIO;

    if (dctx->stream_idx >= dctx->fmt->nb_streams)
        return -EINVAL;
    dctx->st = dctx->fmt->streams[dctx->stream_idx];

    codec = avcodec_find_decoder(dctx->st->codecpar->codec_id);
    if (codec == NULL)
        return -EPROTO;

    dctx->codec = avcodec_alloc_context3(codec);
    if (dctx->codec == NULL)
        return -ENOMEM;

    if (dctx->pkt->stream_index == dctx->st->index) {
        ret = avcodec_parameters_to_context(dctx->codec, dctx->st->codecpar);
        if (ret != 0)
            return -EIO;

        if (avcodec_open2(dctx->codec, NULL, NULL) != 0) {
            avcodec_free_context(&dctx->codec);
            return -ENOMEM;
        }

        init = 1;

        ret = avcodec_send_packet(dctx->codec, dctx->pkt);
        av_packet_unref(dctx->pkt);
        if (ret != 0) {
            ret = -EIO;
            goto end;
        }

        ret = receive_frames(dctx, cb, ctx);
        if (ret != 0)
            goto end;
    } else
        av_packet_unref(dctx->pkt);

    for (;;) {
        ret = av_read_frame(dctx->fmt, dctx->pkt);
        if (ret != 0) {
            if (ret == AVERROR_EOF)
                ret = 0;
            break;
        }
        if (dctx->pkt->stream_index != dctx->st->index) {
            av_packet_unref(dctx->pkt);
            continue;
        }

        if (!init) {
            ret = avcodec_parameters_to_context(dctx->codec,
                                                dctx->st->codecpar);
            if (ret != 0)
                return -EIO;

            if (avcodec_open2(dctx->codec, NULL, NULL) != 0) {
                avcodec_free_context(&dctx->codec);
                return -ENOMEM;
            }

            init = 1;
        }

        ret = avcodec_send_packet(dctx->codec, dctx->pkt);
        av_packet_unref(dctx->pkt);
        if (ret != 0)
            break;

        ret = receive_frames(dctx, cb, ctx);
        if (ret != 0)
            break;
    }

end:
    if (init) {
        avcodec_send_packet(dctx->codec, NULL);
        tmp = receive_frames(dctx, cb, ctx);
        avcodec_close(dctx->codec);
        if (tmp != 0)
            return tmp;
    }
    return ret;
}

int
main(int argc, char **argv)
{
    const char *url;
    int ret;
    int stream_idx;
    struct decode_ctx ctx;

    if (argc < 3) {
        fputs("Must specify URL and stream index\n", stderr);
        return EXIT_FAILURE;
    }
    url = argv[1];
    stream_idx = atoi(argv[2]);

    if (init_decode_ctx(&ctx, url, stream_idx) != 0) {
        fprintf(stderr, "Error opening %s\n", url);
        return EXIT_FAILURE;
    }

    ret = process_decode(&ctx, &decode_cb, NULL);

    destroy_decode_ctx(&ctx);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
