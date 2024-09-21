/*
 * libmatroska_codecs.h
 */

#ifndef _MATROSKA_CODECS_H
#define _MATROSKA_CODECS_H

#include "libavcodec/codec_id.h"

struct libmatroska_codec {
    const char      *name;
    enum AVCodecID  codec_id;
};

const struct libmatroska_codec *libmatroska_codec_id_find(const char *str,
                                                          unsigned int len);

#endif

/* vi: set expandtab sw=4 ts=4: */
