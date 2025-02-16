/*
 * parser.h
 */

#ifndef _PARSER_H
#define _PARSER_H

#if _FILE_OFFSET_BITS != 64
#error "'-D_FILE_OFFSET_BITS=64' is required to use this module"
#endif

#include "element.h"

#include <stddef.h>

#include <sys/types.h>

struct parser;

struct semantic_processor;

struct buf;

typedef int semantic_action_t(const char *, enum etype, edata_t *, void **,
                              size_t *, void **, size_t *, size_t, size_t,
                              struct buf *, off_t, void *, int);

struct elem_data {
    const char              *val;
    semantic_action_t       *act;
    enum etype              etype;
    const struct elem_data  *const *ref;
};

extern const struct parser ebml_parser;
#define EBML_PARSER (&ebml_parser)

extern const struct parser matroska_parser;
#define MATROSKA_PARSER (&matroska_parser)

extern const struct semantic_processor matroska_semantic_processor;
#define MATROSKA_SEMANTIC_PROCESSOR (&matroska_semantic_processor)

extern const struct elem_data *ebml_data;

const char *parser_desc(const struct parser *parser);

int parser_look_up(const struct parser *parser, const char *str,
                   const struct elem_data **data,
                   const struct elem_data **ebml_parent);

int semantic_processor_look_up(const struct semantic_processor *sproc,
                               const char *str, semantic_action_t **act);

#endif

/* vi: set expandtab sw=4 ts=4: */
