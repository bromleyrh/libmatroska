/*
 * parser.h
 */

#ifndef _PARSER_H
#define _PARSER_H

#include "element.h"

struct parser;

extern const struct parser ebml_parser;
#define EBML_PARSER (&ebml_parser)

extern const struct parser matroska_parser;
#define MATROSKA_PARSER (&matroska_parser)

const char *parser_desc(const struct parser *parser);

int parser_look_up(const struct parser *parser, const char *str,
                   const char **val, enum etype *etype);

#endif

/* vi: set expandtab sw=4 ts=4: */
