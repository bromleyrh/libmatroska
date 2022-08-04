/*
 * parser.h
 */

#ifndef _PARSER_H
#define _PARSER_H

struct parser;

extern const struct parser ebml_parser;
#define EBML_PARSER (&ebml_parser)

extern const struct parser matroska_parser;
#define MATROSKA_PARSER (&matroska_parser)

int parser_look_up(const struct parser *parser, const char *str,
                   const char **val);

#endif

/* vi: set expandtab sw=4 ts=4: */
