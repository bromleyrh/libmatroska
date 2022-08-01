/*
 * parser.c
 */

#include "common.h"
#include "parser.h"
#include "parser_defs.h"

#include "matroska_schema.h"

struct parser {
    const struct trie_node *id_root;
};

EXPORTED const struct parser matroska_parser = {
    .id_root = TRIE_ROOT
};

/* vi: set expandtab sw=4 ts=4: */
