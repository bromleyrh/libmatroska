/*
 * parser_defs.h
 */

#ifndef _PARSER_DEFS_H
#define _PARSER_DEFS_H

#include <stddef.h>

struct trie_node {
    const char              *label;
    const struct trie_node  *children[256];
    const char              *val;
};

#endif

/* vi: set expandtab sw=4 ts=4: */
