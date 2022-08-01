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

#define DEF_TRIE_NODE_BRANCH(nm, lbl, ...) \
    static const struct trie_node trie_node_##nm = { \
        .label = lbl, \
        __VA_ARGS__ \
    }

#define DEF_TRIE_NODE_INFORMATION(nm, lbl, value) \
    static const struct trie_node trie_node_##nm = { \
        .label = lbl, \
        .val = value \
    }

#define ENTRY(key, nm) .children[(unsigned char)key] = &trie_node_##nm

#endif

/* vi: set expandtab sw=4 ts=4: */
