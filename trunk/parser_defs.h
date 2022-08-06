/*
 * parser_defs.h
 */

#ifndef _PARSER_DEFS_H
#define _PARSER_DEFS_H

#include "element.h"

#include <stddef.h>

struct trie_node {
    const char              *label;
    const struct trie_node  *children[256];
    const char              *val;
    enum etype              etype;
};

#define __DEF_TRIE_NODE_BRANCH(prefix, nm, lbl, ...) \
    static const struct trie_node prefix##_trie_node_##nm = { \
        .label = lbl, \
        __VA_ARGS__ \
    }

#define __DEF_TRIE_NODE_INFORMATION(prefix, nm, lbl, value, typ) \
    static const struct trie_node prefix##_trie_node_##nm = { \
        .label = lbl, \
        .val = value, \
        .etype = typ \
    }

#define __ENTRY(prefix, key, nm) \
    .children[(unsigned char)key] = &prefix##_trie_node_##nm

#define _DEF_TRIE_NODE_BRANCH(prefix, nm, lbl, ...) \
    __DEF_TRIE_NODE_BRANCH(prefix, nm, lbl, __VA_ARGS__)

#define _DEF_TRIE_NODE_INFORMATION(...) \
    __DEF_TRIE_NODE_INFORMATION(__VA_ARGS__)

#define _ENTRY(...) __ENTRY(__VA_ARGS__)

#define DEF_TRIE_NODE_BRANCH(nm, lbl, ...) \
    _DEF_TRIE_NODE_BRANCH(TRIE_NODE_PREFIX, nm, lbl, __VA_ARGS__)

#define DEF_TRIE_NODE_INFORMATION(...) \
    _DEF_TRIE_NODE_INFORMATION(TRIE_NODE_PREFIX, __VA_ARGS__)

#define ENTRY(...) _ENTRY(TRIE_NODE_PREFIX, __VA_ARGS__)

#define TRIE_ROOT(doctype) doctype##_TRIE_ROOT

#endif

/* vi: set expandtab sw=4 ts=4: */
