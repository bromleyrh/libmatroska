/*
 * parser_defs.h
 */

#ifndef _PARSER_DEFS_H
#define _PARSER_DEFS_H

#include "element.h"
#include "parser.h"

#include <stddef.h>

struct trie_node {
    const char              *label;
    const struct trie_node  *children[256];
    const struct elem_data  *data;
    const struct elem_data  *ebml_parent;
};

#define __DEF_EBML_DATA(prefix, nm, value, action, typ) \
    static const struct elem_data prefix##_elem_data_##nm = { \
        .val    = value, \
        .act    = action, \
        .etype  = typ \
    }

#define _DEF_EBML_DATA(...) __DEF_EBML_DATA(__VA_ARGS__)

#define DEF_EBML_DATA(...) \
    _DEF_EBML_DATA(TRIE_NODE_PREFIX, __VA_ARGS__)

#define __EBML_PARENT(prefix, nm) &prefix##_elem_data_##nm
#define _EBML_PARENT(...) __EBML_PARENT(__VA_ARGS__)
#define EBML_PARENT(...) _EBML_PARENT(TRIE_NODE_PREFIX, __VA_ARGS__)

#define EBML_PARENT_NIL(nm) NULL

#define __DEF_TRIE_NODE_BRANCH(prefix, nm, lbl, ...) \
    static const struct trie_node prefix##_trie_node_##nm = { \
        .label = lbl, \
        __VA_ARGS__ \
    }

#define __DEF_TRIE_NODE_INFORMATION(prefix, nm, lbl, ebml_par) \
    static const struct trie_node prefix##_trie_node_##nm = { \
        .label          = lbl, \
        .data           = &prefix##_elem_data_##nm, \
        .ebml_parent    = ebml_par \
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
