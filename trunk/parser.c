/*
 * parser.c
 */

#include "common.h"
#include "element.h"
#include "parser.h"
#include "parser_defs.h"

#include "ebml_schema.h"
#include "matroska_schema.h"

#include "matroska_semantics.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>

struct parser {
    const struct trie_node  *id_root;
    const char              *desc;
};

struct semantic_processor {
    const struct trie_node  *id_root;
    const char              *desc;
};

struct trie_edge {
    const char              *label;
    const struct trie_node  *dst;
};

#define DEF_PARSER(nm, descr) \
    EXPORTED const struct parser nm##_parser = { \
        .id_root    = TRIE_ROOT(nm), \
        .desc       = descr \
    };

#define DEF_SEMANTIC_PROCESSOR(nm, descr) \
    EXPORTED const struct semantic_processor nm##_semantic_processor = { \
        .id_root    = TRIE_ROOT(nm##_semantics), \
        .desc       = descr \
    };

#define LIST_PARSERS() \
    _X(ebml,        "EBML") \
    _X(matroska,    "Matroska")

#define LIST_SEMANTIC_PROCESSORS() \
    _X(matroska, "Matroska semantics")

#define _X DEF_PARSER
LIST_PARSERS()
#undef _X

#define _X DEF_SEMANTIC_PROCESSOR
LIST_SEMANTIC_PROCESSORS()
#undef _X

static int find_trie_edge(const struct trie_node *, unsigned char,
                          struct trie_edge *);

static int traverse_trie_edge(const struct trie_edge *, const char **);

static int do_trie_search(const struct trie_node *, const char *,
                          const char **, int (**)(const char *, void *),
                          enum etype *);

static int
find_trie_edge(const struct trie_node *src, unsigned char digit,
               struct trie_edge *edge)
{
    const struct trie_node *dst = src->children[digit];

    if (dst == NULL)
        return -1;

    edge->label = dst->label;
    edge->dst = dst;

    return 0;
}

static int
traverse_trie_edge(const struct trie_edge *edge, const char **str)
{
    int i;

    for (i = 0;; i++) {
        if (edge->label[i] != **str)
            break;
        if (**str == '\0') {
            if (edge->dst->val != NULL)
                return -1;
            break;
        }
        ++*str;
    }

    return i;
}

static int
do_trie_search(const struct trie_node *node, const char *str, const char **val,
               int (**handler)(const char *, void *), enum etype *etype)
{
    struct trie_edge edge;

    for (;;) {
        const unsigned char digit = str[0];
        int idx;

        if (find_trie_edge(node, digit, &edge) == -1)
            return 0;

        idx = traverse_trie_edge(&edge, &str);
        if (idx == -1)
            break;

        if (edge.label[idx] != '\0')
            return 0;

        node = edge.dst;
    }

    if (val != NULL)
        *val = edge.dst->val;
    if (handler != NULL)
        *handler = edge.dst->handler;
    if (etype != NULL)
        *etype = edge.dst->etype;

    return 1;
}

const char *
parser_desc(const struct parser *parser)
{
    return parser->desc;
}

int
parser_look_up(const struct parser *parser, const char *str, const char **val,
               enum etype *etype)
{
    return do_trie_search(parser->id_root, str, val, NULL, etype);
}

int
semantic_processor_look_up(const struct semantic_processor *sproc,
                           const char *str,
                           int (**handler)(const char *, void *))
{
    return do_trie_search(sproc->id_root, str, NULL, handler, NULL);
}

/* vi: set expandtab sw=4 ts=4: */
