/*
 * parser.c
 */

#include "common.h"
#include "parser.h"
#include "parser_defs.h"

#include "ebml_schema.h"
#include "matroska_schema.h"

#include <errno.h>
#include <stddef.h>
#include <string.h>

struct parser {
    const struct trie_node *id_root;
};

struct trie_edge {
    const char              *label;
    const struct trie_node  *dst;
};

EXPORTED const struct parser ebml_parser = {
    .id_root = EBML_TRIE_ROOT
};

EXPORTED const struct parser matroska_parser = {
    .id_root = MATROSKA_TRIE_ROOT
};

static int find_trie_edge(const struct trie_node *, unsigned char,
                          struct trie_edge *);

static int traverse_trie_edge(const struct trie_edge *, const char **);

static int do_trie_search(const struct trie_node *, const char *,
                          const char **);

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
do_trie_search(const struct trie_node *node, const char *str, const char **val)
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

    *val = edge.dst->val;

    return 1;
}

int
parser_look_up(const struct parser *parser, const char *str, const char **val)
{
    return do_trie_search(parser->id_root, str, val);
}

/* vi: set expandtab sw=4 ts=4: */
