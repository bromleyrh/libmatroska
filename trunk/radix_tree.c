/*
 * radix_tree.c
 */

#include "common.h"
#include "radix_tree.h"

#include <dynamic_array.h>
#include <malloc_ext.h>
#include <strings_ext.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct radix_tree_edge {
    const char              *label;
    struct radix_tree_node  *dst;
};

struct walk_info {
    struct radix_tree_node  *node;
    int                     childidx;
    int                     lenlabel;
};

#define NODE_SIZE(rt) \
    (offsetof(struct radix_tree_node, val) + (rt)->val_size)

#ifdef NDEBUG
#define DEBUG if (0)
#else
#define DEBUG if (1)
#endif

#define MAGIC_VALID(strct, type) ((strct)->magic == type ## _MAGIC)

#define TREE_VALID(rt) MAGIC_VALID(rt, RADIX_TREE)
#define NODE_VALID(node) MAGIC_VALID(node, RADIX_TREE_NODE)

#define FOREACH_CHILD(i, node, start) \
    for ((i) = start; (i) < (int)ARRAY_SIZE((node)->children); (i)++)

static int check_nchildren(struct radix_tree_node *);

static void subtree_free(struct radix_tree_node *);

static int new_node(struct radix_tree *, struct radix_tree_node **,
                    enum radix_tree_node_type, const char *, ssize_t,
                    const void *);
static void free_node(struct radix_tree_node *);

static int find_edge(const struct radix_tree_node *, unsigned char,
                     struct radix_tree_edge *);
static int traverse_edge(const struct radix_tree_edge *, const char **);
static int split_edge(struct radix_tree *, struct radix_tree_node *,
                      struct radix_tree_edge *, int, const char *,
                      const void *);

static int do_insert(struct radix_tree *, struct radix_tree_node *,
                     const char *, const void *);

static int do_search(struct radix_tree *, struct radix_tree_node *,
                     const char *, void *);

static int concat_labels(const char *, const char *, const char **);

static int do_delete(struct radix_tree *, struct radix_tree_node *,
                     const char *);

static int push_label(struct dynamic_array *, const char *, int *);
static int pop_label(struct dynamic_array *, int);

static int process_children(struct walk_info *, struct dynamic_array *,
                            struct dynamic_array *, int *);
static int do_walk(struct radix_tree_node *, radix_tree_walk_cb_t, void *);
static int do_serialize(struct radix_tree_node *, radix_tree_sr_cb_t, void *);

static int
check_nchildren(struct radix_tree_node *node)
{
    int i, n;

    n = 0;
    FOREACH_CHILD(i, node, 0) {
        if (node->children[i] != NULL)
            ++n;
    }

    return node->nchildren == n ? 0 : -EIO;
}

static void
subtree_free(struct radix_tree_node *node)
{
    int i, n;

    if (node->nchildren > 0) {
        n = 0;
        FOREACH_CHILD(i, node, 0) {
            if (node->children[i] == NULL)
                continue;
            ++n;
            subtree_free(node->children[i]);
            if (n == node->nchildren)
                break;
        }
    }

    free_node(node);
}

static int
new_node(struct radix_tree *rt, struct radix_tree_node **node,
         enum radix_tree_node_type type, const char *label, ssize_t lenlabel,
         const void *val)
{
    int err;
    struct radix_tree_node *ret;

    ret = calloc(1, NODE_SIZE(rt));
    if (ret == NULL)
        return MINUS_ERRNO;

    ret->type = type;

    if (label == NULL)
        ret->label = NULL;
    else {
        ret->label = lenlabel < 0 ? strdup(label) : strndup(label, lenlabel);
        if (ret->label == NULL) {
            err = MINUS_ERRNO;
            free(ret);
            return err;
        }
    }

    if (ret->type == NODE_TYPE_INFORMATION)
        memcpy(ret->val, val, rt->val_size);

    ret->magic = RADIX_TREE_NODE_MAGIC;

    *node = ret;
    return 0;
}

static void
free_node(struct radix_tree_node *node)
{
    free((void *)node->label);
    free(node);
}

static int
find_edge(const struct radix_tree_node *src, unsigned char digit,
          struct radix_tree_edge *edge)
{
    struct radix_tree_node *dst = src->children[digit];

    if (dst == NULL)
        return -1;

    edge->label = dst->label;
    edge->dst = dst;

    return 0;
}

static int
traverse_edge(const struct radix_tree_edge *edge, const char **str)
{
    int i;

    for (i = 0;; i++) {
        if (edge->label[i] != **str)
            break;
        if (**str == '\0') {
            if (edge->dst->type == NODE_TYPE_INFORMATION)
                return -1;
            break;
        }
        ++*str;
    }

    return i;
}

static int
split_edge(struct radix_tree *rt, struct radix_tree_node *src,
           struct radix_tree_edge *edge, int idx, const char *str,
           const void *val)
{
    const char *newlabel;
    int err;
    struct radix_tree_node *branch_node, *info_node;

    err = new_node(rt, &branch_node, NODE_TYPE_BRANCH, edge->label, idx, NULL);
    if (err)
        return err;

    err = new_node(rt, &info_node, NODE_TYPE_INFORMATION, str, -1, val);
    if (err) {
        free_node(branch_node);
        return err;
    }

    branch_node->children[(unsigned char)edge->label[idx]] = edge->dst;
    branch_node->children[(unsigned char)str[0]] = info_node;
    branch_node->nchildren = 2;

    newlabel = strdup(&edge->label[idx]);
    if (newlabel == NULL) {
        err = MINUS_ERRNO;
        free_node(branch_node);
        free_node(info_node);
        return err;
    }

    src->children[(unsigned char)edge->label[0]] = branch_node;
    free((void *)edge->dst->label);
    edge->dst->label = newlabel;

#ifndef NDEBUG
    ++rt->stats.num_branch_nodes;
    ++rt->stats.edge_splits;
#endif
    ++rt->stats.num_info_nodes;

    return 0;
}

static int
do_insert(struct radix_tree *rt, struct radix_tree_node *node, const char *str,
          const void *val)
{
    int err;
    int idx;
    struct radix_tree_edge edge;
    struct radix_tree_node *info_node;
    unsigned char digit;

    for (;;) {
        DEBUG {
            if (!NODE_VALID(node))
                return -EIO;
            if (check_nchildren(node) != 0) {
                fputs("nchildren invalid\n", stderr);
                return -EIO;
            }
        }

        digit = str[0];

        if (find_edge(node, digit, &edge) == -1)
            break;

        idx = traverse_edge(&edge, &str);
        if (idx == -1)
            return -EADDRINUSE;

        if (edge.label[idx] != '\0')
            goto branch;

        node = edge.dst;
    }

    err = new_node(rt, &info_node, NODE_TYPE_INFORMATION, str, -1, val);
    if (err)
        return err;
    if (node->type == NODE_TYPE_INFORMATION) {
        err = new_node(rt, &node->children[0], NODE_TYPE_INFORMATION, "", -1,
                       node->val);
        if (err) {
            free_node(info_node);
            return err;
        }

        node->type = NODE_TYPE_BRANCH;
        node->nchildren += 2;
#ifndef NDEBUG
        ++rt->stats.num_branch_nodes;
#endif
    } else
        ++node->nchildren;
    node->children[digit] = info_node;

    ++rt->stats.num_info_nodes;

    return 0;

branch:
    return split_edge(rt, node, &edge, idx, str, val);
}

static int
do_search(struct radix_tree *rt, struct radix_tree_node *node, const char *str,
          void *val)
{
    struct radix_tree_edge edge;

    for (;;) {
        const unsigned char digit = str[0];
        int idx;

        DEBUG {
            if (!NODE_VALID(node))
                return -EIO;
            if (check_nchildren(node) != 0) {
                fputs("nchildren invalid\n", stderr);
                return -EIO;
            }
        }

        if (find_edge(node, digit, &edge) == -1)
            return 0;

        idx = traverse_edge(&edge, &str);
        if (idx == -1)
            break;

        if (edge.label[idx] != '\0')
            return 0;

        node = edge.dst;
    }

    memcpy(val, edge.dst->val, rt->val_size);

    return 1;
}

static int
concat_labels(const char *label1, const char *label2, const char **newlabel)
{
    char *ret;

    ret = malloc(strlen(label1) + strlen(label2) + 1);
    if (ret == NULL)
        return MINUS_ERRNO;

    strcpy(stpcpy(ret, label1), label2);

    *newlabel = ret;
    return 0;
}

static int
do_delete(struct radix_tree *rt, struct radix_tree_node *node, const char *str)
{
    int err;
    int idx;
    struct radix_tree_edge edge;
    struct radix_tree_node *parent = NULL;
    unsigned char digit, parentidx = 0;

    for (;;) {
        DEBUG {
            if (!NODE_VALID(node))
                return -EIO;
            if (check_nchildren(node) != 0) {
                fputs("nchildren invalid\n", stderr);
                return -EIO;
            }
        }

        digit = str[0];

        if (find_edge(node, digit, &edge) == -1)
            return -EADDRNOTAVAIL;

        idx = traverse_edge(&edge, &str);
        if (idx == -1)
            break;

        if (edge.label[idx] != '\0')
            return -EADDRNOTAVAIL;

        parent = node;
        parentidx = digit;
        node = edge.dst;
    }

    if (node->type == NODE_TYPE_BRANCH && node->nchildren == 2) {
        /* merge node and remaining child */
        const char *newlabel = NULL;
        struct radix_tree_node *child = NULL;

        assert(parent != NULL);

        FOREACH_CHILD(idx, node, 0) {
            if (idx == digit)
                continue;
            if (node->children[idx] != NULL) {
                child = node->children[idx];
                break;
            }
        }
        if (child == NULL)
            abort();

        err = concat_labels(node->label, child->label, &newlabel);
        if (err)
            return err;

        parent->children[parentidx] = child;

        free((void *)child->label);
        child->label = newlabel;

        free_node(node);
#ifndef NDEBUG
        --rt->stats.num_branch_nodes;
        ++rt->stats.node_merges;
#endif
    } else {
        node->children[digit] = NULL;
        --node->nchildren;
    }

    free_node(edge.dst);

    --rt->stats.num_info_nodes;

    return 0;
}

static int
push_label(struct dynamic_array *str, const char *label, int *lenlabel)
{
    int err;
    int len;

    for (len = 0; *label != '\0'; len++) {
        err = dynamic_array_push_back(str, label);
        if (err)
            return err;
        ++label;
    }

    *lenlabel = len;
    return 0;
}

static int
pop_label(struct dynamic_array *str, int lenlabel)
{
    int err;
    size_t len;

    err = dynamic_array_size(str, &len);
    if (err)
        return err;

    return dynamic_array_truncate(str, len - lenlabel);
}

static int
process_children(struct walk_info *info, struct dynamic_array *str,
                 struct dynamic_array *nodestack, int *level)
{
    int err;
    int i;
    struct radix_tree_node *n = info->node;
    struct walk_info tmp;

    FOREACH_CHILD(i, n, info->childidx) {
        if (n->children[i] != NULL)
            break;
    }

    if (i < (int)ARRAY_SIZE(n->children)) {
        info->childidx = i + 1;

        err = push_label(str, n->children[i]->label, &tmp.lenlabel);
        if (err)
            return err;

        tmp.node = n->children[i];
        tmp.childidx = 0;
        err = dynamic_array_push_back(nodestack, &tmp);
        if (err)
            return err;
        ++*level;

        return 1;
    }

    return 0;
}

static int
do_walk(struct radix_tree_node *node, radix_tree_walk_cb_t fn, void *ctx)
{
    int level;
    int ret;
    struct dynamic_array *nodestack, *str;
    struct walk_info tmp;

    ret = dynamic_array_new(&nodestack, 32, sizeof(struct walk_info));
    if (ret != 0)
        return ret;
    ret = dynamic_array_new(&str, 32, sizeof(char));
    if (ret != 0) {
        dynamic_array_free(nodestack);
        return ret;
    }

    tmp.node = node;
    tmp.childidx = 0;
    tmp.lenlabel = 0;
    ret = dynamic_array_push_back(nodestack, &tmp);
    if (ret != 0)
        goto err;
    level = 0;

    while (level >= 0) {
        struct walk_info *info;

        info = &((struct walk_info *)dynamic_array_buf(nodestack))[level];

        DEBUG {
            if (!NODE_VALID(info->node))
                return -EIO;
            ret = check_nchildren(info->node);
            if (ret != 0) {
                fputs("nchildren invalid\n", stderr);
                return -EIO;
            }
        }

        if (info->node->type == NODE_TYPE_INFORMATION) {
            const char nullchar = '\0';

            ret = dynamic_array_push_back(str, &nullchar);
            if (ret != 0)
                return ret;
            ++info->lenlabel;
            ret = (*fn)(dynamic_array_buf(str), info->node->val, ctx);
            if (ret != 0)
                return ret;
        } else if ((ret = process_children(info, str, nodestack, &level))
                   != 0) {
            if (ret == 1)
                continue;
            return ret;
        }

        ret = pop_label(str, info->lenlabel);
        if (ret != 0)
            return ret;

        ret = dynamic_array_pop_back(nodestack);
        if (ret != 0)
            return ret;
        --level;
    }

    dynamic_array_free(nodestack);
    dynamic_array_free(str);

    return 0;

err:
    dynamic_array_free(nodestack);
    dynamic_array_free(str);
    return ret;
}

static int
do_serialize(struct radix_tree_node *node, radix_tree_sr_cb_t fn, void *ctx)
{
    int level;
    int ret;
    struct dynamic_array *nodestack, *str;
    struct walk_info tmp;

    ret = dynamic_array_new(&nodestack, 32, sizeof(struct walk_info));
    if (ret != 0)
        return ret;
    ret = dynamic_array_new(&str, 32, sizeof(char));
    if (ret != 0) {
        dynamic_array_free(nodestack);
        return ret;
    }

    tmp.node = node;
    tmp.childidx = 0;
    tmp.lenlabel = 0;
    ret = dynamic_array_push_back(nodestack, &tmp);
    if (ret != 0)
        goto err;
    level = 0;

    while (level >= 0) {
        struct walk_info *info;

        info = &((struct walk_info *)dynamic_array_buf(nodestack))[level];

        DEBUG {
            if (!NODE_VALID(info->node))
                return -EIO;
            ret = check_nchildren(info->node);
            if (ret != 0) {
                fputs("nchildren invalid\n", stderr);
                return -EIO;
            }
        }

        if (info->node->type == NODE_TYPE_INFORMATION) {
            const char nullchar = '\0';

            ret = dynamic_array_push_back(str, &nullchar);
            if (ret != 0)
                return ret;
            ++info->lenlabel;
            ret = (*fn)(info->node, dynamic_array_buf(str), info->node->val,
                        ctx);
            if (ret != 0)
                return ret;
        } else {
            ret = process_children(info, str, nodestack, &level);
            if (ret != 0) {
                if (ret == 1)
                    continue;
                return ret;
            }
            ret = (*fn)(info->node, NULL, NULL, ctx);
            if (ret != 0)
                return ret;
        }

        ret = pop_label(str, info->lenlabel);
        if (ret != 0)
            return ret;

        ret = dynamic_array_pop_back(nodestack);
        if (ret != 0)
            return ret;
        --level;
    }

    dynamic_array_free(nodestack);
    dynamic_array_free(str);

    return 0;

err:
    dynamic_array_free(nodestack);
    dynamic_array_free(str);
    return ret;
}

int
radix_tree_new(struct radix_tree **rt, size_t val_size)
{
    int err;
    struct radix_tree *ret;

    if (rt == NULL)
        return -EINVAL;

    if (omalloc(&ret) == NULL)
        return MINUS_ERRNO;

    ret->val_size = val_size;

    err = new_node(ret, &ret->root, NODE_TYPE_ROOT, NULL, -1, NULL);
    if (err) {
        free(ret);
        return err;
    }

    omemset(&ret->stats, 0);

    ret->magic = RADIX_TREE_MAGIC;

    *rt = ret;
    return 0;
}

int
radix_tree_free(struct radix_tree *rt)
{
    if (rt == NULL || !TREE_VALID(rt))
        return -EINVAL;

    rt->magic = 0;

    subtree_free(rt->root);
    free(rt);

    return 0;
}

int
radix_tree_insert(struct radix_tree *rt, const char *str, const void *val)
{
    int err;

    if (rt == NULL || !TREE_VALID(rt) || str == NULL || val == NULL)
        return -EINVAL;

    err = do_insert(rt, rt->root, str, val);
    if (err)
        return err;

#ifndef NDEBUG
    ++rt->stats.insertions;

#endif
    return 0;
}

int
radix_tree_search(struct radix_tree *rt, const char *str, void *val)
{
    int ret;

    if (rt == NULL || !TREE_VALID(rt) || str == NULL || val == NULL)
        return -EINVAL;

    ret = do_search(rt, rt->root, str, val);

#ifndef NDEBUG
    if (ret == 0)
        ++rt->stats.search_misses;
    else if (ret == 1)
        ++rt->stats.search_hits;

#endif
    return ret;
}

int
radix_tree_delete(struct radix_tree *rt, const char *str)
{
    int err;

    if (rt == NULL || !TREE_VALID(rt) || str == NULL)
        return -EINVAL;

    err = do_delete(rt, rt->root, str);
    if (err)
        return err;

#ifndef NDEBUG
    --rt->stats.deletions;

#endif
    return 0;
}

int
radix_tree_walk(const struct radix_tree *rt, radix_tree_walk_cb_t fn, void *ctx)
{
    if (rt == NULL || !TREE_VALID(rt) || fn == NULL)
        return -EINVAL;

    return do_walk(rt->root, fn, ctx);
}

int
radix_tree_serialize(const struct radix_tree *rt, radix_tree_sr_cb_t fn,
                     void *ctx)
{
    if (rt == NULL || !TREE_VALID(rt) || fn == NULL)
        return -EINVAL;

    return do_serialize(rt->root, fn, ctx);
}

int
radix_tree_stats(const struct radix_tree *rt, struct radix_tree_stats *stats)
{
    if (rt == NULL || !TREE_VALID(rt))
        return -EINVAL;

    if (stats != NULL) {
#ifdef NDEBUG
        omemset(stats, 0);
        stats->num_info_nodes = rt->stats.num_info_nodes;
#else
        *stats = rt->stats;
#endif
    }

    return 0;
}

/* vi: set expandtab sw=4 ts=4: */
