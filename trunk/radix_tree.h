/*
 * radix_tree.h
 */

#ifndef _RADIX_TREE_H
#define _RADIX_TREE_H

#include <stddef.h>
#include <stdint.h>

typedef int (*radix_tree_walk_cb_t)(const char *str, void *val, void *ctx);

typedef struct radix_tree_stats {
#ifdef NDEBUG
    unsigned num_info_nodes;
#else
    unsigned num_branch_nodes;
    unsigned num_info_nodes;
    uint64_t insertions;
    uint64_t deletions;
    uint64_t search_hits;
    uint64_t search_misses;
    uint64_t edge_splits;
    uint64_t node_merges;
#endif
} radix_tree_stats_t;

#define RADIX_TREE_MAGIC 0x54444152

struct radix_tree {
    uint32_t                magic;
    struct radix_tree_node  *root;
    size_t                  val_size;
    radix_tree_stats_t      stats;
};

enum radix_tree_node_type {
    NODE_TYPE_ROOT,
    NODE_TYPE_BRANCH,
    NODE_TYPE_INFORMATION
};

#define RADIX_TREE_NODE_MAGIC 0x004e5452

struct radix_tree_node {
    uint32_t                    magic:30;
    enum radix_tree_node_type   type:2;
    const char                  *label;
    struct radix_tree_node      *children[256];
    int                         nchildren;
    char                        val[]; /* used in information nodes */
};

int radix_tree_new(struct radix_tree **rt, size_t val_size);

int radix_tree_free(struct radix_tree *rt);

int radix_tree_insert(struct radix_tree *rt, const char *str, const void *val);

int radix_tree_search(struct radix_tree *rt, const char *str, void *val);

int radix_tree_delete(struct radix_tree *rt, const char *str);

int radix_tree_walk(const struct radix_tree *rt, radix_tree_walk_cb_t fn,
                    void *ctx);

int radix_tree_stats(const struct radix_tree *rt,
                     struct radix_tree_stats *stats);

#endif

/* vi: set expandtab sw=4 ts=4: */
