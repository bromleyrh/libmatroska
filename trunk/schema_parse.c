/*
 * schema_parse.c
 */

#define _WITH_GETLINE

#include "common.h"
#include "element.h"
#include "radix_tree.h"
#include "std_sys.h"
#include "util.h"

#include <avl_tree.h>
#include <crypto.h>
#include <strings_ext.h>

#include <files/util.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlschemas.h>

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

enum op {
    PROCESS_SCHEMA = 1,
    DUMP_PATHS,
    PROCESS_PATHS
};

struct id_node {
    char            *name;
    char            *handler;
    enum etype      type;
    struct id_node  *parent_idnode;
    const char      *ref;
};

enum ns_obj_type {
    TYPE_DIR = 1,
    TYPE_ENT
};

struct ns_key {
    void                *addr;
    char                *name;
    enum ns_obj_type    type;
    void                *dir_addr;
    struct id_node      *idnode;
};

struct ns_dump_ctx {
    FILE    *f;
    int     cb_err;
};

#define EBML_ELEMENT_ID 0xa45dfa3
#define EBML_ELEMENT_ID_WITH_MARKER 0x1a45dfa3

static int ns_key_cmp(const void *, const void *, void *);

static int ns_key_output(const void *, void *);
static int ns_key_free(const void *, void *);

static int ns_init(struct avl_tree **);
static void ns_destroy(struct avl_tree *);
static int ns_insert(struct avl_tree *, struct ns_key *, const char *);
static int ns_look_up(struct avl_tree *, const char *, struct ns_key *);
static int ns_dump(FILE *, struct avl_tree *);

static int do_printf(jmp_buf *, const char *, ...);

static int parse_EBMLSchema(enum op, xmlNode *, struct avl_tree *,
                            struct radix_tree *);
static int parse_element(enum op, xmlNode *, struct avl_tree *,
                         struct radix_tree *);
static int parse_enum(enum op, xmlNode *, struct avl_tree *,
                      struct radix_tree *);
static int parse_restriction(enum op, xmlNode *, struct avl_tree *,
                             struct radix_tree *);
static int parse_documentation(enum op, xmlNode *, struct avl_tree *,
                               struct radix_tree *);
static int parse_implementation_note(enum op, xmlNode *, struct avl_tree *,
                                     struct radix_tree *);
static int parse_extension(enum op, xmlNode *, struct avl_tree *,
                           struct radix_tree *);

static uint64_t get_node_id(const void *);

static int sr_fn(const struct radix_tree_node *, const char *, void *, void *);
static int free_fn(const char *, void *, void *);

static int do_radix_tree_free(struct radix_tree *);

static int _output_parser_data(enum op, xmlNode *, int, struct avl_tree *,
                               struct radix_tree *);

static int output_parser_data(enum op, xmlDocPtr, const char *, const char *);

static int process_paths(int, int);

static int
ns_key_cmp(const void *k1, const void *k2, void *ctx)
{
    const struct ns_key *key1 = *(struct ns_key *const *)k1;
    const struct ns_key *key2 = *(struct ns_key *const *)k2;
    int cmp;

    (void)ctx;

    cmp = (key1->addr > key2->addr) - (key1->addr < key2->addr);
    return cmp == 0 ? strcmp(key1->name, key2->name) : cmp;
}

static int
ns_key_output(const void *k, void *ctx)
{
    const struct ns_key *key = *(struct ns_key *const *)k;
    const struct ns_key **dir_stk;
    FILE *f = ctx;
    int err;
    size_t len, sz;

    sz = 16;
    dir_stk = malloc(sz * sizeof(*dir_stk));
    if (dir_stk == NULL)
        return MINUS_ERRNO;

    dir_stk[0] = key;
    len = 1;

    for (key = key->addr; key != NULL; key = key->addr) {
        if (len == sz) {
            const struct ns_key **tmp;

            sz *= 2;
            tmp = realloc(dir_stk, sz * sizeof(*tmp));
            if (tmp == NULL) {
                err = MINUS_ERRNO;
                goto err;
            }
            dir_stk = tmp;
        }
        dir_stk[len++] = key;
    }

    --len;
    for (;;) {
        if (fprintf(f, "/%s", dir_stk[len]->name) < 0) {
            err = -E_IO;
            goto err;
        }
        if (len == 0)
            break;
        --len;
    }

    free(dir_stk);

    key = *(struct ns_key *const *)k;
    return fprintf(f, "%s\n", key->type == TYPE_DIR ? "/" : "") < 0 ? -E_IO : 0;

err:
    free(dir_stk);
    return err;
}

static int
ns_key_free(const void *k, void *ctx)
{
    struct ns_key *key = *(struct ns_key *const *)k;

    (void)ctx;

    free(key->name);
    free(key->idnode);

    free(key);

    return 0;
}

static int
ns_init(struct avl_tree **ns)
{
    return avl_tree_new(ns, sizeof(struct ns_key *), &ns_key_cmp, 0, NULL, NULL,
                        NULL);
}

static void
ns_destroy(struct avl_tree *ns)
{
    avl_tree_walk_ctx_t wctx = NULL;

    avl_tree_walk(ns, NULL, &ns_key_free, NULL, &wctx);
    avl_tree_free(ns);
}

static int
ns_insert(struct avl_tree *ns, struct ns_key *key, const char *idstr)
{
    int err;
    struct id_node *idnode;
    struct ns_key *k;

    k = malloc(sizeof(*k));
    if (k == NULL)
        return MINUS_ERRNO;

    k->addr = key->addr;
    k->name = key->name;
    k->type = key->type;
    if (k->type == TYPE_DIR)
        k->dir_addr = k;
    k->idnode = key->idnode;

    err = avl_tree_insert(ns, &k);
    if (err) {
        free(k);
        return -sys_maperror(-err);
    }

    if (idstr == NULL)
        return 0;

    idnode = k->idnode;

    if (idnode->handler != NULL
        && printf("int %s(const char *, enum etype, edata_t *, void **, "
                  "size_t *, void **, size_t *, size_t, size_t, struct buf *, "
                  "int64_t, void *, int);\n\n",
                  idnode->handler)
           < 0)
        return -E_IO;

    if (printf("DEF_EBML_DATA(%016" PRIx64 ", \"%s -> %s\", %s%s, %d, "
               "%s%s);\n\n",
               get_node_id(idnode), idstr, idnode->name,
               idnode->handler == NULL ? "" : "&",
               idnode->handler == NULL ? "NULL" : idnode->handler,
               idnode->type, idnode->ref == NULL ? "" : "&",
               idnode->ref == NULL ? "NULL" : idnode->ref)
        < 0)
        return -E_IO;

    return 0;
}

static int
ns_look_up(struct avl_tree *ns, const char *path, struct ns_key *retkey)
{
    char *name, *saveptr;
    char *s;
    int res;
    struct ns_key k, *kp;

    s = strdup(path);
    if (s == NULL)
        return MINUS_ERRNO;

    name = strtok_r(s, "/", &saveptr);
    if (name == NULL) {
        res = -E_INVAL;
        goto err;
    }

    k.addr = NULL;

    for (;;) {
        k.name = name;
        kp = &k;
        res = avl_tree_search(ns, &kp, &kp);
        if (res != 1) {
            if (res != 0) {
                res = -sys_maperror(-res);
                goto err;
            }
            if (strtok_r(NULL, "/", &saveptr) != NULL) {
                res = -E_NOENT;
                goto err;
            }
            break;
        }

        if (kp->type == TYPE_ENT) {
            if (strtok_r(NULL, "/", &saveptr) != NULL) {
                res = -E_NOTDIR;
                goto err;
            }
            res = 1;
            break;
        }
        assert(kp->type == TYPE_DIR);

        name = strtok_r(NULL, "/", &saveptr);
        if (name == NULL) {
            res = -E_ISDIR;
            goto err;
        }

        k.addr = kp->dir_addr;
    }

    if (res == 0) {
        k.name = strdup(k.name);
        if (k.name == NULL) {
            res = MINUS_ERRNO;
            goto err;
        }
        *retkey = k;
    } else
        *retkey = *kp;

    free(s);

    return res;

err:
    free(s);
    return res;
}

static int
ns_dump(FILE *f, struct avl_tree *ns)
{
    avl_tree_walk_ctx_t wctx = NULL;
    int err;
    struct ns_dump_ctx dctx;

    dctx.f = f;
    dctx.cb_err = 0;

    err = avl_tree_walk(ns, NULL, &ns_key_output, &dctx, &wctx);
    return err && !dctx.cb_err ? -sys_maperror(-err) : err;
}

static int
do_printf(jmp_buf *env, const char *fmt, ...)
{
    int ret;
    va_list ap;

    va_start(ap, fmt);
    ret = vprintf(fmt, ap);
    va_end(ap);

    if (ret < 0)
        longjmp(*env, -E_IO);

    return 0;
}

static int
parse_EBMLSchema(enum op op, xmlNode *node, struct avl_tree *ns,
                 struct radix_tree *rt)
{
    (void)op;
    (void)node;
    (void)ns;
    (void)rt;

    return 0;
}

static int
parse_element(enum op op, xmlNode *node, struct avl_tree *ns,
              struct radix_tree *rt)
{
    char *endptr, *path;
    char idstr[7];
    int res;
    struct id_node *idnode;
    struct ns_key *k, retkey;
    unsigned long id;
    xmlChar *prop;

    idnode = malloc(sizeof(*idnode));
    if (idnode == NULL)
        return MINUS_ERRNO;

    prop = xmlGetProp(node, (unsigned char *)"type");
    if (prop == NULL) {
        fputs("Element is missing type\n", stderr);
        res = -E_INVAL;
        goto err1;
    }

    idnode->type = str_to_etype((const char *)prop);

    xmlFree(prop);

    path = (char *)xmlGetProp(node, (unsigned char *)"path");
    if (path == NULL) {
        fputs("Element is missing path\n", stderr);
        res = -E_INVAL;
        goto err1;
    }
    if (op == DUMP_PATHS) {
        res = printf("%s%s\n", path, idnode->type == ETYPE_MASTER ? "/" : "")
              < 0
              ? -E_IO : 0;
        xmlFree(path);
        goto err1;
    }

    idnode->name = (char *)xmlGetProp(node, (unsigned char *)"name");
    if (idnode->name == NULL) {
        fputs("Element is missing name\n", stderr);
        res = -E_INVAL;
        goto err2;
    }

    prop = xmlGetProp(node, (unsigned char *)"id");
    if (prop == NULL) {
        fputs("Element is missing ID\n", stderr);
        res = -E_INVAL;
        goto err3;
    }

    errno = 0;
    id = strtoul((const char *)prop, &endptr, 16);
    res = -en;
    if (res != 0 && *endptr != '\0')
        res = -E_INVAL;

    xmlFree(prop);

    if (res != 0) {
        fputs("Invalid element ID\n", stderr);
        goto err3;
    }

    if (idnode->type == ETYPE_NONE) {
        fputs("Invalid element type\n", stderr);
        goto err3;
    }

    idnode->handler = (char *)xmlGetProp(node, (unsigned char *)"handler");

    res = l64a_r(id, idstr, sizeof(idstr));
    if (res != 0) {
        res = -sys_maperror(-res);
        goto err4;
    }

    res = ns_look_up(ns, path, &retkey);
    if (res != 0) {
        if (res == 1)
            res = -E_ILSEQ;
        goto err4;
    }

    xmlFree(path);
    path = NULL;

    k = malloc(sizeof(*k));
    if (k == NULL) {
        res = MINUS_ERRNO;
        goto err5;
    }

    k->addr = retkey.addr;
    k->name = retkey.name;
    k->type = idnode->type == ETYPE_MASTER ? TYPE_DIR : TYPE_ENT;
    k->idnode = idnode;
    idnode->ref = NULL;

    res = ns_insert(ns, k, idstr);
    if (res != 0)
        goto err6;

    idnode->parent_idnode = k->addr == NULL
                            ? NULL : ((struct ns_key *)k->addr)->idnode;

    free(k);

    res = radix_tree_insert(rt, idstr, &idnode);
    if (res != 0)
        goto err4;

    if (id == EBML_ELEMENT_ID_WITH_MARKER
        && printf("const struct elem_data *ebml_data = EBML_DATA(%016" PRIx64
                  ");\n\n",
                  get_node_id(idnode))
           < 0)
        return -E_IO;

    fprintf(stderr, "ID %s\n", idstr);

    return 0;

err6:
    free(k);
err5:
    free(retkey.name);
err4:
    if (idnode->handler != NULL)
        xmlFree(idnode->handler);
err3:
    xmlFree(idnode->name);
err2:
    if (path != NULL)
        xmlFree(path);
err1:
    free(idnode);
    return res;
}

static int
parse_enum(enum op op, xmlNode *node, struct avl_tree *ns,
           struct radix_tree *rt)
{
    (void)op;
    (void)node;
    (void)ns;
    (void)rt;

    return 0;
}

static int
parse_restriction(enum op op, xmlNode *node, struct avl_tree *ns,
                  struct radix_tree *rt)
{
    (void)op;
    (void)node;
    (void)ns;
    (void)rt;

    return 0;
}

static int
parse_documentation(enum op op, xmlNode *node, struct avl_tree *ns,
                    struct radix_tree *rt)
{
    (void)op;
    (void)node;
    (void)ns;
    (void)rt;

    return 1;
}

static int
parse_implementation_note(enum op op, xmlNode *node, struct avl_tree *ns,
                          struct radix_tree *rt)
{
    (void)op;
    (void)node;
    (void)ns;
    (void)rt;

    return 1;
}

static int
parse_extension(enum op op, xmlNode *node, struct avl_tree *ns,
                struct radix_tree *rt)
{
    (void)op;
    (void)node;
    (void)ns;
    (void)rt;

    return 0;
}

static uint64_t
get_node_id(const void *node)
{
    size_t i;
    static int init;
    static uint32_t key[4];

    if (!init) {
        for (i = 0; i < ARRAY_SIZE(key); i++)
            key[i] = (uint32_t)rand();
        init = 1;
    }

    return xtea_encrypt((uintptr_t)node, key);
}

static int
sr_fn(const struct radix_tree_node *node, const char *str, void *val, void *ctx)
{
    (void)str;
    (void)ctx;

    if (val == NULL) {
        size_t i;

        if (printf("DEF_TRIE_NODE_BRANCH(%016" PRIx64 ", \"%s\"",
                   get_node_id(node),
                   node->label == NULL ? "NULL" : node->label)
            < 0)
            goto err;

        for (i = 0; i < ARRAY_SIZE(node->children); i++) {
            const struct radix_tree_node *child = node->children[i];
            const void *nodep;
            union {
                struct id_node  *ptr;
                char            bytes[sizeof(struct id_node *)];
            } val;

            if (child == NULL)
                continue;

            if (child->type == NODE_TYPE_INFORMATION) {
                memcpy(val.bytes, child->val, sizeof(struct id_node *));
                nodep = val.ptr;
            } else
                nodep = child;

            if (printf(",\n\tENTRY('%c', %016" PRIx64 ")",
                       (int)i, get_node_id(nodep))
                   < 0)
                goto err;
        }

        if (putchar('\n') == EOF)
            goto err;
    } else {
        struct id_node *idnode = *(struct id_node **)val;

        if (idnode->ref == NULL) {
            if (printf("DEF_TRIE_NODE_INFORMATION(%016" PRIx64 ", \"%s\",\n"
                       "\t%s(%016" PRIx64 ")\n",
                       get_node_id(idnode), node->label,
                       idnode->parent_idnode == NULL
                       ? "EBML_DATA_NIL" : "EBML_DATA",
                       idnode->parent_idnode == NULL
                       ? 0 : get_node_id(idnode->parent_idnode))
                < 0)
                goto err;
        } else if (printf("DEF_TRIE_NODE_INFORMATION_REF(%016" PRIx64 ", "
                          "\"%s\",\n"
                          "\t\"%s\", %s(%016" PRIx64 ")\n",
                          get_node_id(idnode), node->label, idnode->ref,
                          idnode->parent_idnode == NULL
                          ? "EBML_DATA_NIL" : "EBML_DATA",
                          idnode->parent_idnode == NULL
                          ? 0 : get_node_id(idnode->parent_idnode))
                   < 0)
            goto err;
    }

    if (fputs(");\n\n", stdout) != EOF)
        return 0;

err:
    return -E_IO;
}

static int
free_fn(const char *str, void *val, void *ctx)
{
    struct id_node *node = *(struct id_node **)val;

    (void)str;
    (void)ctx;

    if (strcmp("EBML", node->name) != 0
        && strcmp("EBMLSemantics", node->name) != 0) {
        xmlFree(node->name);
        xmlFree(node->handler);
    }

    return 0;
}

static int
do_radix_tree_free(struct radix_tree *rt)
{
    int err, tmp;

    err = radix_tree_walk(rt, &free_fn, NULL);

    tmp = radix_tree_free(rt);
    return tmp == 0 ? err : tmp;
}

#define INIT_ENTRY(key1, key2, name) \
    [256 * (unsigned char)(key1) + (unsigned char)(key2)] \
        = {#name, &parse_##name}

static int
_output_parser_data(enum op op, xmlNode *node, int level, struct avl_tree *ns,
                    struct radix_tree *rt)
{
    int ret;
    xmlNode *cur;

    static const struct ent {
        const char  *name;
        int         (*fn)(enum op, xmlNode *, struct avl_tree *,
                          struct radix_tree *);
    } elem_map[256 * 256] = {
        INIT_ENTRY('E', 'B', EBMLSchema),
        INIT_ENTRY('e', 'l', element),
        INIT_ENTRY('e', 'n', enum),
        INIT_ENTRY('r', 'e', restriction),
        INIT_ENTRY('d', 'o', documentation),
        INIT_ENTRY('i', 'm', implementation_note),
        INIT_ENTRY('e', 'x', extension)
    };

    static const char tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

    for (cur = node; cur != NULL; cur = cur->next) {
        const struct ent *ent;

        if (cur->type != XML_ELEMENT_NODE)
            continue;

        if (cur->name[0] == '\0' || cur->name[1] == '\0')
            goto inval_err;
        ent = &elem_map[256 * cur->name[0] + cur->name[1]];
        if (ent->name == NULL)
            goto inval_err;

        ret = (*ent->fn)(op, cur, ns, rt);
        if (ret != 0) {
            if (ret != 1)
                return ret;
            continue;
        }

        fprintf(stderr, "%sName: %s\n",
                &tabs[sizeof(tabs) - 1 - MIN((int)sizeof(tabs) - 1, level)],
                cur->name);

        ret = _output_parser_data(op, cur->children, level + 1, ns, rt);
        if (ret != 0)
            return ret;
    }

    return 0;

inval_err:
    fprintf(stderr, "Unrecognized element %s\n", cur->name);
    return -E_INVAL;
}

#undef INIT_ENTRY

static int
output_parser_data(enum op op, xmlDocPtr doc, const char *doctype,
                   const char *prognm)
{
    int err;
    struct avl_tree *ns;
    struct id_node *idnode;
    struct radix_tree *rt;

    if (op == PROCESS_SCHEMA) {
        char idstr[7];
        jmp_buf env;
        struct ns_key k;

        err = ns_init(&ns);
        if (err)
            return err;

        err = setjmp(env);
        if (err)
            goto err1;

        do_printf(&env, "/* Note: File generated by %s */\n\n", prognm);

        do_printf(&env, "#include \"parser.h\"\n");
        do_printf(&env, "#include \"parser_defs.h\"\n\n");

        do_printf(&env, "#include <stddef.h>\n\n");

        do_printf(&env, "#define TRIE_NODE_PREFIX %s\n\n", doctype);

        do_printf(&env, "extern const struct elem_data *ebml_data;\n\n");

        if (strcmp("ebml", doctype) != 0) {
            idnode = malloc(sizeof(*idnode));
            if (idnode == NULL) {
                err = MINUS_ERRNO;
                goto err1;
            }

            err = l64a_r(EBML_ELEMENT_ID, idstr, sizeof(idstr));
            if (err) {
                err = -sys_maperror(-err);
                goto err3;
            }

            k.name = strdup(strcmp("matroska_semantics", doctype) == 0
                            ? "EBMLSemantics" : "EBML");
            if (k.name == NULL) {
                err = MINUS_ERRNO;
                goto err3;
            }
            k.addr = NULL;
            k.type = TYPE_DIR;

            idnode->name = k.name;
            idnode->handler = NULL;
            idnode->type = ETYPE_MASTER;
            idnode->parent_idnode = NULL;
            idnode->ref = "ebml_data";
            k.idnode = idnode;

            err = ns_insert(ns, &k, idstr);
            if (err) {
                free(k.name);
                goto err3;
            }
        }

        err = radix_tree_new(&rt, sizeof(struct id_node *));
        if (err)
            goto err1;
    } else {
        ns = NULL;
        rt = NULL;
    }

    err = _output_parser_data(op, xmlDocGetRootElement(doc), 0, ns, rt);
    if (err)
        goto err2;

    if (op == PROCESS_SCHEMA) {
        if (printf("#define %s_TRIE_ROOT (&%s_trie_node_%016" PRIx64 ")\n\n",
                   doctype, doctype, get_node_id(rt->root))
            < 0) {
            err = -E_IO;
            goto err2;
        }

        err = radix_tree_serialize(rt, &sr_fn, NULL);
        if (err)
            goto err2;

        if (printf("#undef TRIE_NODE_PREFIX\n\n") < 0) {
            err = -E_IO;
            goto err2;
        }
    }

    err = syncf(stdout);
    if (err)
        goto err2;

    if (op == PROCESS_SCHEMA) {
        do_radix_tree_free(rt);
        ns_destroy(ns);
    }

    return 0;

err3:
    free(idnode);
    ns_destroy(ns);
    return err;

err2:
    do_radix_tree_free(rt);
err1:
    ns_destroy(ns);
    return err;
}

static int
process_paths(int infd, int outfd)
{
    char *line;
    FILE *inf, *outf;
    int res;
    size_t linecap;
    struct avl_tree *ns;
    struct ns_key *k, retkey;

    infd = sys_dup(infd);
    if (infd == -1)
        return MINUS_ERRN;

    inf = fdopen(infd, "r");
    if (inf == NULL) {
        res = MINUS_ERRNO;
        sys_close(infd);
        return res;
    }

    outfd = sys_dup(outfd);
    if (outfd == -1) {
        res = MINUS_ERRN;
        goto err1;
    }

    outf = fdopen(outfd, "w");
    if (outf == NULL) {
        res = MINUS_ERRNO;
        sys_close(outfd);
        goto err1;
    }

    res = ns_init(&ns);
    if (res != 0)
        goto err2;

    line = NULL;
    linecap = 0;
    for (;;) {
        size_t len;

        errno = 0;
        if (getline(&line, &linecap, inf) == -1) {
            res = en;
            free(line);
            if (res != 0) {
                res = -res;
                goto err3;
            }
            break;
        }
        len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            --len;
            line[len] = '\0';
        }

        res = ns_look_up(ns, line, &retkey);
        if (res != 0) {
            if (res != 1)
                goto err3;
            continue;
        }

        k = malloc(sizeof(*k));
        if (k == NULL) {
            res = MINUS_ERRNO;
            goto err4;
        }

        k->addr = retkey.addr;
        k->name = retkey.name;
        k->type = len > 0 && line[len-1] == '/' ? TYPE_DIR : TYPE_ENT;
        k->idnode = NULL;

        res = ns_insert(ns, k, NULL);
        free(k);
        if (res != 0)
            goto err4;
    }

    res = ns_dump(outf, ns);
    if (res != 0)
        goto err3;

    ns_destroy(ns);

    res = syncf(outf);
    if (res != 0)
        goto err2;

    res = fclose(outf) == EOF ? MINUS_ERRNO : 0;
    fclose(inf);

    return res;

err4:
    free(retkey.name);
err3:
    ns_destroy(ns);
err2:
    fclose(outf);
err1:
    fclose(inf);
    return res;
}

int
main(int argc, char **argv)
{
    const char *doctype;
    const char *schemaf;
    enum op op = PROCESS_SCHEMA;
    int status, tmp;
    unsigned seed;
    xmlDocPtr doc, schemadoc;
    xmlSchemaParserCtxtPtr ctx;
    xmlSchemaPtr schema;
    xmlSchemaValidCtxtPtr vctx;

    if (strcmp(argv[1], "-p") == 0) {
        return process_paths(SYS_STDIN_FILENO, SYS_STDOUT_FILENO) == 0
               ? EXIT_SUCCESS : EXIT_FAILURE;
    }

    if (argc < 2) {
        fputs("Must specify XML schema path\n", stderr);
        return EXIT_FAILURE;
    }
    if (argc < 3) {
        fputs("Must specify EBML document type name\n", stderr);
        return EXIT_FAILURE;
    }
    if (argc > 2 && strcmp("-s", argv[1]) == 0) {
        schemaf = argv[2];
        tmp = 3;
    } else {
        schemaf = strcmp("-", argv[1]) == 0 ? NULL : argv[1];
        tmp = 2;
    }
    doctype = argv[tmp++];
    if (argc == tmp)
        seed = time(NULL) + getpid();
    else if (strcmp("-d", argv[tmp]) == 0)
        op = DUMP_PATHS;
    else
        seed = atoi(argv[tmp]);

    LIBXML_TEST_VERSION

    if (op == PROCESS_SCHEMA)
        srand(seed);

    doc = xmlParseFile("-");
    if (doc == NULL)
        goto err1;

    status = EXIT_FAILURE;

    if (schemaf != NULL) {
        schemadoc = xmlParseFile(schemaf);
        if (schemadoc == NULL)
            goto err2;

        ctx = xmlSchemaNewDocParserCtxt(schemadoc);
        if (ctx == NULL)
            goto err3;

        schema = xmlSchemaParse(ctx);
        if (schema == NULL)
            goto err4;

    /*    xmlSchemaDump(stdout, schema);
    */
        vctx = xmlSchemaNewValidCtxt(schema);
        if (vctx == NULL)
            goto err5;

        tmp = xmlSchemaValidateDoc(vctx, doc);
        if (tmp != 0) {
            fprintf(stderr, "%s\n",
                    tmp == -1
                    ? "Error validating XML document" : "XML document invalid");
        }

        xmlSchemaFreeValidCtxt(vctx);
        xmlSchemaFree(schema);
        xmlSchemaFreeParserCtxt(ctx);

        xmlFreeDoc(schemadoc);

        if (tmp != 0)
            goto end;
    }

    if (setvbuf(stdout, NULL, _IOLBF, 0) == EOF)
        fputs("Out of memory\n", stderr);
    else if (output_parser_data(op, doc, doctype, basename_safe(argv[0])) != 0)
        fputs("Parsing error\n", stderr);
    else
        status = EXIT_SUCCESS;

end:

    xmlFreeDoc(doc);
    xmlCleanupParser();

    if (op == PROCESS_SCHEMA && status == EXIT_SUCCESS)
        fprintf(stderr, "Seed: %u\n", seed);

    return status;

err5:
    xmlSchemaFree(schema);
err4:
    xmlSchemaFreeParserCtxt(ctx);
err3:
    xmlFreeDoc(schemadoc);
err2:
    xmlFreeDoc(doc);
err1:
    xmlCleanupParser();
    fprintf(stderr, "Error parsing %s\n", schemaf);
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
