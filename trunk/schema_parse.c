/*
 * schema_parse.c
 */

#include "element.h"
#include "radix_tree.h"

#define NO_ASSERT_MACROS
#include "common.h"
#undef NO_ASSERT_MACROS

#include <crypto.h>
#include <strings_ext.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlschemas.h>

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

#include <sys/param.h>

struct id_node {
    char        *name;
    char        *handler;
    enum etype  type;
};

static int do_printf(jmp_buf *, const char *, ...);

static int parse_EBMLSchema(xmlNode *, struct radix_tree *);
static int parse_element(xmlNode *, struct radix_tree *);
static int parse_enum(xmlNode *, struct radix_tree *);
static int parse_restriction(xmlNode *, struct radix_tree *);
static int parse_documentation(xmlNode *, struct radix_tree *);
static int parse_implementation_note(xmlNode *, struct radix_tree *);
static int parse_extension(xmlNode *, struct radix_tree *);

static uint64_t get_node_id(const struct radix_tree_node *);

static int sr_fn(const struct radix_tree_node *, const char *, void *, void *);
static int free_fn(const char *, void *, void *);

static int do_radix_tree_free(struct radix_tree *);

static int _output_parser_data(xmlNode *, int, struct radix_tree *);

static int output_parser_data(xmlDocPtr, const char *);

static int
do_printf(jmp_buf *env, const char *fmt, ...)
{
    int ret;
    va_list ap;

    va_start(ap, fmt);
    ret = vprintf(fmt, ap);
    va_end(ap);

    if (ret < 0)
        longjmp(*env, -EIO);

    return 0;
}

static int
parse_EBMLSchema(xmlNode *node, struct radix_tree *rt)
{
    (void)node;
    (void)rt;

    return 0;
}

static int
parse_element(xmlNode *node, struct radix_tree *rt)
{
    char idstr[7];
    char *endptr;
    int err;
    struct id_node idnode;
    unsigned long id;
    xmlChar *prop;

    idnode.name = (char *)xmlGetProp(node, (unsigned char *)"name");
    if (idnode.name == NULL) {
        fputs("Element is missing name\n", stderr);
        return -EINVAL;
    }

    prop = xmlGetProp(node, (unsigned char *)"id");
    if (prop == NULL) {
        fputs("Element is missing ID\n", stderr);
        err = -EINVAL;
        goto err1;
    }

    errno = 0;
    id = strtoul((const char *)prop, &endptr, 16);
    err = -errno;
    if (!err && *endptr != '\0')
        err = -EINVAL;

    xmlFree(prop);

    if (err) {
        fputs("Invalid element ID\n", stderr);
        goto err1;
    }

    prop = xmlGetProp(node, (unsigned char *)"type");
    if (prop == NULL) {
        fputs("Element is missing type\n", stderr);
        err = -EINVAL;
        goto err1;
    }

    idnode.type = str_to_etype((const char *)prop);

    xmlFree(prop);

    if (idnode.type == ETYPE_NONE) {
        fputs("Invalid element type\n", stderr);
        goto err1;
    }

    idnode.handler = (char *)xmlGetProp(node, (unsigned char *)"handler");

    err = l64a_r(id, idstr, sizeof(idstr));
    if (err)
        goto err2;

    err = radix_tree_insert(rt, idstr, &idnode);
    if (err)
        goto err2;

    fprintf(stderr, "ID %s\n", idstr);

    return 0;

err2:
    if (idnode.handler != NULL)
        xmlFree(idnode.handler);
err1:
    xmlFree(idnode.name);
    return err;
}

static int
parse_enum(xmlNode *node, struct radix_tree *rt)
{
    (void)node;
    (void)rt;

    return 0;
}

static int
parse_restriction(xmlNode *node, struct radix_tree *rt)
{
    (void)node;
    (void)rt;

    return 0;
}

static int
parse_documentation(xmlNode *node, struct radix_tree *rt)
{
    (void)node;
    (void)rt;

    return 1;
}

static int
parse_implementation_note(xmlNode *node, struct radix_tree *rt)
{
    (void)node;
    (void)rt;

    return 1;
}

static int
parse_extension(xmlNode *node, struct radix_tree *rt)
{
    (void)node;
    (void)rt;

    return 0;
}

static uint64_t
get_node_id(const struct radix_tree_node *node)
{
    size_t i;
    static int init;
    static uint32_t key[4];

    if (!init) {
        for (i = 0; i < ARRAY_SIZE(key); i++)
            key[i] = (uint32_t)rand();
        init = 1;
    }

    return xtea_encrypt((uint64_t)(uintptr_t)node, key);
}

static int
sr_fn(const struct radix_tree_node *node, const char *str, void *val, void *ctx)
{
    (void)ctx;

    if (val == NULL) {
        size_t i;

        if (printf("DEF_TRIE_NODE_BRANCH(%016" PRIx64 ", \"%s\"",
                   get_node_id(node),
                   node->label == NULL ? "NULL" : node->label)
            < 0)
            goto err;

        for (i = 0; i < ARRAY_SIZE(node->children); i++) {
            if (node->children[i] != NULL
                && printf(",\n\tENTRY('%c', %016" PRIx64 ")",
                          (int)i, get_node_id(node->children[i]))
                   < 0)
                goto err;
        }

        if (putchar('\n') == EOF)
            goto err;
    } else {
        struct id_node *idnode = val;

        if (idnode->handler != NULL
            && printf("int %s(const char *, enum etype, edata_t *, "
                      "const void *, size_t, size_t, void *);\n\n",
                      idnode->handler)
               < 0)
            goto err;

        if (printf("DEF_TRIE_NODE_INFORMATION(%016" PRIx64 ", \"%s\",\n"
                   "\t\"%s -> %s\", %s%s, %d\n",
                   get_node_id(node), node->label, str, idnode->name,
                   idnode->handler == NULL ? "" : "&",
                   idnode->handler == NULL ? "NULL" : idnode->handler,
                   idnode->type)
            < 0)
            goto err;
    }

    if (fputs(");\n\n", stdout) != EOF)
        return 0;

err:
    return -EIO;
}

static int
free_fn(const char *str, void *val, void *ctx)
{
    struct id_node *node = val;

    (void)str;
    (void)ctx;

    xmlFree(node->name);
    xmlFree(node->handler);

    return 0;
}

static int
do_radix_tree_free(struct radix_tree *rt)
{
    return radix_tree_walk(rt, &free_fn, NULL);
}

#define INIT_ENTRY(key1, key2, name) \
    [256 * (unsigned char)(key1) + (unsigned char)(key2)] \
        = {#name, &parse_##name}

static int
_output_parser_data(xmlNode *node, int level, struct radix_tree *rt)
{
    int ret;
    xmlNode *cur;

    static const struct ent {
        const char  *name;
        int         (*fn)(xmlNode *, struct radix_tree *);
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

        ret = (*ent->fn)(cur, rt);
        if (ret != 0) {
            if (ret != 1)
                return ret;
            continue;
        }

        fprintf(stderr, "%sName: %s\n",
                &tabs[sizeof(tabs) - 1 - MIN((int)sizeof(tabs) - 1, level)],
                cur->name);

        ret = _output_parser_data(cur->children, level + 1, rt);
        if (ret != 0)
            return ret;
    }

    return 0;

inval_err:
    fprintf(stderr, "Unrecognized element %s\n", cur->name);
    return -EINVAL;
}

#undef INIT_ENTRY

static int
output_parser_data(xmlDocPtr doc, const char *doctype)
{
    int err;
    jmp_buf env;
    struct radix_tree *rt;

    err = radix_tree_new(&rt, sizeof(struct id_node));
    if (err)
        return err;

    err = _output_parser_data(xmlDocGetRootElement(doc), 0, rt);
    if (err)
        goto err;

    err = setjmp(env);
    if (err)
        goto err;

    do_printf(&env, "#include \"parser.h\"\n");
    do_printf(&env, "#include \"parser_defs.h\"\n\n");

    do_printf(&env, "#include <stddef.h>\n\n");

    do_printf(&env, "#define TRIE_NODE_PREFIX %s\n\n", doctype);

    do_printf(&env, "#define %s_TRIE_ROOT (&%s_trie_node_%016" PRIx64 ")\n\n",
              doctype, doctype, get_node_id(rt->root));

    err = radix_tree_serialize(rt, &sr_fn, NULL);
    if (!err)
        return printf("#undef TRIE_NODE_PREFIX\n\n") < 0 ? -EIO : 0;

err:
    do_radix_tree_free(rt);
    return err;
}

int
main(int argc, char **argv)
{
    const char *doctype;
    const char *schemaf;
    int ret, status;
    unsigned seed;
    xmlDocPtr doc, schemadoc;
    xmlSchemaParserCtxtPtr ctx;
    xmlSchemaPtr schema;
    xmlSchemaValidCtxtPtr vctx;

    if (argc < 2) {
        fputs("Must specify XML schema path\n", stderr);
        return EXIT_FAILURE;
    }
    if (argc < 3) {
        fputs("Must specify EBML document type name\n", stderr);
        return EXIT_FAILURE;
    }
    schemaf = argv[1];
    doctype = argv[2];
    seed = argc == 4 ? atoi(argv[3]) : time(NULL) + getpid();

    LIBXML_TEST_VERSION

    srand(seed);

    schemadoc = xmlParseFile(schemaf);
    if (schemadoc == NULL)
        goto err1;
    doc = xmlParseFile("-");
    if (doc == NULL)
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

    ret = xmlSchemaValidateDoc(vctx, doc);
    if (ret == 0)
        status = EXIT_SUCCESS;
    else {
        status = EXIT_FAILURE;
        fprintf(stderr, "%s\n",
                ret == -1
                ? "Error validating XML document" : "XML document invalid");
    }

    xmlSchemaFreeValidCtxt(vctx);

    xmlSchemaFree(schema);

    xmlSchemaFreeParserCtxt(ctx);

    xmlFreeDoc(schemadoc);

    if (ret == 0) {
        setlinebuf(stdout);
        if (output_parser_data(doc, doctype) != 0) {
            status = EXIT_FAILURE;
            fputs("Parsing error\n", stderr);
        }
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();

    if (status == EXIT_SUCCESS)
        fprintf(stderr, "Seed: %u\n", seed);

    return status;

err5:
    xmlSchemaFree(schema);
err4:
    xmlSchemaFreeParserCtxt(ctx);
err3:
    xmlFreeDoc(doc);
err2:
    xmlFreeDoc(schemadoc);
    xmlCleanupParser();
err1:
    fprintf(stderr, "Error parsing %s\n", schemaf);
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
