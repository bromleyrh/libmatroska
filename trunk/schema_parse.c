/*
 * schema_parse.c
 */

#include "common.h"
#include "radix_tree.h"

#include <strings_ext.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlschemas.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/param.h>

struct id_node {
    char *name;
};

static int parse_EBMLSchema(xmlNode *, struct radix_tree *);
static int parse_element(xmlNode *, struct radix_tree *);
static int parse_enum(xmlNode *, struct radix_tree *);
static int parse_restriction(xmlNode *, struct radix_tree *);
static int parse_documentation(xmlNode *, struct radix_tree *);
static int parse_implementation_note(xmlNode *, struct radix_tree *);
static int parse_extension(xmlNode *, struct radix_tree *);

static int sr_fn(const struct radix_tree_node *, const char *, void *, void *);
static int free_fn(const char *, void *, void *);

static int do_radix_tree_free(struct radix_tree *);

static int _output_parser_data(xmlNode *, int, struct radix_tree *);

static int output_parser_data(xmlDocPtr);

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
        goto err;
    }

    errno = 0;
    id = strtoul((const char *)prop, &endptr, 16);
    err = -errno;
    if (!err && *endptr != '\0')
        err = -EINVAL;

    xmlFree(prop);

    if (err) {
        fputs("Invalid element ID\n", stderr);
        goto err;
    }

    err = l64a_r(id, idstr, sizeof(idstr));
    if (err)
        goto err;

    err = radix_tree_insert(rt, idstr, &idnode);
    if (err)
        goto err;

    fprintf(stderr, "ID %s\n", idstr);

    return 0;

err:
    free(idnode.name);
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

static int
sr_fn(const struct radix_tree_node *node, const char *str, void *val, void *ctx)
{
    (void)ctx;

    printf("static const struct trie_node trie_node_%jx = {\n",
           (uintmax_t)(uintptr_t)node);

    fputs("\t.label = ", stdout);
    if (node->label == NULL)
        fputs("NULL", stdout);
    else
        printf("\"%s\"", node->label);

    if (val == NULL) {
        size_t i;

        for (i = 0; i < ARRAY_SIZE(node->children); i++) {
            if (node->children[i] != NULL) {
                printf(",\n\t.children[(unsigned char)'%c'] = &trie_node_%jx",
                       (int)i, (uintmax_t)(uintptr_t)node->children[i]);
            }
        }
    } else {
        struct id_node *idnode = val;

        printf(",\n\t.val = \"%s -> %s\"", str, idnode->name);
    }

    fputs("\n};\n\n", stdout);

    return 0;
}

static int
free_fn(const char *str, void *val, void *ctx)
{
    struct id_node *node = val;

    (void)str;
    (void)ctx;

    xmlFree(node->name);

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
output_parser_data(xmlDocPtr doc)
{
    int err;
    struct radix_tree *rt;

    err = radix_tree_new(&rt, sizeof(struct id_node));
    if (err)
        return err;

    err = _output_parser_data(xmlDocGetRootElement(doc), 0, rt);
    if (!err) {
        printf("#include \"parser_defs.h\"\n\n");

        printf("#define TRIE_ROOT (&trie_node_%jx)\n\n",
               (uintmax_t)(uintptr_t)rt->root);

        err = radix_tree_serialize(rt, &sr_fn, NULL);
    }

    do_radix_tree_free(rt);

    return err;
}

int
main(int argc, char **argv)
{
    const char *schemaf;
    int ret, status;
    xmlDocPtr doc, schemadoc;
    xmlSchemaParserCtxtPtr ctx;
    xmlSchemaPtr schema;
    xmlSchemaValidCtxtPtr vctx;

    if (argc < 2) {
        fputs("Must specify XML schema path\n", stderr);
        return EXIT_FAILURE;
    }
    schemaf = argv[1];

    LIBXML_TEST_VERSION

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
        if (output_parser_data(doc) != 0) {
            status = EXIT_FAILURE;
            fputs("Parsing error\n", stderr);
        }
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();

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
