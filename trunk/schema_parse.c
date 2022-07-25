/*
 * schema_parse.c
 */

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlschemas.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#include <sys/param.h>

static int parse_EBMLSchema(xmlNode *);
static int parse_element(xmlNode *);
static int parse_enum(xmlNode *);
static int parse_restriction(xmlNode *);
static int parse_documentation(xmlNode *);
static int parse_implementation_note(xmlNode *);
static int parse_extension(xmlNode *);

static int _output_parser_data(xmlNode *, int);

static int output_parser_data(xmlDocPtr);

static int
parse_EBMLSchema(xmlNode *node)
{
    (void)node;

    return 0;
}

static int
parse_element(xmlNode *node)
{
    char *endptr;
    int err;
    union {
        unsigned long l;
        unsigned char b[4];
    } val;
    xmlChar *prop;

    prop = xmlGetProp(node, (unsigned char *)"id");
    if (prop == NULL) {
        fputs("Element is missing ID\n", stderr);
        return -EINVAL;
    }

    errno = 0;
    val.l = strtoul((const char *)prop, &endptr, 16);
    err = -errno;
    if (!err && *endptr != '\0')
        err = -EINVAL;

    xmlFree(prop);

    if (err)
        fputs("Invalid element ID\n", stderr);
    else
        printf("%hhu %hhu %hhu %hhu\n", val.b[0], val.b[1], val.b[2], val.b[3]);

    return err;
}

static int
parse_enum(xmlNode *node)
{
    (void)node;

    return 0;
}

static int
parse_restriction(xmlNode *node)
{
    (void)node;

    return 0;
}

static int
parse_documentation(xmlNode *node)
{
    (void)node;

    return 1;
}

static int
parse_implementation_note(xmlNode *node)
{
    (void)node;

    return 1;
}

static int
parse_extension(xmlNode *node)
{
    (void)node;

    return 0;
}

#define INIT_ENTRY(key1, key2, name) \
    [256 * (unsigned char)(key1) + (unsigned char)(key2)] \
        = {#name, &parse_##name}

static int
_output_parser_data(xmlNode *node, int level)
{
    int ret;
    xmlNode *cur;

    static const struct ent {
        const char  *name;
        int         (*fn)(xmlNode *);
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

        ret = (*ent->fn)(cur);
        if (ret != 0) {
            if (ret != 1)
                return ret;
            continue;
        }

        fprintf(stderr, "%sName: %s\n",
                &tabs[sizeof(tabs) - 1 - MIN((int)sizeof(tabs) - 1, level)],
                cur->name);

        ret = _output_parser_data(cur->children, level + 1);
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
    return _output_parser_data(xmlDocGetRootElement(doc), 0);
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
