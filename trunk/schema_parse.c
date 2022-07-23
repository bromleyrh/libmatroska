/*
 * schema_parse.c
 */

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlschemas.h>

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
    const char *schemaf;
    int ret, status;
    xmlDocPtr doc;
    xmlSchemaParserCtxtPtr ctx;
    xmlSchemaPtr schema;
    xmlSchemaValidCtxtPtr vctx;

    if (argc < 2) {
        fputs("Must specify XML schema path\n", stderr);
        return EXIT_FAILURE;
    }
    schemaf = argv[1];

    LIBXML_TEST_VERSION

    doc = xmlParseFile(schemaf);
    if (doc == NULL)
        goto err1;

    ctx = xmlSchemaNewDocParserCtxt(doc);
    if (ctx == NULL)
        goto err2;

    schema = xmlSchemaParse(ctx);
    if (schema == NULL)
        goto err3;

/*    xmlSchemaDump(stdout, schema);
*/
    vctx = xmlSchemaNewValidCtxt(schema);
    if (vctx == NULL)
        goto err4;

    ret = xmlSchemaValidateFile(vctx, "-", 0);
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

    xmlFreeDoc(doc);
    xmlCleanupParser();

    return status;

err4:
    xmlSchemaFree(schema);
err3:
    xmlSchemaFreeParserCtxt(ctx);
err2:
    xmlFreeDoc(doc);
    xmlCleanupParser();
err1:
    fprintf(stderr, "Error parsing %s\n", schemaf);
    return EXIT_FAILURE;
}

/* vi: set expandtab sw=4 ts=4: */
