/*
 * schema_parse.c
 */

#include <expat.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef XML_UNICODE_WCHAR_T
#include <wchar.h>
#endif

#include <sys/param.h>

#ifdef XML_LARGE_SIZE
#define PRI_XML_LINENO "llu"
#else
#define PRI_XML_LINENO "lu"
#endif

#ifdef XML_UNICODE_WCHAR_T
#define PRI_XML_CHAR "ls"
#else
#define PRI_XML_CHAR "s"
#endif

static const char tabs[] = "\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";

#define TABS(level) \
    (&tabs[sizeof(tabs) - 1 - MIN((int)sizeof(tabs) - 1, level)])

static void XMLCALL start_element_cb(void *, const XML_Char *,
                                     const XML_Char **);
static void XMLCALL end_element_cb(void *, const XML_Char *);

static void XMLCALL
start_element_cb(void *userData, const XML_Char *name, const XML_Char **atts)
{
    int *level = userData;

    (void)atts;

    printf("%s%" PRI_XML_CHAR " {\n", TABS(*level), name);

    ++*level;
}

static void XMLCALL
end_element_cb(void *userData, const XML_Char *name)
{
    int *level = userData;

    (void)name;

    --*level;

    printf("%s}\n", TABS(*level));
}

int
main(int argc, char **argv)
{
    enum XML_Status res;
    int level = 0;
    int status = EXIT_FAILURE;
    XML_Parser parser;

    (void)argc;
    (void)argv;

    parser = XML_ParserCreate(NULL);
    if (parser == NULL)
        return EXIT_FAILURE;

    XML_SetElementHandler(parser, &start_element_cb, &end_element_cb);
    XML_SetUserData(parser, &level);

    for (;;) {
        char buf[4096];
        int is_final;
        size_t ret;

        ret = fread(buf, 1, sizeof(buf), stdin);
        is_final = ret == 0;
        if (is_final && !feof(stdin)) {
            fprintf(stderr, "Error reading: %s\n", strerror(errno));
            break;
        }

        res = XML_Parse(parser, buf, ret, is_final);
        if (res != XML_STATUS_OK) {
            fprintf(stderr, "%" PRI_XML_CHAR " at line %" PRI_XML_LINENO "\n",
                    XML_ErrorString(XML_GetErrorCode(parser)),
                    XML_GetCurrentLineNumber(parser));
            break;
        }

        if (is_final) {
            status = EXIT_SUCCESS;
            break;
        }
    }

    XML_ParserFree(parser);

    return status;
}

/* vi: set expandtab sw=4 ts=4: */
