/*
 * element_test.c
 */

#include "element.h"

#define NO_ASSERT_MACROS
#include "common.h"
#undef NO_ASSERT_MACROS

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main(int argc, char **argv)
{
    int err;
    size_t i;

    static const struct test_eid_to_u64 {
        const char  *src;
        int         err;
    } tests_eid_to_u64[] = {
        {"\x80",        -ENOTSUP},
        {"\x40\x00",    -EINVAL},
        {"\x81",        0},
        {"\x40\x01",    -EINVAL},
        {"\xbf",        0},
        {"\x40\x3f",    -EINVAL},
        {"\xff",        -EINVAL},
        {"\x40\x7f",    0}
    };
    static const struct test_edatasz_to_u64 {
        const char  *src;
        size_t      len;
        uint64_t    dst;
    } tests_edatasz_to_u64[] = {
        {"\xff",            1, EDATASZ_UNKNOWN},
        {"\x40\x7f",        2, 127},
        {"\x20\x00\x7f",    3, 127},
        {"\x7f\xff",        2, EDATASZ_UNKNOWN},
        {"\x20\x3f\xff",    3, 16383}
    };

    (void)argc;
    (void)argv;

    i = 0;
    while (i < ARRAY_SIZE(tests_eid_to_u64)) {
        const struct test_eid_to_u64 *t = &tests_eid_to_u64[i];
        size_t ressz;
        uint64_t res;

        err = eid_to_u64(t->src, &res, &ressz);
        if (err != t->err) {
            fputs("eid_to_u64() returned incorrect result\n", stderr);
            return EXIT_FAILURE;
        }

        fprintf(stderr, "eid_to_u64() test %zu\n", ++i);
    }

    i = 0;
    while (i < ARRAY_SIZE(tests_edatasz_to_u64)) {
        const struct test_edatasz_to_u64 *t = &tests_edatasz_to_u64[i];
        size_t ressz;
        uint64_t res;

        err = edatasz_to_u64(t->src, &res, &ressz);
        if (err) {
            fprintf(stderr, "edatasz_to_u64() returned \"%s\"\n",
                    strerror(-err));
            return EXIT_FAILURE;
        }

        if (res != t->dst || ressz != t->len) {
            fputs("edatasz_to_u64() returned incorrect result\n", stderr);
            return EXIT_FAILURE;
        }

        fprintf(stderr, "edatasz_to_u64() test %zu\n", ++i);
    }

    return EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
