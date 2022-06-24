/*
 * element_test.c
 */

#include "common.h"
#include "element.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
    int err;
    size_t i;

    static const struct test {
        const char  *src;
        int         err;
    } tests[] = {
        {"\x80",        -EINVAL},
        {"\x40\x00",    -EINVAL},
        {"\x81",        0},
        {"\x40\x01",    -EINVAL},
        {"\xbf",        0},
        {"\x40\x3f",    -EINVAL},
        {"\xff",        -EINVAL},
        {"\x40\x7f",    0}
    };

    (void)argc;
    (void)argv;

    i = 0;
    while (i < ARRAY_SIZE(tests)) {
        const struct test *t = &tests[i];
        size_t ressz;
        uint64_t res;

        err = eid_to_u64(t->src, &res, &ressz);
        if (err != t->err) {
            fputs("eid_to_u64() returned incorrect result\n", stderr);
            return EXIT_FAILURE;
        }

        fprintf(stderr, "eid_to_u64() test %zu\n", ++i);
    }

    return EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
