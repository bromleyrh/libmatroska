/*
 * vint_test.c
 */

#define _FILE_OFFSET_BITS 64

#include "matroska.h"
#include "vint.h"

#define NO_ASSERT_MACROS
#include "common.h"
#undef NO_ASSERT_MACROS

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int matroska_print_err(FILE *, int);

int
main(int argc, char **argv)
{
    int err;
    size_t i;

    static const struct test_u64_to_vint {
        uint64_t    src;
        int         len;
        uint64_t    dst;
    } tests_u64_to_vint[] = {
        {2, -1, 0x82},
        {2,  2, 0x240},
        {2,  3, 0x20020},
        {2,  4, 0x2000010}
    };
    static const struct test_vint_to_u64 {
        const char  *src;
        int         len;
        uint64_t    dst;
    } tests_vint_to_u64[] = {
        {"\x82",                1, 2},
        {"\x40\x02",            2, 2},
        {"\x20\x00\x02",        3, 2},
        {"\x10\x00\x00\x02",    4, 2}
    };

    (void)argc;
    (void)argv;

    i = 0;
    while (i < ARRAY_SIZE(tests_u64_to_vint)) {
        const char *func;
        const struct test_u64_to_vint *t = &tests_u64_to_vint[i];
        size_t bufsz;
        union {
            char        buf[4];
            uint64_t    n;
        } res;

        memset(&res, 0, sizeof(res));
        if (t->len < 0) {
            bufsz = sizeof(res.buf);
            err = u64_to_vint(t->src, res.buf, &bufsz);
            func = "u64_to_vint";
        } else {
            err = u64_to_vint_l(t->src, res.buf, t->len);
            func = "u64_to_vint_l";
        }
        if (err) {
            if (err > 0)
                err = matroska_print_err(stderr, err);
            fprintf(stderr, "%s() returned \"%s\"\n", func, strerror(-err));
            return EXIT_FAILURE;
        }

        if (res.n != t->dst || (t->len < 0 && bufsz != (size_t)-t->len)) {
            fprintf(stderr, "%s() returned incorrect result\n", func);
            return EXIT_FAILURE;
        }

        fprintf(stderr, "u64_to_vint*() test %zu\n", ++i);
    }

    i = 0;
    while (i < ARRAY_SIZE(tests_vint_to_u64)) {
        const struct test_vint_to_u64 *t = &tests_vint_to_u64[i];
        size_t ressz;
        uint64_t res;

        err = vint_to_u64(t->src, &res, &ressz);
        if (err) {
            if (err > 0)
                err = matroska_print_err(stderr, err);
            fprintf(stderr, "vint_to_u64() returned \"%s\"\n", strerror(-err));
            return EXIT_FAILURE;
        }

        if (res != t->dst || ressz != (size_t)t->len) {
            fputs("vint_to_u64() returned incorrect result\n", stderr);
            return EXIT_FAILURE;
        }

        fprintf(stderr, "vint_to_u64() test %zu\n", ++i);
    }

    return EXIT_SUCCESS;
}

/* vi: set expandtab sw=4 ts=4: */
