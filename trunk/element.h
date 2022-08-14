/*
 * element.h
 */

#ifndef _ELEMENT_H
#define _ELEMENT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define ETYPE_HASH(c1, c2) ((unsigned)(256 * (c1) + (c2)))

#define _LIST_ETYPE(type, val, name, hash) _X(ETYPE_##type, val, name, hash)

#define LIST_ETYPES() \
    _LIST_ETYPE(INTEGER,    1,      "integer",  ETYPE_HASH('i', 'n')) \
    _LIST_ETYPE(UINTEGER,   2,      "uinteger", ETYPE_HASH('u', 'i')) \
    _LIST_ETYPE(FLOAT,      4,      "float",    ETYPE_HASH('f', 'l')) \
    _LIST_ETYPE(STRING,     8,      "string",   ETYPE_HASH('s', 't')) \
    _LIST_ETYPE(UTF8,       16,     "utf-8",    ETYPE_HASH('u', 't')) \
    _LIST_ETYPE(DATE,       32,     "date",     ETYPE_HASH('d', 'a')) \
    _LIST_ETYPE(MASTER,     64,     "master",   ETYPE_HASH('m', 'a')) \
    _LIST_ETYPE(BINARY,     128,    "binary",   ETYPE_HASH('b', 'i'))

#define ETYPE_IS_NUMERIC(type) \
    ((type) & (ETYPE_INTEGER | ETYPE_UINTEGER | ETYPE_FLOAT))

#define ETYPE_IS_FIXED_WIDTH(type) \
    (ETYPE_IS_NUMERIC(type) || (type) & ETYPE_DATE)

#define ETYPE_IS_STRING(type) \
    ((type) & (ETYPE_STRING | ETYPE_UTF8))

#define ETYPE_MAX_FIXED_WIDTH 8

enum etype {
    ETYPE_NONE,
#define _X(type, val, name, hash) \
    type = val,
    LIST_ETYPES()
#undef _X
};

typedef struct {
    enum etype      type:8;
    unsigned        dbl:1;
    union {
        int64_t     integer;
        uint64_t    uinteger;
        float       floats;
        double      floatd;
        int64_t     date;
        char        *ptr;
        char        bytes[8];
    };
} edata_t;

#define EDATASZ_UNKNOWN (~0ull)

int eid_to_u64(const char *x, uint64_t *y, size_t *sz);

int u64_to_eid(uint64_t x, char *y, size_t *bufsz);

uint64_t vintmax(size_t len);

int edatasz_to_u64(const char *x, uint64_t *y, size_t *sz);

int u64_to_edatasz(uint64_t x, char *y, size_t *bufsz);

int u64_to_edatasz_l(uint64_t x, char *y, size_t bufsz);

const char *etype_to_str(enum etype etype);

enum etype str_to_etype(const char *str);

int edata_unpack(const char *x, edata_t *y, enum etype etype, size_t sz);

int edata_to_timespec(edata_t *x, struct timespec *y);

#endif

/* vi: set expandtab sw=4 ts=4: */
