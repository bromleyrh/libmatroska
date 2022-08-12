/*
 * element.h
 */

#ifndef _ELEMENT_H
#define _ELEMENT_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define ETYPE_HASH(c1, c2) ((unsigned)(256 * (c1) + (c2)))

#define _LIST_ETYPE(type, name, hash) _X(ETYPE_##type, name, hash)

#define LIST_ETYPES() \
    _LIST_ETYPE(INTEGER,    "integer",  ETYPE_HASH('i', 'n')) \
    _LIST_ETYPE(UINTEGER,   "uinteger", ETYPE_HASH('u', 'i')) \
    _LIST_ETYPE(FLOAT,      "float",    ETYPE_HASH('f', 'l')) \
    _LIST_ETYPE(STRING,     "string",   ETYPE_HASH('s', 't')) \
    _LIST_ETYPE(UTF8,       "utf-8",    ETYPE_HASH('u', 't')) \
    _LIST_ETYPE(DATE,       "date",     ETYPE_HASH('d', 'a')) \
    _LIST_ETYPE(MASTER,     "master",   ETYPE_HASH('m', 'a')) \
    _LIST_ETYPE(BINARY,     "binary",   ETYPE_HASH('b', 'i'))

enum etype {
    ETYPE_NONE,
#define _X(type, name, hash) \
    type,
    LIST_ETYPES()
#undef _X
};

typedef struct {
    enum etype      type;
    union {
        int64_t     integer;
        uint64_t    uinteger;
        double      floatpt;
        time_t      date;
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

#endif

/* vi: set expandtab sw=4 ts=4: */
