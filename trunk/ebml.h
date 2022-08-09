/*
 * ebml.h
 */

#ifndef _EBML_H
#define _EBML_H

#include "parser.h"

#include <stdio.h>

#include <sys/types.h>

typedef struct ebml_hdl *ebml_hdl_t;

typedef struct {
    int (*open)(void **, void *);
    int (*close)(void *);
    int (*read)(void *, void *, ssize_t *);
    int (*get_fpos)(void *, off_t *);
} ebml_io_fns_t;

struct ebml_file_args {
    int         fd;
    const char  *pathname;
};

extern const ebml_io_fns_t ebml_file_fns;
#define EBML_FILE_FNS (&ebml_file_fns)

int ebml_open(ebml_hdl_t *hdl, const ebml_io_fns_t *fns,
              const struct parser *parser, void *args);

int ebml_close(ebml_hdl_t hdl);

int ebml_dump(FILE *f, ebml_hdl_t hdl);

#endif

/* vi: set expandtab sw=4 ts=4: */
