/*
 * err.h
 */

#ifndef _ERR_H
#define _ERR_H

struct errmap_ent {
    int src;
    int dst;
};

extern const int min_errn;

extern const int errtbl[];

extern const struct errmap_ent errmap[];

extern const int errmapr[];

#endif

/* vi: set expandtab sw=4 ts=4: */
