/*
 * common.h
 */

#ifndef _COMMON_H
#define _COMMON_H

#define EXPORTED __attribute__((__visibility__("default")))

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define PLURAL(val, suffix) ((val) == 1 ? "" : suffix)

#endif

/* vi: set expandtab sw=4 ts=4: */
