/*
 * util.h
 */

#ifndef _UTIL_H
#define _UTIL_H

#include "config.h"

#ifdef HAVE_FLS
#include <strings.h>
#endif

#ifndef HAVE_FLS
int fls(int i);

#endif

#endif

/* vi: set expandtab sw=4 ts=4: */
