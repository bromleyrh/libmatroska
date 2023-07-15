/*
 * debug.c
 */

#include "debug.h"

#define X(id) \
void \
trace_handler_##id(void) \
{ \
    return; \
}
LIST_TRACE_HANDLERS(X)
#undef X

/* vi: set expandtab sw=4 ts=4: */
