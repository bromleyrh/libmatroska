#include "parser.h"
#include "parser_defs.h"

#include <stddef.h>

#define TRIE_NODE_PREFIX matroska_semantics

#define matroska_semantics_TRIE_ROOT (&matroska_semantics_trie_node_4e0bea38ad6796e3)

int matroska_contentcompalgo_handler(const char *, enum etype, edata_t *, const void *, size_t, size_t, size_t, off_t, void *);

DEF_TRIE_NODE_INFORMATION(f0ca00471dbe8876, "I72",
	"I72 -> ElementHandler", &matroska_contentcompalgo_handler, 2
);

int matroska_contentcompsettings_handler(const char *, enum etype, edata_t *, const void *, size_t, size_t, size_t, off_t, void *);

DEF_TRIE_NODE_INFORMATION(f97ef5a2b7f351c1, "J72",
	"J72 -> ElementHandler", &matroska_contentcompsettings_handler, 128
);

int matroska_tracknumber_handler(const char *, enum etype, edata_t *, const void *, size_t, size_t, size_t, off_t, void *);

DEF_TRIE_NODE_INFORMATION(3123b404e030512f, "L1",
	"L1 -> ElementHandler", &matroska_tracknumber_handler, 64
);

int matroska_block_handler(const char *, enum etype, edata_t *, const void *, size_t, size_t, size_t, off_t, void *);

DEF_TRIE_NODE_INFORMATION(94bb6e1820481f44, "V0",
	"V0 -> ElementHandler", &matroska_block_handler, 64
);

int matroska_simpleblock_handler(const char *, enum etype, edata_t *, const void *, size_t, size_t, size_t, off_t, void *);

DEF_TRIE_NODE_INFORMATION(6541088397072c6c, "X0",
	"X0 -> ElementHandler", &matroska_simpleblock_handler, 64
);

DEF_TRIE_NODE_BRANCH(4e0bea38ad6796e3, "NULL",
	ENTRY('I', f0ca00471dbe8876),
	ENTRY('J', f97ef5a2b7f351c1),
	ENTRY('L', 3123b404e030512f),
	ENTRY('V', 94bb6e1820481f44),
	ENTRY('X', 6541088397072c6c)
);

#undef TRIE_NODE_PREFIX

