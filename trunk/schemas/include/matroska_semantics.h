#include "parser.h"
#include "parser_defs.h"

#include <stddef.h>

#define TRIE_NODE_PREFIX matroska_semantics

#define matroska_semantics_TRIE_ROOT (&matroska_semantics_trie_node_7da5aadf013a6947)

int matroska_contentcompalgo_handler(const char *, enum etype, edata_t *, const void *, size_t, size_t, off_t, void *);

DEF_TRIE_NODE_INFORMATION(5d813af5e5d07293, "I72",
	"I72 -> ElementHandler", &matroska_contentcompalgo_handler, 2
);

int matroska_contentcompsettings_handler(const char *, enum etype, edata_t *, const void *, size_t, size_t, off_t, void *);

DEF_TRIE_NODE_INFORMATION(73a9e22af01f45b4, "J72",
	"J72 -> ElementHandler", &matroska_contentcompsettings_handler, 128
);

int matroska_tracknumber_handler(const char *, enum etype, edata_t *, const void *, size_t, size_t, off_t, void *);

DEF_TRIE_NODE_INFORMATION(1e02043c2b83120f, "L1",
	"L1 -> ElementHandler", &matroska_tracknumber_handler, 64
);

int matroska_block_handler(const char *, enum etype, edata_t *, const void *, size_t, size_t, off_t, void *);

DEF_TRIE_NODE_INFORMATION(99d9392d3779d318, "V0",
	"V0 -> ElementHandler", &matroska_block_handler, 64
);

int matroska_simpleblock_handler(const char *, enum etype, edata_t *, const void *, size_t, size_t, off_t, void *);

DEF_TRIE_NODE_INFORMATION(78b42be19cf9ee99, "X0",
	"X0 -> ElementHandler", &matroska_simpleblock_handler, 64
);

DEF_TRIE_NODE_BRANCH(7da5aadf013a6947, "NULL",
	ENTRY('I', 5d813af5e5d07293),
	ENTRY('J', 73a9e22af01f45b4),
	ENTRY('L', 1e02043c2b83120f),
	ENTRY('V', 99d9392d3779d318),
	ENTRY('X', 78b42be19cf9ee99)
);

#undef TRIE_NODE_PREFIX

