#include "parser.h"
#include "parser_defs.h"

#include <stddef.h>

#define TRIE_NODE_PREFIX matroska_semantics

DEF_EBML_DATA(61485a4d3807a977, "XyRF8 -> EBMLSemantics", NULL, 64);

int matroska_tracknumber_handler(const char *, enum etype, edata_t *, void **, size_t *, void **, size_t *, size_t, size_t, off_t, void *, int);

DEF_EBML_DATA(995430b2b344fab4, "L1 -> ElementHandler1", &matroska_tracknumber_handler, 64);

int matroska_simpleblock_handler(const char *, enum etype, edata_t *, void **, size_t *, void **, size_t *, size_t, size_t, off_t, void *, int);

DEF_EBML_DATA(6c96b2ba9464a50a, "X0 -> ElementHandler2", &matroska_simpleblock_handler, 64);

int matroska_block_handler(const char *, enum etype, edata_t *, void **, size_t *, void **, size_t *, size_t, size_t, off_t, void *, int);

DEF_EBML_DATA(5d422e94b7585337, "V0 -> ElementHandler3", &matroska_block_handler, 64);

int matroska_contentcompalgo_handler(const char *, enum etype, edata_t *, void **, size_t *, void **, size_t *, size_t, size_t, off_t, void *, int);

DEF_EBML_DATA(f49e569718548582, "I72 -> ElementHandler4", &matroska_contentcompalgo_handler, 2);

int matroska_contentcompsettings_handler(const char *, enum etype, edata_t *, void **, size_t *, void **, size_t *, size_t, size_t, off_t, void *, int);

DEF_EBML_DATA(c9d72920e2258d3c, "J72 -> ElementHandler5", &matroska_contentcompsettings_handler, 128);

#define matroska_semantics_TRIE_ROOT (&matroska_semantics_trie_node_56c0bad518162816)

DEF_TRIE_NODE_INFORMATION(f49e569718548582, "I72",
	EBML_PARENT(61485a4d3807a977)
);

DEF_TRIE_NODE_INFORMATION(c9d72920e2258d3c, "J72",
	EBML_PARENT(61485a4d3807a977)
);

DEF_TRIE_NODE_INFORMATION(995430b2b344fab4, "L1",
	EBML_PARENT(61485a4d3807a977)
);

DEF_TRIE_NODE_INFORMATION(5d422e94b7585337, "V0",
	EBML_PARENT(61485a4d3807a977)
);

DEF_TRIE_NODE_INFORMATION(6c96b2ba9464a50a, "X0",
	EBML_PARENT(61485a4d3807a977)
);

DEF_TRIE_NODE_BRANCH(56c0bad518162816, "NULL",
	ENTRY('I', f49e569718548582),
	ENTRY('J', c9d72920e2258d3c),
	ENTRY('L', 995430b2b344fab4),
	ENTRY('V', 5d422e94b7585337),
	ENTRY('X', 6c96b2ba9464a50a)
);

#undef TRIE_NODE_PREFIX

