#include "parser.h"
#include "parser_defs.h"

#include <stddef.h>

#define TRIE_NODE_PREFIX matroska_semantics

extern const struct elem_data *ebml_data;

DEF_EBML_DATA(ebcb62ba3f3cb3ad, "XyRF8 -> EBMLSemantics", NULL, 64, &ebml_data);

int matroska_tracknumber_handler(const char *, enum etype, edata_t *, void **, size_t *, void **, size_t *, size_t, size_t, struct buf *, off_t, void *, int);

DEF_EBML_DATA(9ca558f56a65ed0e, "L1 -> ElementHandler1", &matroska_tracknumber_handler, 64, NULL);

int matroska_simpleblock_handler(const char *, enum etype, edata_t *, void **, size_t *, void **, size_t *, size_t, size_t, struct buf *, off_t, void *, int);

DEF_EBML_DATA(69b1794b3b997964, "X0 -> ElementHandler2", &matroska_simpleblock_handler, 64, NULL);

int matroska_block_handler(const char *, enum etype, edata_t *, void **, size_t *, void **, size_t *, size_t, size_t, struct buf *, off_t, void *, int);

DEF_EBML_DATA(7afcf64e8f3e741f, "V0 -> ElementHandler3", &matroska_block_handler, 64, NULL);

int matroska_contentcompalgo_handler(const char *, enum etype, edata_t *, void **, size_t *, void **, size_t *, size_t, size_t, struct buf *, off_t, void *, int);

DEF_EBML_DATA(14599d4adc995e60, "I72 -> ElementHandler4", &matroska_contentcompalgo_handler, 2, NULL);

int matroska_contentcompsettings_handler(const char *, enum etype, edata_t *, void **, size_t *, void **, size_t *, size_t, size_t, struct buf *, off_t, void *, int);

DEF_EBML_DATA(00973ed5ed95eeb0, "J72 -> ElementHandler5", &matroska_contentcompsettings_handler, 128, NULL);

#define matroska_semantics_TRIE_ROOT (&matroska_semantics_trie_node_12b4b594924a9698)

DEF_TRIE_NODE_INFORMATION(14599d4adc995e60, "I72",
	EBML_DATA(ebcb62ba3f3cb3ad)
);

DEF_TRIE_NODE_INFORMATION(00973ed5ed95eeb0, "J72",
	EBML_DATA(ebcb62ba3f3cb3ad)
);

DEF_TRIE_NODE_INFORMATION(9ca558f56a65ed0e, "L1",
	EBML_DATA(ebcb62ba3f3cb3ad)
);

DEF_TRIE_NODE_INFORMATION(7afcf64e8f3e741f, "V0",
	EBML_DATA(ebcb62ba3f3cb3ad)
);

DEF_TRIE_NODE_INFORMATION(69b1794b3b997964, "X0",
	EBML_DATA(ebcb62ba3f3cb3ad)
);

DEF_TRIE_NODE_BRANCH(12b4b594924a9698, "NULL",
	ENTRY('I', 14599d4adc995e60),
	ENTRY('J', 00973ed5ed95eeb0),
	ENTRY('L', 9ca558f56a65ed0e),
	ENTRY('V', 7afcf64e8f3e741f),
	ENTRY('X', 69b1794b3b997964)
);

#undef TRIE_NODE_PREFIX

