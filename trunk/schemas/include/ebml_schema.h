#include "parser.h"
#include "parser_defs.h"

#include <stddef.h>

#define TRIE_NODE_PREFIX ebml

#define ebml_TRIE_ROOT (&ebml_trie_node_250d137c1e651052)

DEF_TRIE_NODE_INFORMATION(5afc12a2d2563707, "/82",
	"/82 -> DocTypeExtension", NULL, 64
);

DEF_TRIE_NODE_INFORMATION(3697f09f8bc99cee, "082",
	"082 -> DocType", NULL, 8
);

DEF_TRIE_NODE_INFORMATION(51996277f9069e9a, "182",
	"182 -> DocTypeExtensionName", NULL, 8
);

DEF_TRIE_NODE_INFORMATION(8793bf887d9bafb3, "282",
	"282 -> DocTypeExtensionVersion", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(570cee804817c171, "382",
	"382 -> DocTypeReadVersion", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(8f3b74caa87c2bd3, "482",
	"482 -> EBMLVersion", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(3ef78b1cf19bf7ac, "582",
	"582 -> DocTypeVersion", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(e33f0af06a827a6d, "XyRFO",
	"XyRFO -> EBML", NULL, 64
);

DEF_TRIE_NODE_INFORMATION(6b29b53d06e32920, "g1",
	"g1 -> Void", NULL, 128
);

DEF_TRIE_NODE_INFORMATION(85d19ab06246af95, "m92",
	"m92 -> EBMLMaxIDLength", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(3c4c3ee763085ee2, "n92",
	"n92 -> EBMLMaxSizeLength", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(515f4fbf4ed849fa, "r92",
	"r92 -> EBMLReadVersion", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(a74e2ee871b32e3c, "z0",
	"z0 -> CRC-32", NULL, 128
);

DEF_TRIE_NODE_BRANCH(250d137c1e651052, "NULL",
	ENTRY('/', 5afc12a2d2563707),
	ENTRY('0', 3697f09f8bc99cee),
	ENTRY('1', 51996277f9069e9a),
	ENTRY('2', 8793bf887d9bafb3),
	ENTRY('3', 570cee804817c171),
	ENTRY('4', 8f3b74caa87c2bd3),
	ENTRY('5', 3ef78b1cf19bf7ac),
	ENTRY('X', e33f0af06a827a6d),
	ENTRY('g', 6b29b53d06e32920),
	ENTRY('m', 85d19ab06246af95),
	ENTRY('n', 3c4c3ee763085ee2),
	ENTRY('r', 515f4fbf4ed849fa),
	ENTRY('z', a74e2ee871b32e3c)
);

#undef TRIE_NODE_PREFIX

