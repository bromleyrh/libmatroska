#include "parser.h"
#include "parser_defs.h"

#include <stddef.h>

#define TRIE_NODE_PREFIX ebml

#define ebml_TRIE_ROOT (&ebml_trie_node_700d458032367a80)

DEF_TRIE_NODE_INFORMATION(9de233085e6c13bd, "/82",
	"/82 -> DocTypeExtension", NULL, 64
);

DEF_TRIE_NODE_INFORMATION(fa52c9f73fb2f4a4, "082",
	"082 -> DocType", NULL, 8
);

DEF_TRIE_NODE_INFORMATION(2072f4971cc5c3aa, "182",
	"182 -> DocTypeExtensionName", NULL, 8
);

DEF_TRIE_NODE_INFORMATION(cd46fa4e8f866cc7, "282",
	"282 -> DocTypeExtensionVersion", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(a0aea5eafd79804e, "382",
	"382 -> DocTypeReadVersion", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(021b0577d422e3fc, "482",
	"482 -> EBMLVersion", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(dac014b05ec5df5c, "582",
	"582 -> DocTypeVersion", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(f3618bef43cbcf9f, "XyRFO",
	"XyRFO -> EBML", NULL, 64
);

DEF_TRIE_NODE_INFORMATION(0487e5991e90a6d9, "g1",
	"g1 -> Void", NULL, 128
);

DEF_TRIE_NODE_INFORMATION(3df9ddad2eabcb91, "m92",
	"m92 -> EBMLMaxIDLength", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(d2cc328ac4fd9004, "n92",
	"n92 -> EBMLMaxSizeLength", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(2edcd557d9e1a544, "r92",
	"r92 -> EBMLReadVersion", NULL, 2
);

DEF_TRIE_NODE_INFORMATION(b106fde8db935a07, "z0",
	"z0 -> CRC-32", NULL, 128
);

DEF_TRIE_NODE_BRANCH(700d458032367a80, "NULL",
	ENTRY('/', 9de233085e6c13bd),
	ENTRY('0', fa52c9f73fb2f4a4),
	ENTRY('1', 2072f4971cc5c3aa),
	ENTRY('2', cd46fa4e8f866cc7),
	ENTRY('3', a0aea5eafd79804e),
	ENTRY('4', 021b0577d422e3fc),
	ENTRY('5', dac014b05ec5df5c),
	ENTRY('X', f3618bef43cbcf9f),
	ENTRY('g', 0487e5991e90a6d9),
	ENTRY('m', 3df9ddad2eabcb91),
	ENTRY('n', d2cc328ac4fd9004),
	ENTRY('r', 2edcd557d9e1a544),
	ENTRY('z', b106fde8db935a07)
);

#undef TRIE_NODE_PREFIX

