#ifndef HOGWASH_BOYER_MOORE_TREE_H
#define HOGWASH_BOYER_MOORE_TREE_H

#include "../config.h"
#include "hogwash.h"

typedef struct bnode{
	unsigned char	byte;
	struct bnode*	Child;
	struct bnode*	NextPeer;
	char			IsTerminal;
	int				TerminalRuleID;
} BNode;

typedef struct bm_tree{
	BNode*			TreeHead;
	unsigned char	TreeDependMask[MAX_RULES/8];
	char			IgnoreCase;
}BMTree;


int	InitTree(BMTree* Tree, char IgnoreCase);
int AddToTree(BMTree* Tree, char* String, int Len, int RuleID);
int MatchStringTree(BMTree* Tree, unsigned char* PacketRuleBits, char* Packet, int Plen);
void FreeTree(BMTree* Tree);

#endif
