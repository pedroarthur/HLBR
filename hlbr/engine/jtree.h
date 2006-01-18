#ifndef HLBR_JTREE_H
#define HLBR_JTREE_H

#include "hlbr.h"

#define MAX_STRING_LEN	1024

#define NODE_TYPE_NORMAL	1
#define NODE_TYPE_SHORT		2

typedef struct short_jnode{
	unsigned char	NodeType;
	unsigned char	temp;
	unsigned char	Byte;
	struct jnode*	PassNode;
	struct jnode*	FailNode;
	char			IsTerminal;
	int				TerminalRuleID;
	struct jnode*	Parent;
} SJNode;

typedef struct jnode{
	unsigned char	NodeType;
	unsigned char	temp;
	struct jnode*	Bytes[256];
	struct jnode*	FailNode;
	char			IsTerminal;
	int				TerminalRuleID;
	int				Count;
} JNode;

typedef struct jtree{
	JNode*			Head;
	char			NoCase;
	char			IsFinalized;
	unsigned char	DependMask[MAX_RULES/8];
} JTree;


int	InitJTree(JTree* j, char NoCase);
int AddStringJTree(JTree* j, unsigned char* String, int SLen, int RuleID);
int FinalizeJTree(JTree* j);
int MatchStrings(JTree* j, unsigned char* PacketRuleBits, unsigned char* String, int SLen);

#endif
