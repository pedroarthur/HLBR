/**************************************
* This is a multi-string matching
* algorithm based on a Boyer-Moore
* string match.  It matches multiple
* substrings in a candidate string
*
* Jason Larsen
* 4/21/03
***************************************/
#include "jtree.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include "bits.h"

//#define DEBUGBUILD
//#define DEBUGMATCH
//#define DEBUGFINAL
//#define DEBUGESCAPE

#ifdef DEBUGFINAL
int	node_count=0;
#endif

#ifdef DEBUGESCAPE
#define DBGESCAPE(a)	DBG(a)
#else
#define DBGESCAPE(a)
#endif


int calloc_count = 0;
int free_count = 0;
int FreeNode(JNode* n);

extern GlobalVars	Globals;

/**
 * Set up the tree.
 */
int InitJTree(JTree* j, char NoCase)
{
	DEBUGPATH;

	bzero(j, sizeof(JTree));
	
	j->NoCase = NoCase;
	
	return TRUE;
}

/**
 * Add a string to the tree.
 */
int AddStringJTreeReal(JTree* j, unsigned char* String, int SLen, int RuleID)
{
	JNode*	node;
	int		i;

	DEBUGPATH;

	if (!j) return FALSE;
	if (!String) return FALSE;
	if (SLen>MAX_STRING_LEN) return FALSE;

	j->IsFinalized = FALSE;
	
	/* if this is the first string in the tree... */
	if (!j->Head) {
#ifdef DEBUGBUILD
		printf("First String in tree\n");
#endif	
		j->Head = calloc(sizeof(JNode),1);
		if (!j->Head) {
			printf("Out of memory\n");
			return FALSE;
		}
#ifdef DEBUGFINAL		
		node_count++;
#endif		
	}
	
	node = j->Head;
	
	for (i=0;i<SLen;i++) {
		if (!node->Bytes[String[i]]) {
#ifdef DEBUGBUILD
			printf("Adding Node for byte %c\n",String[i]);
#endif			
			node->Bytes[String[i]] = calloc(sizeof(JNode),1);
			calloc_count++;
			if (!node->Bytes[String[i]]) {
				printf("Out of memory\n");
				return FALSE;
			}
#ifdef DEBUGFINAL			
			node_count++;
#endif			
			
			/*in a nocase tree, point both cases to the same node*/
			if (j->NoCase) {
				node->Bytes[tolower(String[i])]=node->Bytes[String[i]];
				node->Bytes[toupper(String[i])]=node->Bytes[String[i]];
			}
			
			node->Count++;
		}
		node = node->Bytes[String[i]];
		node->temp = String[i];
	}
	
	node->IsTerminal = TRUE;
	
	/*set the bit in the mask*/
	SetBit(j->DependMask, Globals.NumRules, RuleID, 1);
	//SetBit(node->TerminalMask, Globals.NumRules, RuleID, 1);
	node->TerminalRuleID = RuleID;
	
	return TRUE;
}

/**
 * Add a string to the tree. Decode binary sections (defined between ||).
 */
int AddStringJTree(JTree* j, unsigned char* String, int SLen, int RuleID)
{
	unsigned char	Buff[MAX_STRING_LEN+1];
	int		BuffLen;
	int		i;
	int		IsBinary;
	
	char		BinBuff[6];
	int		BinChar;
	
	DEBUGPATH;

	/* apply the escape decoding */
	IsBinary = FALSE;
	BuffLen = 0;
	for (i=0;i<SLen;i++) {
		if (String[i] == 0x00) break;
		if (String[i] == '|') {
			if (String[i+1] == '|') {
				DBGESCAPE(PRINTERROR("Literal Pipe\n"));
				Buff[BuffLen]='|';
				BuffLen++;
			} else {
				if (IsBinary) {
					DBGESCAPE(PRINTERROR("Switching to text mode\n"));
					IsBinary = FALSE;
				} else {
					DBGESCAPE(PRINTERROR("Switching to binary mode\n"));
					IsBinary = TRUE;
				}
			}
		} else {
			if (IsBinary) {
				while (String[i] == ' ') i++;
				if (String[i] == 0x00) {
					PRINTERROR("Unexpected end of string. Expected |\n");
					return FALSE;
				}
				
				BinBuff[0] = String[i];
				BinBuff[1] = String[i+1];
				BinBuff[2] = 0x00;
				
				if ( (BinBuff[0] == '|') || (BinBuff[1] == '|')) {
					PRINTERROR1("Parse Error \"%s\"\n", BinBuff);
					return FALSE;
				}
				
				BinChar = strtoul(BinBuff, NULL, 16);
				
				DBGESCAPE(PRINTERROR1("Adding binary character %02X\n", BinChar));
				Buff[BuffLen]=BinChar;

				BuffLen++;
				i++;
			} else {
				DBGESCAPE(PRINTERROR("Adding literal character %c\n",String[i]));
				Buff[BuffLen] = String[i];
				BuffLen++;
			}
		}
	}

	DBGESCAPE(PRINTERROR1("Buff is %s\n",Buff));
	DBGESCAPE(PRINTERROR1("BuffLen is %i\n", BuffLen));
	
	/* really add it */
	return AddStringJTreeReal(j, Buff, BuffLen, RuleID);
}


/**
 * Find the optimal node (jtree) to continue from for the given string.
 */
JNode* FindOptimalNode(JTree* j, JNode*	n, unsigned char* String, int SLen)
{
	int		i,k;
	unsigned char*	s;
	JNode*		optimal;
	JNode*		node;
	
	DEBUGPATH;

#ifdef DEBUGBUILD
	printf("(%s)->",String);
#endif
	
	/*the default is always to return to the root node*/
	optimal=j->Head;

	/*go search for a better node to return to*/
	if (SLen!=0){
		for (i=SLen-1;i>0;i--){
#ifdef DEBUGBUILD
			printf("Testing char %c\n",String[i]);
#endif			
			node=j->Head;
			k=0;
			while (node){
				if (node->Bytes[String[i+k]]){
#ifdef DEBUGBUILD
					printf("Match at %c\n",String[i+k]);
#endif					
					if (i+k==SLen-1){
#ifdef DEBUGBUILD
						printf("New Optimal found\n");
#endif						
						optimal=node->Bytes[String[i+k]];
						break;
					}
					node=node->Bytes[String[i+k]];
					k++;
				}else{
					break;
				}
				
			}
		}
	}

#ifdef DEBUGBUILD
	if (optimal==j->Head){
		printf("Root\n");
	}
#endif
	
	/*find the optimal nodes for the children*/
	for (i=0;i<256;i++){
		/*skip the upper case section in nocase trees*/
		if (j->NoCase){
			if (i==65) i=91;
		}
		
		if (n->Bytes[i]){
			s=calloc(sizeof(char), MAX_STRING_LEN+1);
			if (!s){
				printf("Out of memory\n");
				return j->Head;
			}
			memcpy(s, String, SLen);
			s[SLen]=i;
			n->Bytes[i]->FailNode=FindOptimalNode(j,n->Bytes[i], s, SLen+1);
			if (s) free(s);
		}
	}

	return optimal;
}


/******************************************
* Swap full nodes for short nodes to 
* save memory
******************************************/
int ConvertNode(JNode* n, JNode** Parent, int NoCase){
	int		i;
	SJNode*	Short;
	static int		SCount=0;
	static int		LCount=0;
	
	DEBUGPATH;

	printf("This node has %i subnodes \"%c\"\n",n->Count,n->temp);

	/*first convert all the subnodes so the leaves*/
	/*get converted first*/
	
	for (i=0;i<256;i++){
		if (NoCase){
			if (i==65) i=91;
		}

		if ( (n->Bytes[i]) && (!ConvertNode(n->Bytes[i], &n->Bytes[i], NoCase)) )
			return FALSE;
	}
	
	/*root node is always a normal node*/
	if (!Parent) return TRUE;
	
	/*now convert this node*/
	if (n->Count<2){
		Short=calloc(sizeof(SJNode),1);
		Short->NodeType=NODE_TYPE_SHORT;
		if (n->Count==0){
			Short->PassNode=NULL;
		}else{
			for (i=0;i<256;i++)
				if (n->Bytes[i]){
					Short->PassNode=n->Bytes[i];
					break;
				}
		}
		Short->temp=n->temp;
		Short->Byte=n->temp;
		Short->FailNode=n->FailNode;
		Short->IsTerminal=n->IsTerminal;
		Short->TerminalRuleID=n->TerminalRuleID;
		
		free(*Parent);
		*Parent=(JNode*)Short;
		*Parent=NULL;
		
		SCount++;
	}else{
		LCount++;
	}

	printf("There are %i short and %i long\n",SCount, LCount);

	return TRUE;
}

int FreeNode(JNode* n){
	int i;
	
	for (i=0;i<256;i++){		
		if (n->Bytes[i]){
			FreeNode(n->Bytes[i]);
			n->Bytes[i]=NULL;
		}
	}

	free(n);
	free_count++;
	
	return TRUE;
	
}

/******************************************
* Swap full nodes for short nodes to 
* save memory
******************************************/
int CompressJTree(JTree* j){

	DEBUGPATH;

	return ConvertNode(j->Head, NULL, j->NoCase);
}

/******************************************
* Fill in the FailNode 
* entries
*******************************************/
int FinalizeJTree(JTree* j){
	
	DEBUGPATH;

	if (!j) return FALSE;
	if (!j->Head){
		printf("Tree is empty\n");
		return FALSE;
	}

#ifdef DEBUGFINAL
	printf("finding optimal node for %i nodes\n",node_count);
#endif

	j->Head->FailNode=FindOptimalNode(j, j->Head, NULL, 0);


/*
	printf("Compressing tree\n");
	if (!CompressJTree(j)){
		printf("Couldn't compress tree\n");
		return FALSE;
	}
*/
	
	return TRUE;
}

/*****************************************************
* See which of the substrings exist in the string
*****************************************************/
int MatchStrings(JTree* j, unsigned char* PacketRuleBits, unsigned char* String, int SLen){
	JNode*			node;
	int				i;
	unsigned char	LocalDepend[MAX_RULES/8];
	
	DEBUGPATH;

	memcpy(LocalDepend, j->DependMask, MAX_RULES/8);

	node=j->Head;
	for (i=0;i<SLen;i++){
#ifdef DEBUGMATCH	
		if (node==j->Head){
			printf("on <Root> looking for %c\n", String[i]);
		}else{
			printf("on %c      looking for %c\n", node->temp, String[i]);
		}
#endif		
		if (node->Bytes[String[i]]){
			node=node->Bytes[String[i]];
			if (node->IsTerminal){
#ifdef DEBUG			
				printf("Match on %c\n",String[i]);
#endif				
				SetBit(LocalDepend, Globals.NumRules, node->TerminalRuleID, 0);
			}
		}else{

		  // original code! including Boyer moore optimization:
		        //node=node->FailNode;
                        //if (node!=j->Head) i--;

		        node=j->Head;
                        if(node->Bytes[String[i]]) i--;


		}
	}

	NotAndBitFields(PacketRuleBits, LocalDepend, PacketRuleBits, Globals.NumRules);

	return TRUE;
}
