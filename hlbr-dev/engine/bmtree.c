#include "bmtree.h"
#include <string.h>
#include "bits.h"
#include <stdio.h>
#include <stdlib.h>
#ifdef _SOLARIS_
#include <strings.h>
#endif
#include <ctype.h>


//#define DEBUGBUILD

extern GlobalVars	Globals;

/****************************************************
* Start a new Boyer-Moore Tree
****************************************************/
int	InitTree(BMTree* tree, char IgnoreCase){

#ifdef DEBUGPATH
	printf("In InitTree\n");
#endif

	bzero(tree, sizeof(BMTree));

	return TRUE;
}

/**************************************************
* Add a string to the tree
***************************************************/
int AddToTreeSorted(BMTree* Tree, char* String, int Len, int RuleID){
	int 	i;
	BNode**	this;
	BNode** last;
	int		count;
	
#ifdef DEBUGPATH
	printf("In AddToTree\n");
#endif

	if (Len==0) return FALSE;

#ifdef DEBUGBUILD
	printf("Adding %s to tree\n",String);
#endif	

	SetBit(Tree->TreeDependMask, Globals.NumRules, RuleID, 1);

	this=&Tree->TreeHead;
	last=this;
	for (i=0;i<Len;i++){
		printf("This letter is a %c\n",String[i]);		
		count=0;
		while (*this){
			printf("Comparing %c vs %c\n",String[i], (*this)->byte);
			if ( (*this)->byte > String[i]){
#ifdef DEBUGBUILD
				printf("%c goes before %c\n", String[i], (*this)->byte);
#endif		
				(*last)->NextPeer=calloc(sizeof(BNode),1);
				last=&(*last)->NextPeer;
				(*last)->NextPeer=(*this);
				
				(*last)->byte=String[i];
				this=&(*last)->Child;
				break;
			}
			last=this;
			this=&(*this)->NextPeer;
			printf("Next\n");
			count++;
			if (count>6) exit(0);
		}
		
		if (!(*this)){
#ifdef DEBUGBUILD
			printf("There are no children. Adding a child \"%c\"\n", String[i]);
#endif		
			(*this)=calloc(sizeof(BNode),1);
			(*this)->byte=String[i];
			last=this;
			this=&(*this)->Child;
			continue;
		}

	}


	printf("This is the end\n");
	(*last)->IsTerminal=TRUE;
	(*last)->TerminalRuleID=RuleID;
	
	return TRUE;
}

/**************************************************
* Add a string to the tree
***************************************************/
int AddToTree(BMTree* Tree, char* String, int Len, int RuleID){
	int 	i;
	BNode*	this;
	BNode**	that;
	char	HexMode;
	char	NextChar;
	char	HexChar[3];
	int		HexCount;
	
#ifdef DEBUGPATH
	printf("In AddToTree\n");
#endif

	if (Len==0) return FALSE;

#ifdef DEBUGBUILD
	printf("Adding %s to tree\n",String);
#endif	

	SetBit(Tree->TreeDependMask, Globals.NumRules, RuleID, 1);

	that=&Tree->TreeHead;
	HexMode=FALSE;
	for (i=0;i<Len;i++){
		if (HexMode){
			NextChar=String[i];
		
			/*Check for the end of a hex encoded block*/
			if (NextChar=='|'){
				HexMode=FALSE;
				continue;
			}
			
			/*compress white space*/
			if (NextChar==' ') continue;
			
			HexChar[HexCount]=NextChar;
			HexCount++;
			if (HexCount==2){
				NextChar=strtoul(HexChar, NULL, 16);
				HexCount=0;
#ifdef DEBUG
				printf("Hex processed as %02x\n",HexChar);
#endif							
			}else{
				continue;
			}
		}else{
			/*Read in the bytes literally*/
			if (Tree->IgnoreCase){
				NextChar=tolower(String[i]);
			}else{
				NextChar=String[i];
			}
			
			/*check for the start of a hex encoded block*/
			if (NextChar=='|'){
				if (String[i+1]=='|'){
					/*this is a literal pipe*/
					NextChar='|';
					i++;
				}else{
					HexMode=TRUE;
					HexCount=0;
					continue;
				}
			}
		}
		
#ifdef DEBUGBUILD	
		if ((*that) && (*that)->IsTerminal) printf("Terminal Node\n");
#endif		
		if (!*that){
#ifdef DEBUGBUILD
			printf("Allocating a new child node for %c (%i)\n",NextChar, NextChar);
#endif			
			(*that)=calloc(sizeof(BNode),1);
			(*that)->byte=NextChar;
			this=(*that);
			that=&(*that)->Child;
		}else{
			while (*that){
				if ( (*that)->byte==NextChar){
#ifdef DEBUGBUILD				
					printf("Already had a \"%c\"\n",NextChar);
#endif					
					break;
				}else{
#ifdef DEBUGBUILD
					printf("Wasn't that one \"%c\"\n", (*that)->byte);
#endif				
					that=&(*that)->NextPeer;
				}
			}
			
			if (!(*that)){
#ifdef DEBUGBUILD			
				printf("Allocating a new peer node for %c (%i)\n",NextChar, NextChar);
#endif				
				(*that)=calloc(sizeof(BNode),1);
				(*that)->byte=NextChar;
				this=(*that);
			}

			/*check to see if there are no children*/
			if (i==Len-1) break;
								
			that=&(*that)->Child;
			this=(*that);
		}		
	}
#ifdef DEBUGBUILD	
	printf("this is \"%c\"\n",this->byte);
#endif	
	this->IsTerminal=TRUE;
	this->TerminalRuleID=RuleID;
	
	return TRUE;
}



/********************************************
* do the tree pattern matching
********************************************/
int MatchStringTree(BMTree* Tree, unsigned char* PacketRuleBits, char* Packet, int Plen){
	register int	i;
	register int	j;
	BNode*			this;
	unsigned char	LocalDepend[MAX_RULES/8];
	unsigned char	ThisChar;
	
#ifdef DEBUGPATH
	printf("In MatchStringTree\n");
#endif	
	
	memcpy(LocalDepend, Tree->TreeDependMask, MAX_RULES/8);
	
	for (i=0;i<Plen;i++){
		j=0;
		this=Tree->TreeHead;
		while (this){
			if ( (j+i+1)>Plen){
#ifdef DEBUG			
				printf("I ran off the edge of the packet\n");
#endif				
				break;
			}
			if (Tree->IgnoreCase){
				ThisChar=tolower(Packet[j+i]);
			}else{
				ThisChar=Packet[j+i];
			}
			if (ThisChar==this->byte){
				if (this->IsTerminal){
#ifdef DEBUG				
					printf("Rule %i matches\n",this->TerminalRuleID);
#endif					
					SetBit(LocalDepend, Globals.NumRules, this->TerminalRuleID, 0);
				}
				this=this->Child;
				j++;
			}else{
				this=this->NextPeer;
			}
		}
	}
	
	NotAndBitFields(PacketRuleBits, LocalDepend, PacketRuleBits, Globals.NumRules);
	
	return TRUE;
}

/*******************************************
* We're all done with this tree
********************************************/
void FreeTree(BMTree* tree){
}
