#include "bits.h"
#include "hlbr.h"
#include <stdio.h>

/***************************************************
* Retrieve the value of a bit
***************************************************/
inline int GetBit(unsigned char* BitField, int BitFieldLen, int BitNum){
	char	byte;
	
	DEBUGPATH;

	if (BitNum > BitFieldLen-1) return FALSE;

	byte=BitField[BitNum/8];
	switch (BitNum%8){
	case 0:
		return byte & 0x80;
	case 1:
		return byte & 0x40;
	case 2:
		return byte & 0x20;
	case 3:
		return byte & 0x10;
	case 4:
		return byte & 0x08;
	case 5:
		return byte & 0x04;
	case 6:
		return byte & 0x02;
	case 7:
		return byte & 0x01;
	}	
	
	return FALSE;
}

/***************************************************
* Set the value of a bit
***************************************************/
inline void SetBit(unsigned char* BitField, int BitFieldLen, int BitNum, char Value){
	unsigned char*	byte;

	DEBUGPATH;
	
	byte=&BitField[BitNum/8];
	
	if (Value){
		switch (BitNum%8){
		case 0:
			*byte |= 0x80;
			break;
		case 1:
			*byte |= 0x40;
			break;
		case 2:
			*byte |= 0x20;
			break;
		case 3:
			*byte |= 0x10;
			break;
		case 4:
			*byte |= 0x08;
			break;
		case 5:
			*byte |= 0x04;
			break;
		case 6:
			*byte |= 0x02;
			break;
		case 7:
			*byte |= 0x01;
			break;
		}	
	}else{
		switch (BitNum%8){
		case 0:
			*byte &= 0x7F;
			break;
		case 1:
			*byte &= 0xBF;
			break;
		case 2:
			*byte &= 0xDF;
			break;
		case 3:
			*byte &= 0xEF;
			break;
		case 4:
			*byte &= 0xF7;
			break;
		case 5:
			*byte &= 0xFB;
			break;
		case 6:
			*byte &= 0xFD;
			break;
		case 7:
			*byte &= 0xFE;
			break;
		}	
	}	
}

/***************************************************
* Set the value of a range of bits
***************************************************/
inline void SetBits(unsigned char* BitField, int BitFieldLen, int StartBit, int EndBit, char Value){

  DEBUGPATH;

}

/***************************************************
* Calculate the bitwise NOT AND of the two bitfields
***************************************************/
inline void NotAndBitFields(unsigned char* BitField1, unsigned char* BitField2, unsigned char* TargetBitField, int BitFieldLen){
	unsigned int*	IntField1;
	unsigned int*	IntField2;
	unsigned int*	IntTarget;
	register int	i;
	register int	len;
	
	DEBUGPATH;

	IntField1=(unsigned int*)BitField1;
	IntField2=(unsigned int*)BitField2;
	IntTarget=(unsigned int*)TargetBitField;
	
	len = (BitFieldLen/32)+1;
	for (i=0;i<len;i++)
		IntTarget[i]=(IntField2[i]^0xFFFFFFFF) & IntField1[i];
}

/***************************************************
* Calculate the bitwise AND of the two bitfields
***************************************************/
inline void AndBitFields(unsigned char* BitField1, unsigned char* BitField2, unsigned char* TargetBitField, int BitFieldLen){	

  DEBUGPATH;

}

/***************************************************
* Calculate the bitwise OR of the two bitfields
***************************************************/
inline void OrBitFields(unsigned char* BitField1, unsigned char* BitField2, unsigned char* TargetBitField, int BitFieldLen){

  DEBUGPATH;

}

/***************************************************
* Calculate the bitwise OR of the two bitfields
* This is the slow way.  Finish the faster way later.
***************************************************/
int	CountBits(unsigned char* BitField, int BitFieldLen){
	int	i;
	int	count;
	
	DEBUGPATH;

	count=0;
	for (i=0;i<BitFieldLen;i++)
		if (GetBit(BitField, BitFieldLen, i)) count++;
		
	return count;
}

/***************************************************
* return the number of bits that are true
* TODO: finish this
***************************************************/
int	CountBitsNot(unsigned char* BitField, int BitFieldLen){
	int i;
	int	count;
	
	DEBUGPATH;
	
	count = 0;
	for (i=0;i<(BitFieldLen/8);i++){
		switch (BitField[i]){
		case 0:
			count+=0;
			break;
		case 1:
		case 2:
		case 4:
		case 8:
		case 16:
		case 32:
		case 64:
		case 128:
			count+=1;
			break;
		case 3:
		case 5:
		case 6:
		case 9:
		case 10:
		case 12:
		case 17:
		case 18:
		case 20:
		case 24:
		case 33:
		case 34:
		case 36:
		case 40:
		case 65:
		case 129:
			count+=2;
			break;
		case 7:	
		case 11:
		case 13:
		case 14:
		case 19:
		case 21:
		case 22:	
		case 25:
		case 26:
		case 28:
		case 35:
		case 37:
		case 38:	
		case 41:
		case 42:
		case 44:
			count+=3;
			break;	
		case 15:
		case 23:
		case 27:
		case 29:
		case 30:
		case 39:
		case 43:
			count+=4;
			break;
		case 31:
			count+=5;	
		}
	}

	return count;
}


/************************************************************
* Returns true if a bitfield is empty
*************************************************************/
int BitFieldIsEmpty(unsigned char* BitField, int BitFieldLen){
	int*	Field;
	int		i,j;
	
	DEBUGPATH;

	Field=(int*)BitField;

	for (i=0;i<BitFieldLen/32;i++){
		if (Field[i]!=0) return FALSE;
	}
	
	for (j=i*32;j<BitFieldLen;j++){
		if (GetBit(BitField, BitFieldLen, j)) return FALSE;
	}
	
	return TRUE;
}
