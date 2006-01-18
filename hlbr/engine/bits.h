#ifndef _HLBR_BITS_H_
#define _HLBR_BITS_H_

#ifndef TRUE
#define TRUE	1
#define FALSE	0
#define NULL	0
#endif


int GetBit(unsigned char* BitField, int BitFieldLen, int BitNum);
void SetBit(unsigned char* BitField, int BitFieldLen, int BitNum, char Value);
void SetBits(unsigned char* BitField, int BitFieldLen, int StartBit, int EndBit, char Value);
void NotAndBitFields(unsigned char* BitField1, unsigned char* BitField2, unsigned char* TargetBitField, int BitFieldLen);
void AndBitFields(unsigned char* BitField1, unsigned char* BitField2, unsigned char* TargetBitField, int BitFieldLen);
void OrBitFields(unsigned char* BitField1, unsigned char* BitField2, unsigned char* TargetBitField, int BitFieldLen);
int	CountBits(unsigned char* BitField, int BitFieldLen);
int BitFieldIsEmpty(unsigned char* BitField, int BitFieldLen);


#endif
