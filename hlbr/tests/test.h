#ifndef _HLBR_TEST_H_
#define _HLBR_TEST_H_

#include "../config.h"
#include "../engine/hlbr.h"

#define TEST_NONE	-1

int InitTests();
int CreateTest(char* Name);
int	GetTestByName(char* Name);
int BindTestToDecoder(int TestID, char* Decoder);
int TestAddNode(int TestID, int RuleNum, void* Data);
int TestsFinishSetup();

#endif
