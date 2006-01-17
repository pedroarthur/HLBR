#include "module.h"
#include <stdio.h>
#include <string.h>
#include "../decoders/decode.h"

/**************put includes for plugins here*************/
#include "module_web_unique.h"
#include "module_dns_unique.h"
#include "module_dynamic.h"
#include "module_ats2.h"
#include "module_covert.h"

extern GlobalVars Globals;

//#define DEBUG

/*********************************
* Set up all the modules
*********************************/
int InitModules(){
#ifdef DEBUGPATH
	printf("In InitModules\n");
#endif

	if (!InitModuleDynamic()) return FALSE;
	if (!InitModuleWebUnique()) return FALSE;
	if (!InitModuleDNSUnique()) return FALSE;
	if (!InitModuleATS2()) return FALSE;
	if (!InitModuleCovert()) return FALSE;

	return TRUE;
}

/*************************************
* Given a name, return the module ID
*************************************/
int	GetModuleByName(char* Name){
	int	i;

#ifdef DEBUGPATH
	printf("In GetModuleByName\n");
#endif

	for (i=0;i<Globals.NumModules;i++)
		if (strcasecmp(Name, Globals.Modules[i].Name)==0) return i;

	return MODULE_NONE;
}

/**************************************
* Allocate a module
**************************************/
int CreateModule(char* Name){
	int		ModuleID;
	
#ifdef DEBUGPATH
	printf("In CreateModule\n");
#endif	

	ModuleID=GetModuleByName(Name);
	if (ModuleID!=MODULE_NONE){	
		printf("There is already a module named %s\n",Name);
		return MODULE_NONE;
	}
	
	ModuleID=Globals.NumModules;
	Globals.NumModules++;
	
	snprintf(Globals.Modules[ModuleID].Name, MAX_NAME_LEN, "%s", Name);
	Globals.Modules[ModuleID].ID=ModuleID;
	
#ifdef DEBUG
	printf("Allocating module \"%s\" in number %i\n",Globals.Modules[ModuleID].Name, ModuleID);	
#endif	

	return ModuleID;
}


/**************************************************
* Bind a module to a decoder
**************************************************/
int BindModuleToDecoder(int ModuleID, char* Decoder){
	int DecoderID;
	
#ifdef DEBUGPATH
	printf("In BindModuleToDecoder\n");
#endif

	DecoderID=GetDecoderByName(Decoder);
	Globals.Modules[ModuleID].DecoderID=DecoderID;
	if (DecoderID==DECODER_NONE) return FALSE;

	return DecoderAddModule(DecoderID, ModuleID);
}

/*****************************************************
* Set a setting on the module
*****************************************************/
int ModuleParseArg(int ModuleID, char* Arg){
	ModuleRec*		m;
	
#ifdef DEBUGPATH
	printf("In ModuleParseArg\n");
#endif

	if (ModuleID>=Globals.NumModules) return FALSE;
	
	m=&Globals.Modules[ModuleID];
	
	if (m->ParseArg)
	if (m->ParseArg(Arg)){
		m->Active=TRUE;
		return TRUE;
	}
	
	return FALSE;
}
