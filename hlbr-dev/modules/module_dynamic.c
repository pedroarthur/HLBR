/*
 * File: module_dynamic.c
 * License: GNU General Public License (GPL)
 * Indent Options:
 *      indent -kr -nbad -i4 -br -ce -nbc -npcs -cli4 -sc module_dynamic.c
 *
 * This static module takes care of the loading and unloading of dynamic modules.
 * The dynamic module should have a Module_MODULENAME_Init() function.
 * A shutdown handler is registered for each module we load.
 * A pointer to 'Globals' is passed to the modules init() function on the stack.
 */

/*
 *
 *  Hogwash (The Inline Packet Scrubber)
 *  Copyright (C) 2001-2003  Jason Larsen
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */


#include "../config.h"

#ifndef HAS_DLOPEN
int InitModuleDynamic()
{
    //DBG((printf("Dynamic module loading disabled\n")));
    return TRUE;
}
#else

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <ctype.h>
#include "../engine/hogwash.h"
#include "module.h"
#include "../engine/hoglib.h"
#include "module_dynamic.h"

#define DEBUG

extern GlobalVars Globals;

typedef struct module_dynamic_rec_t {
    /* Attach things here */
    void *Handle;
    char *Name;
    int Major, Minor;
    int (*InitFunc) (GlobalVars * g);
} ModuleDynamicRec;

char ModulesPath[MAX_NAME_LEN] = "";

#define RTLD_FLAGS RTLD_NOW

/****************************************/
int ModuleDynamicShutdownFunc(void *Data)
{
    ModuleDynamicRec *module;

    DEBUGPATH;

    module = (ModuleDynamicRec *) Data;
    DBG((printf("Calling dlclose for %s\n", module->Name)));
    dlclose(module->Handle);

    FREE_IF(module->Name);
    FREE_IF(module);
    return TRUE;
}

/**************************************************/
/* This function is the guts of the module loader */
/**************************************************/
int Module_Dynamic_Init(char *name)
{
    ModuleDynamicRec *module;
    char Workbuf[255 + MAX_NAME_LEN];

    DEBUGPATH;

    if (!name[0])
	return FALSE;

    snprintf(Workbuf, sizeof(Workbuf), "%s/mod_%s.so",
	     ((ModulesPath[0]) ? ModulesPath : "modules"), name);

    module = (ModuleDynamicRec *) calloc(sizeof(ModuleDynamicRec), 1);
    module->Handle = NULL;
    module->InitFunc = NULL;
    /* FIXME: dynamic modules should know what parent version of hogwash is running */
    module->Major = MAJOR_VERSION;
    module->Minor = MINOR_VERSION;

    /* This gets freed in the ShutdownFunc function or on error */
    module->Name = MALLOC(MAX_NAME_LEN);
    strncpy(module->Name, name, MAX_NAME_LEN);

    module->Handle = dlopen(Workbuf, RTLD_FLAGS);
    if (module->Handle == NULL)
	goto dl_errr;

    snprintf(Workbuf, sizeof(Workbuf),
	     "%c%s_Init", toupper(name[0]), name + 1);

    module->InitFunc = dlsym(module->Handle, Workbuf);
    if (module->InitFunc == NULL) {
	/* some OS's need the _ */
	snprintf(Workbuf, sizeof(Workbuf), "_%c%s_Init",
		 toupper(name[0]), name + 1);
	module->InitFunc = dlsym(module->Handle, Workbuf);
	if (module->InitFunc == NULL)
	    goto dl_errr;
    }

    module->InitFunc(&Globals);

    /* The shared object needs to be unloaded after  */
    /* the loaded modules shutdown handler is called */
    DBG((printf
	 ("%s found at %p\nAdding Shutdown handler\n",
	  Workbuf, module->func)));

    AddShutdownHandler(ModuleDynamicShutdownFunc, module);
    return TRUE;

  dl_errr:
    printf("DLERR: %s\n", (char *) dlerror());
    FREE(module->Name);
    FREE_IF(module);
    return FALSE;
}

/***********************************
 * The modulepath is a static var 
 * that gets overwritten with each call.
 ***********************************/
int Module_Dynamic_ParseArg(char *Arg)
{
    char *ptr;

    DEBUGPATH;

    ptr = NULL;

    if ((ptr = ParseCmp("modulepath", Arg)) != NULL) {
	strncpy(ModulesPath, ptr, sizeof(ModulesPath));
	printf("Setting modulepath to %s\n", ModulesPath);
	FREE(ptr);
    }
    if ((ptr = ParseCmp("loadmodule", Arg)) != NULL) {
	printf("Loading dynamic module %s\n", ptr);
	Module_Dynamic_Init(ptr);
	FREE(ptr);
    }
    return TRUE;
}


/*****************************************/
/* Init this module. Called by module.c */
/***************************************/
int InitModuleDynamic()
{
    int ModuleID;

    DEBUGPATH;

    ModuleID = CreateModule("dynamic");
    if (ModuleID == MODULE_NONE)
	return FALSE;

    ModulesPath[0] = 0;
    Globals.Modules[ModuleID].ParseArg = Module_Dynamic_ParseArg;

    return TRUE;
}

#endif
