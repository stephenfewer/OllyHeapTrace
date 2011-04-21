//---------------------------------------------------------------------------
// OllyHeapTrace - A Heap Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2008 Stephen Fewer of Harmony Security
//---------------------------------------------------------------------------
#ifndef HOOKS_H
#define HOOKS_h

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "Plugin.h"

#pragma nopackwarning

#define BUFFER_SIZE	         256

typedef struct _LOGDATA
{
	DWORD dwAddress;
	DWORD dwSize;
	DWORD dwType;

	DWORD dwCallerAddress;
	DWORD dwThreadId;
	DWORD dwHeap;
	DWORD dwHeapBlock;
	DWORD dwHeapBlockSize;
	char cMessage[BUFFER_SIZE];
	char cReturnMessage[BUFFER_SIZE];
	BOOL bReturnMessageSet;
	int iHookIndex;

} LOGDATA, * LPLOGDATA;

typedef BOOL (* HOOK_FUNC)( LPLOGDATA pLogData, t_reg * pRegisters );

struct HOOK
{
	const char * cpModuleName;
	const char * cpFunctionName;
	DWORD dwFunctionAddress;
	HOOK_FUNC handle_call;
	HOOK_FUNC handle_return;
};

BOOL DefaultDWORD_Return( LPLOGDATA, t_reg * );
BOOL DefaultBOOL_Return( LPLOGDATA, t_reg * );
BOOL DefaultINT_Return( LPLOGDATA, t_reg * );

BOOL RtlInitializeCriticalSection_Call( LPLOGDATA, t_reg * );
BOOL RtlDeleteCriticalSection_Call( LPLOGDATA, t_reg * );

BOOL RtlAllocateHeap_Call( LPLOGDATA , t_reg *  );
BOOL RtlAllocateHeap_Return( LPLOGDATA , t_reg *  );
BOOL RtlReAllocateHeap_Call( LPLOGDATA , t_reg *  );
BOOL RtlFreeHeap_Call( LPLOGDATA , t_reg *  );
BOOL RtlCreateHeap_Call( LPLOGDATA , t_reg *  );
BOOL RtlCreateHeap_Return( LPLOGDATA, t_reg * );
BOOL GetProcessHeap_Call( LPLOGDATA , t_reg *  );
BOOL GetProcessHeap_Return( LPLOGDATA, t_reg * );
BOOL RtlDestroyHeap_Call( LPLOGDATA, t_reg * );
BOOL RtlSizeHeap_Call( LPLOGDATA, t_reg * );

#endif
