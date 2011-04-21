//---------------------------------------------------------------------------
// OllyHeapTrace - A Heap Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2008 Stephen Fewer of Harmony Security
//---------------------------------------------------------------------------
#include <stdio.h>
//#include <stdlib.h>

#include "hooks.h"

extern DWORD dwProcessHeap;

struct HEAPFLAGS
{
	DWORD dwValue;
	const char * cpName;
};
//---------------------------------------------------------------------------
struct HEAPFLAGS flags[] = {

	{ HEAP_GENERATE_EXCEPTIONS, "HEAP_GENERATE_EXCEPTIONS" },
	{ HEAP_NO_SERIALIZE, "HEAP_NO_SERIALIZE" },
	{ HEAP_ZERO_MEMORY, "HEAP_ZERO_MEMORY" },

	{ NULL, NULL }
};
//---------------------------------------------------------------------------
VOID ResolveHeapFlags( DWORD dwFlags, char * cpOutput )
{
	int iCount = 0, i = 0;
	memset( cpOutput, 0, MAX_PATH );

	while( flags[i].cpName != NULL )
	{
		if( dwFlags & flags[i].dwValue == flags[i].dwValue )
		{
			if( iCount > 0 )
				strcat( cpOutput, " | " );
			strcat( cpOutput, flags[i].cpName );
			iCount++;
		}
		i++;
	}

	if( iCount == 0 )
		strcat( cpOutput, "0" );
}
//---------------------------------------------------------------------------
BOOL DefaultDWORD_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
	snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "0x%.8X", pRegisters->r[REG_EAX] );
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL DefaultINT_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
	snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "%d", pRegisters->r[REG_EAX] );
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL DefaultBOOL_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
	snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "%s", (pRegisters->r[REG_EAX] ? "TRUE" : "FALSE" ) );
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL RtlInitializeCriticalSection_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	DWORD dwParameter;
	Readmemory( &dwParameter, pRegisters->r[REG_ESP]+4, 4, MM_SILENT );
	snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlInitializeCriticalSection( 0x%.8X )", dwParameter );
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL RtlDeleteCriticalSection_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	DWORD dwParameter;
	Readmemory( &dwParameter, pRegisters->r[REG_ESP]+4, 4, MM_SILENT );
	snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlDeleteCriticalSection( 0x%.8X )", dwParameter );
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL RtlAllocateHeap_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	char cFlagsOutput[MAX_PATH];
	DWORD dwParameters[3];
	Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, 12, MM_SILENT );
	ResolveHeapFlags(  dwParameters[1], (char *)&cFlagsOutput );
	if( dwProcessHeap != NULL && dwParameters[0] == dwProcessHeap )
		snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlAllocateHeap( GetProcessHeap(), %s, %d )", cFlagsOutput, dwParameters[2] );
	else
		snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlAllocateHeap( 0x%.8X, %s, %d )", dwParameters[0], cFlagsOutput, dwParameters[2] );
	pLogData->dwHeap = dwParameters[0];
	pLogData->dwHeapBlockSize = dwParameters[2];
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL RtlAllocateHeap_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
	pLogData->dwHeapBlock = pRegisters->r[REG_EAX];
	snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "0x%.8X", pLogData->dwHeapBlock );
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL RtlReAllocateHeap_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	char cFlagsOutput[MAX_PATH];
	DWORD dwParameters[4];
	Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, 16, MM_SILENT );
	ResolveHeapFlags(  dwParameters[1], (char *)&cFlagsOutput );
	if( dwProcessHeap != NULL && dwParameters[0] == dwProcessHeap )
		snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlReAllocateHeap( GetProcessHeap(), %s, 0x%.8X, %d )", cFlagsOutput, dwParameters[2], dwParameters[3] );
	else
		snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlReAllocateHeap( 0x%.8X, %s, 0x%.8X, %d )", dwParameters[0], cFlagsOutput, dwParameters[2], dwParameters[3] );
	pLogData->dwHeap = dwParameters[0];
	pLogData->dwHeapBlockSize = dwParameters[3];
	pLogData->dwHeapBlock = dwParameters[2];
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL RtlFreeHeap_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	char cFlagsOutput[MAX_PATH];
	DWORD dwParameters[3];
	Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, 12, MM_SILENT );
	ResolveHeapFlags(  dwParameters[1], (char *)&cFlagsOutput );
	if( dwProcessHeap != NULL && dwParameters[0] == dwProcessHeap )
		snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlFreeHeap( GetProcessHeap(), %s, 0x%.8X )", cFlagsOutput, dwParameters[2] );
	else
		snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlFreeHeap( 0x%.8X, %s, 0x%.8X )", dwParameters[0], cFlagsOutput, dwParameters[2] );
	pLogData->dwHeap = dwParameters[0];
	pLogData->dwHeapBlock = dwParameters[2];
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL RtlCreateHeap_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	char cFlagsOutput[MAX_PATH];
	DWORD dwParameters[3];
	Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, 12, MM_SILENT );
	ResolveHeapFlags(  dwParameters[0], (char *)&cFlagsOutput );
	snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlCreateHeap( %s, %d, %d )", cFlagsOutput, dwParameters[1], dwParameters[2] );
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL RtlCreateHeap_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
	snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "0x%.8X", pRegisters->r[REG_EAX] );
	pLogData->dwHeap = pRegisters->r[REG_EAX];
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL GetProcessHeap_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	snprintf( pLogData->cMessage, BUFFER_SIZE, "GetProcessHeap()" );
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL GetProcessHeap_Return( LPLOGDATA pLogData, t_reg * pRegisters )
{
	dwProcessHeap = pRegisters->r[REG_EAX];
	snprintf( pLogData->cReturnMessage, BUFFER_SIZE, "0x%.8X", dwProcessHeap );
	pLogData->dwHeap = dwProcessHeap;
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL RtlDestroyHeap_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	DWORD dwParameter;
	Readmemory( &dwParameter, pRegisters->r[REG_ESP]+4, 4, MM_SILENT );
	if( dwProcessHeap != NULL && dwParameter == dwProcessHeap )
		snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlDestroyHeap( GetProcessHeap() )" );
	else
		snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlDestroyHeap( 0x%.8X )", dwParameter );
	pLogData->dwHeap = dwParameter;
	return TRUE;
}
//---------------------------------------------------------------------------
BOOL RtlSizeHeap_Call( LPLOGDATA pLogData, t_reg * pRegisters )
{
	char cFlagsOutput[MAX_PATH];
	DWORD dwParameters[3];
	Readmemory( &dwParameters, pRegisters->r[REG_ESP]+4, 12, MM_SILENT );
	ResolveHeapFlags(  dwParameters[1], (char *)&cFlagsOutput );
	if( dwProcessHeap != NULL && dwParameters[0] == dwProcessHeap )
		snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlSizeHeap( GetProcessHeap(), %s, 0x%.8X )", cFlagsOutput, dwParameters[2] );
	else
		snprintf( pLogData->cMessage, BUFFER_SIZE, "RtlSizeHeap( 0x%.8X, %s, 0x%.8X )", dwParameters[0], cFlagsOutput, dwParameters[2] );
	pLogData->dwHeap = dwParameters[0];
	pLogData->dwHeapBlock = dwParameters[2];
	return TRUE;
}
//---------------------------------------------------------------------------

