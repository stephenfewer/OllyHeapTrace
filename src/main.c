//---------------------------------------------------------------------------
// OllyHeapTrace - A Heap Tracer plugin for OllyDbg
//         By Stephen Fewer of Harmony Security (www.harmonysecurity.com)
// Copyright (c) 2008 Stephen Fewer of Harmony Security
//---------------------------------------------------------------------------
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#include "hooks.h"
#pragma nopackwarning
//---------------------------------------------------------------------------
#pragma link ".\\bin\\OllyDbg.lib"
//---------------------------------------------------------------------------
#define OLLYHT_NAME          "OllyHeapTrace"
#define OLLYHT_VERSION       "1.1"
#define OLLYHT_ABOUT		 "By Stephen Fewer of Harmony Security (www.harmonysecurity.com)"

struct COLORS
{
	BYTE bColor;
	DWORD dwHeap;
};

struct COLORS colors[NCOLORS-1] = {0};
//---------------------------------------------------------------------------
struct HOOK hooks[] = {
	{ "ntdll", "RtlAllocateHeap",              NULL, RtlAllocateHeap_Call,              RtlAllocateHeap_Return },
	{ "ntdll", "RtlFreeHeap",                  NULL, RtlFreeHeap_Call,                  DefaultBOOL_Return },
	{ "ntdll", "RtlCreateHeap",                NULL, RtlCreateHeap_Call,                RtlCreateHeap_Return },
	{ "ntdll", "RtlDestroyHeap",               NULL, RtlDestroyHeap_Call,               DefaultBOOL_Return },
	{ "ntdll", "RtlReAllocateHeap",            NULL, RtlReAllocateHeap_Call,            RtlAllocateHeap_Return },
	{ "ntdll", "RtlSizeHeap",                  NULL, RtlSizeHeap_Call,                  DefaultINT_Return },
	{ "ntdll", "RtlInitializeCriticalSection", NULL, RtlInitializeCriticalSection_Call, NULL },
	{ "ntdll", "RtlDeleteCriticalSection",     NULL, RtlDeleteCriticalSection_Call,     NULL },

	{ "kernel32", "GetProcessHeap",            NULL, GetProcessHeap_Call,                GetProcessHeap_Return },

	{ NULL, NULL, NULL, NULL, NULL }
};
//---------------------------------------------------------------------------
HINSTANCE hDll               = NULL;
HANDLE hOllyWindow           = NULL;
volatile BOOL bEnabled       = FALSE;
char cLogWindowClass[32]     = { 0 };
t_table logtable             = { 0 };

volatile DWORD dwLogIndex = 0;
//DWORD dwIgnoreHeaps[MAX_PATH] = {0};
DWORD dwProcessHeap          = NULL;
//---------------------------------------------------------------------------
int WINAPI DllEntryPoint( HINSTANCE hInstance, DWORD dwReason, LPVOID lpReserved )
{
  if( dwReason == DLL_PROCESS_ATTACH )
	hDll = hInstance;
  return 1;
}
//---------------------------------------------------------------------------
int _export cdecl ODBG_Plugindata( char cShortname[32] )
{
  strcpy( cShortname, OLLYHT_NAME );
  return PLUGIN_VERSION;
}
//---------------------------------------------------------------------------
BYTE GetColor( DWORD dwHeap )
{
	int i;
	for( i=0 ; i<NCOLORS-1 ; i++ )
	{
		if( colors[i].dwHeap == dwHeap )
			return colors[i].bColor;
	}
	for( i=0 ; i<NCOLORS-1 ; i++ )
	{
		if( colors[i].dwHeap == NULL )
		{
			colors[i].dwHeap = dwHeap;
            return colors[i].bColor;
		}
	}
	return GRAY;
}
//---------------------------------------------------------------------------
int LogWindowGetText( char * cpBuffer, char * pMask, int * pSelect, t_sortheader * pHeader, int iColumn )
{
	int i = 0;
	LPLOGDATA pLogData = (LPLOGDATA)pHeader;
	BYTE bColor = GetColor( pLogData->dwHeap );

	if( iColumn == 0 )
	{
		*pSelect = DRAW_GRAY;
		i = Decodeaddress( pLogData->dwCallerAddress, 0, ADC_VALID, cpBuffer, BUFFER_SIZE, NULL );
		if( i == 0 )
			i = snprintf( cpBuffer, BUFFER_SIZE, "0x%.8X", pLogData->dwCallerAddress );
	}
	else if( iColumn == 1 )
	{
		*pSelect = DRAW_GRAY;
		i = snprintf( cpBuffer, BUFFER_SIZE, "0x%.8X", pLogData->dwThreadId );
	}
	else if( iColumn == 2 )
	{
		i = snprintf( cpBuffer, BUFFER_SIZE, "%s", pLogData->cMessage );
		*pSelect = DRAW_MASK;
		memset( pMask, DRAW_DIRECT|bColor, i );
	}
	else if( iColumn == 3 )
	{
		if( strlen( pLogData->cReturnMessage ) > 0 )
		{
			i = snprintf( cpBuffer, BUFFER_SIZE, "%s", pLogData->cReturnMessage );
			*pSelect = DRAW_MASK;
			memset( pMask, DRAW_DIRECT|bColor, i );
		}
	}
	return i;
}
//---------------------------------------------------------------------------
void CreateLogWindow( void )
{
	if( logtable.bar.nbar == 0 )
	{
		logtable.bar.name[0]    = "Caller";
		logtable.bar.defdx[0]   = 20;
		logtable.bar.mode[0]    = BAR_NOSORT;

		logtable.bar.name[1]    = "Thread";
		logtable.bar.defdx[1]   = 12;
		logtable.bar.mode[1]    = BAR_NOSORT;

		logtable.bar.name[2]    = "Function Call";
		logtable.bar.defdx[2]   = 64;
		logtable.bar.mode[2]    = BAR_NOSORT;

		logtable.bar.name[3]    = "Return Value";
		logtable.bar.defdx[3]   = 16;
		logtable.bar.mode[3]    = BAR_NOSORT;

		logtable.bar.nbar       = 4;
		logtable.mode           = TABLE_COPYMENU|TABLE_APPMENU|TABLE_SAVEPOS|TABLE_ONTOP;
		logtable.drawfunc       = LogWindowGetText;
	}
	Quicktablewindow( &logtable, 15, logtable.bar.nbar, cLogWindowClass, "OllyHeapTrace - Log" );
}
//---------------------------------------------------------------------------
VOID HandleRightClick( HWND hw )
{
	LPLOGDATA pLogData;
	HMENU hMenu;
	int i;
	char cBuffer[BUFFER_SIZE];

	hMenu = CreatePopupMenu();
	pLogData = (LPLOGDATA)Getsortedbyselection( &(logtable.data), logtable.data.selected );
	if( hMenu != NULL && pLogData != NULL )
	{
		if( pLogData->dwHeap != NULL )
		{
			snprintf( cBuffer, BUFFER_SIZE, "Delete trace for heap 0x%.8X", pLogData->dwHeap );
			AppendMenu( hMenu, MF_STRING, 1, cBuffer );

			snprintf( cBuffer, BUFFER_SIZE, "View dump of heap 0x%.8X", pLogData->dwHeap );
			AppendMenu( hMenu, MF_STRING, 2, cBuffer );

			if( pLogData->dwHeapBlock != NULL )
			{
				snprintf( cBuffer, BUFFER_SIZE, "View dump of heap block 0x%.8X", pLogData->dwHeapBlock );
				AppendMenu( hMenu, MF_STRING, 3, cBuffer );
			}
		}

	}
	i = Tablefunction( &logtable, hw, WM_USER_MENU, 0, (LPARAM)hMenu );
	if( hMenu != NULL )
		DestroyMenu( hMenu );

	if( i == 1 )
	{
		DWORD dwHeap = pLogData->dwHeap;
		pLogData = (LPLOGDATA)logtable.data.data;
		for( i=0 ; i<logtable.data.n ; i++ )
		{
			if( pLogData[i].dwHeap == dwHeap )
			{
				Deletesorteddata( &(logtable.data), pLogData[i].dwAddress );
				i = -1;
				continue;
			}
		}
		InvalidateRect( hw, NULL, FALSE );
	}
	else if( i == 2 )
	{
		Createdumpwindow( "OllyHeapTrace - Dump Heap", pLogData->dwHeap, 4096, 0, 0x01101, NULL );
	}
	else if( i == 3 && pLogData->dwHeapBlock != NULL )
	{
		if( pLogData->dwHeapBlockSize == NULL )
			pLogData->dwHeapBlockSize = 4096;
		Createdumpwindow( "OllyHeapTrace - Dump Heap Block", pLogData->dwHeapBlock, pLogData->dwHeapBlockSize, 0, 0x01101, NULL );
		//Createdumpwindow( "OllyHeapTrace - Dump Heap Block", pLogData->dwHeapBlock - 8, pLogData->dwHeapBlockSize + 8, 0, 0x01101, NULL );
	}
}
//---------------------------------------------------------------------------
LRESULT CALLBACK LogWindowProc( HWND hw,UINT msg,WPARAM wp,LPARAM lp)
{
	LPLOGDATA pLogData;

	switch( msg )
	{
		case WM_DESTROY:
		case WM_MOUSEMOVE:
		case WM_LBUTTONDOWN:
		case WM_LBUTTONDBLCLK:
		case WM_LBUTTONUP:
		case WM_RBUTTONDOWN:
		case WM_RBUTTONDBLCLK:
		case WM_HSCROLL:
		case WM_VSCROLL:
		case WM_TIMER:
		case WM_SYSKEYDOWN:
		case WM_USER_SCR:
		case WM_USER_VABS:
		case WM_USER_VREL:
		case WM_USER_VBYTE:
		case WM_USER_STS:
		case WM_USER_CNTS:
		case WM_USER_CHGS:
		case WM_KEYDOWN:
			return Tablefunction( &logtable, hw, msg, wp, lp );
		case WM_USER_MENU:
			HandleRightClick( hw );
			return 0;
		case WM_USER_DBLCLK:
			pLogData = (LPLOGDATA)Getsortedbyselection( &(logtable.data), logtable.data.selected );
			if ( pLogData != NULL )
				Setcpu( 0, pLogData->dwCallerAddress, 0, 0, CPU_ASMHIST|CPU_ASMCENTER|CPU_ASMFOCUS );
			return 1;
		case WM_USER_CHALL:
		case WM_USER_CHMEM:
			InvalidateRect( hw, NULL, FALSE );
			return 0;
		case WM_PAINT:
			Painttable( hw, &logtable, LogWindowGetText );
			return 0;
		default: break;
	}
	return DefMDIChildProc( hw, msg, wp, lp );
}
//---------------------------------------------------------------------------
int _export cdecl ODBG_Plugininit( int iOllyVersion, HWND hWindow, DWORD * features )
{
	int i;
	if( iOllyVersion < PLUGIN_VERSION )
		return -1;

	hOllyWindow = hWindow;

	bEnabled = FALSE;

	if( Createsorteddata( &(logtable.data), NULL, sizeof(LOGDATA), 64, NULL, NULL ) != 0 )
		return -1;

	if( Registerpluginclass( cLogWindowClass, NULL, hDll, LogWindowProc ) < 0 )
	{
		Destroysorteddata( &(logtable.data) );
		return -1;
	}

	for( i=0 ; i<NCOLORS-1 ; i++ )
	{
		colors[i].bColor = i+1;
		colors[i].dwHeap = NULL;
	}
	colors[NCOLORS-2].bColor = BLACK;

	//for( i=0 ; i<MAX_PATH ; i++ )
	//	dwIgnoreHeaps[i] = NULL;

	Addtolist( 0, 0, "%s plugin v%s", OLLYHT_NAME, OLLYHT_VERSION );
	Addtolist( 0, -1, "  %s", OLLYHT_ABOUT );

	return 0;
}
//---------------------------------------------------------------------------
t_module * FindModule( t_table * modtable, const char * cpName )
{
	int i;
	t_module *  m = (t_module *)modtable->data.data;
	for( i=0 ; i<modtable->data.n ; i++ )
	{
		if( strnicmp( cpName, m[i].name, SHORTLEN ) == 0 )
			return &m[i];
	}
	return NULL;
}
//---------------------------------------------------------------------------
VOID CreateBreakpoint( t_module * m, const char * cpName, DWORD * pAddress )
{
	if( Findlabelbyname( (char *)cpName, pAddress, m->codebase, (m->codebase + m->codesize) ) != NM_NONAME )
	{
		if( Setbreakpoint( *pAddress, TY_ACTIVE, 0 ) == 0 )
			return;
	}
 /*
	*pAddress = Findimportbyname( cpName, 0, 0x80000000 );
	if( *pAddress != 0 )
	{
		if( Setbreakpoint( *pAddress, TY_ACTIVE, 0 ) == 0 )
			return;
	}
       */
	//*pAddress = NULL;

	Addtolist( 0, 1, "%s: Failed to create breakpoint for %s.", OLLYHT_NAME, cpName );
	//RaiseException( 1, 0, 0, NULL );
}
//---------------------------------------------------------------------------
void DisableBreakpoints( BOOL bDisable )
{
	int i = 0;

	while( hooks[i].cpModuleName != NULL )
	{
		if( hooks[i].dwFunctionAddress != NULL )
		{
			if( bDisable )
				Setbreakpoint( hooks[i].dwFunctionAddress, TY_DISABLED, 0 );
			hooks[i].dwFunctionAddress = NULL;
		}
		i++;
	}
}
//---------------------------------------------------------------------------
BOOL EnableBreakpoints( void )
{
	BOOL bSuccess;
	t_module * m;
	int i = 0;
	t_table * modtable = (t_table *)Plugingetvalue( VAL_MODULES );

	__try
	{
		while( hooks[i].cpModuleName != NULL )
		{
			// fix case insensitive search!!!
			m = FindModule( modtable, hooks[i].cpModuleName );
			if( m == NULL )
			{
				Addtolist( 0, 1, "%s: Failed to find module %s.", OLLYHT_NAME, hooks[i].cpModuleName );
				RaiseException( 2, 0, 0, NULL );
			}
			CreateBreakpoint( m, hooks[i].cpFunctionName, &hooks[i].dwFunctionAddress );
			i++;
		}
		bSuccess = TRUE;
	}
	__except( EXCEPTION_EXECUTE_HANDLER )
	{
		//PEXCEPTION_POINTERS x = GetExceptionInformation();
		//if( x->ExceptionCode == 1 )
		//{
			DisableBreakpoints( TRUE );
			bSuccess = FALSE;
			Addtolist( 0, 1, "%s failed to enable required breakpoints.", OLLYHT_NAME );
		//	Addtolist( 0, 1, "    Breakpoint for %s failed.", w->ExceptionInformation[0] );
		//}
	}
	return bSuccess;
}
//---------------------------------------------------------------------------
void _export cdecl ODBG_Plugindestroy( void )
{
	//int i;
	//LPLOGDATA pLogData;
	bEnabled = FALSE;

	Unregisterpluginclass( cLogWindowClass );

	/*pLogData = (LPLOGDATA)logtable.data.data;
	for( i=0 ; i<logtable.data.n ; i++ )
		free( &pLogData[i] );*/

	Destroysorteddata( &(logtable.data) );

	DisableBreakpoints( FALSE );

	//for( i=0 ; i<MAX_PATH ; i++ )
	//	dwIgnoreHeaps[i] = NULL;
}
//---------------------------------------------------------------------------
void _export cdecl ODBG_Pluginreset( void )
{
	//int i;
	//LPLOGDATA pLogData;
	bEnabled = FALSE;

	/*pLogData = (LPLOGDATA)logtable.data.data;
	for( i=0 ; i<logtable.data.n ; i++ )
		free( &pLogData[i] );*/
	
	Destroysorteddata( &(logtable.data) );
	Createsorteddata( &(logtable.data), NULL, sizeof(LOGDATA), 64, NULL, NULL );

	DisableBreakpoints( FALSE );

	//for( i=0 ; i<MAX_PATH ; i++ )
	//	dwIgnoreHeaps[i] = NULL;
}
//---------------------------------------------------------------------------
int _export cdecl ODBG_Pluginmenu( int iOrigin, char cData[4096], LPVOID lpItem )
{
	switch( iOrigin )
	{
		case PM_MAIN:
			strcpy( cData, "0 &Enable/Disable,1 &View Log,|2 &About" );
			return 1;
		default:
			break;
	}
	return 0;
}
//---------------------------------------------------------------------------
void _export cdecl ODBG_Pluginaction( int iOrigin, int iAction, LPVOID lpItem )
{
	char cBuffer[BUFFER_SIZE];

	if( iOrigin == PM_MAIN )
	{
		switch( iAction )
		{
			// Enable/Disable
			case 0:
				if( bEnabled )
					bEnabled = FALSE;
				else
					bEnabled = TRUE;

				if( bEnabled )
					bEnabled = EnableBreakpoints();
				else
					DisableBreakpoints( TRUE );
				
				Flash( "%s %s.", OLLYHT_NAME, ( bEnabled ? "Enabled" : "Disabled" ) );
				break;

			// View Log
			case 1:
				CreateLogWindow();
				break;

			// About
			case 2:
				snprintf( cBuffer, BUFFER_SIZE, "%s v%s\n%s", OLLYHT_NAME, OLLYHT_VERSION, OLLYHT_ABOUT );
				MessageBox( hOllyWindow, cBuffer, "About", MB_OK|MB_ICONINFORMATION );
				break;

			default:
				break;
		}
	}
}
//---------------------------------------------------------------------------
int  _export cdecl ODBG_Pausedex( int iReason, int iExtData, t_reg * pRegisters, DEBUG_EVENT * pDebugEvent )
{
	BOOL bFound = FALSE;
	int i = 0;
	LPLOGDATA pLogData;

	if( !bEnabled || pRegisters == NULL && ((iReason & PP_INT3BREAK) != PP_INT3BREAK) )
		return 0;

	while( hooks[i].cpModuleName != NULL )
	{
		if( pRegisters->ip == hooks[i].dwFunctionAddress )
		{
			pLogData = (LPLOGDATA)malloc( sizeof(LOGDATA) );
			memset( pLogData, 0, sizeof(LOGDATA) );
			pLogData->dwAddress = dwLogIndex++;
			pLogData->dwSize = 1;
			
			pLogData->iHookIndex = i;
			pLogData->dwThreadId = pDebugEvent->dwThreadId;

			Readmemory( &pLogData->dwCallerAddress, pRegisters->r[REG_ESP], 4, MM_SILENT );

			if( hooks[i].handle_call != NULL )
				hooks[i].handle_call( pLogData, pRegisters );

			if( hooks[i].handle_return != NULL )
				Setbreakpoint( pLogData->dwCallerAddress, TY_ONESHOT, 0 );//TY_ONESHOT//TY_ACTIVE

			Addsorteddata( &(logtable.data), pLogData );
			bFound = TRUE;
			break;
		}
		i++;
	}

	if( !bFound )
	{
		pLogData = (LPLOGDATA)logtable.data.data;
		for( i=0 ; i<logtable.data.n ; i++ )
		{
			if( pRegisters->ip == pLogData[i].dwCallerAddress && !pLogData[i].bReturnMessageSet )
			{
				if( hooks[pLogData[i].iHookIndex].handle_return != NULL )
					pLogData[i].bReturnMessageSet = hooks[pLogData[i].iHookIndex].handle_return( &pLogData[i], pRegisters );
				bFound = TRUE;
				break;
			}
		}
	}

	if( bFound )
	{
		Go( 0, 0, STEP_RUN, 1, 1 );
    	return 1;
	}

	return 0;
}
//---------------------------------------------------------------------------

