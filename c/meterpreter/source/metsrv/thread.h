#ifndef _METERPRETER_METSRV_THREAD_H
#define _METERPRETER_METSRV_THREAD_H

#include "common_thread.h"

/*****************************************************************************************/
// Win32/64 specific definitions...

typedef struct __OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	_PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;
	PVOID SecurityQualityOfService;
} _OBJECT_ATTRIBUTES, * _POBJECT_ATTRIBUTES;

typedef struct __CLIENT_ID
{
  PVOID UniqueProcess;
  PVOID UniqueThread;
} _CLIENT_ID, * _PCLIENT_ID;

typedef HANDLE (WINAPI * OPENTHREAD)( DWORD, BOOL, DWORD ); // kernel32!OpenThread

typedef DWORD (WINAPI * NTOPENTHREAD)( PHANDLE, ACCESS_MASK, _POBJECT_ATTRIBUTES, _PCLIENT_ID ); // ntdll!NtOpenThread

/*****************************************************************************************/

LOCK * lock_create( VOID );

VOID lock_destroy( LOCK * lock );

VOID lock_acquire( LOCK * lock );

VOID lock_release( LOCK * lock );

/*****************************************************************************************/

EVENT * event_create( VOID );

BOOL event_destroy( EVENT * event );

BOOL event_signal( EVENT * event );

BOOL event_poll( EVENT * event, DWORD timeout );

/*****************************************************************************************/

THREAD * thread_open( VOID );

THREAD * thread_create( THREADFUNK funk, LPVOID param1, LPVOID param2, LPVOID param3 );

void disable_thread_error_reporting(void);

BOOL thread_run( THREAD * thread );

BOOL thread_sigterm( THREAD * thread );

BOOL thread_kill( THREAD * thread );

BOOL thread_join( THREAD * thread );

BOOL thread_destroy( THREAD * thread );

/*****************************************************************************************/

#endif
