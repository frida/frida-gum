/*
 * Copyright (C) 2008-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DBGHELP_H__
#define __GUM_DBGHELP_H__

#include "gumdefs.h"

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4091)
#endif

#define _WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>

#ifdef _MSC_VER
# pragma warning (pop)
#endif

typedef struct _GumDbghelpImpl        GumDbghelpImpl;
typedef struct _GumDbghelpImplPrivate GumDbghelpImplPrivate;

struct _GumDbghelpImpl
{
  BOOL (WINAPI * StackWalk64) (DWORD MachineType, HANDLE hProcess,
      HANDLE hThread, LPSTACKFRAME64 StackFrame, PVOID ContextRecord,
      PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
      PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
      PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
      PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress);
  BOOL (WINAPI * SymInitialize) (HANDLE hProcess, PCSTR UserSearchPath,
      BOOL fInvadeProcess);
  BOOL (WINAPI * SymCleanup) (HANDLE hProcess);
  BOOL (WINAPI * SymEnumSymbols) (HANDLE hProcess, ULONG64 BaseOfDll,
      PCSTR Mask, PSYM_ENUMERATESYMBOLS_CALLBACK EnumSymbolsCallback,
      PVOID UserContext);
  BOOL (WINAPI * SymFromAddr) (HANDLE hProcess, DWORD64 Address,
      PDWORD64 Displacement, PSYMBOL_INFO Symbol);
  DWORD (WINAPI * SymSetOptions) (DWORD SymOptions);
  PVOID (WINAPI * SymFunctionTableAccess64) (HANDLE hProcess,
      DWORD64 AddrBase);
  BOOL (WINAPI * SymGetLineFromAddr64) (HANDLE hProcess, DWORD64 qwAddr,
      PDWORD pdwDisplacement, PIMAGEHLP_LINE64 Line64);
  DWORD64 (WINAPI * SymGetModuleBase64) (HANDLE hProcess, DWORD64 qwAddr);
  BOOL (WINAPI * SymGetTypeInfo) (HANDLE hProcess, DWORD64 ModBase,
      ULONG TypeId, IMAGEHLP_SYMBOL_TYPE_INFO GetType, PVOID pInfo);
  DWORD64(WINAPI * SymLoadModuleEx) (HANDLE hProcess, HANDLE hFile, 
      PCSTR ImageName, PCSTR ModuleName, DWORD64 BaseOfDll, DWORD DllSize, 
      PMODLOAD_DATA Data, DWORD Flags);
  BOOL (WINAPI * SymGetModuleInfo) (HANDLE hProcess, DWORD dwAddr,
      PIMAGEHLP_MODULE ModuleInfo);

  void (* Lock) (void);
  void (* Unlock) (void);

  /*< private */
  GumDbghelpImplPrivate * priv;
};

G_BEGIN_DECLS

G_GNUC_INTERNAL GumDbghelpImpl * gum_dbghelp_impl_try_obtain (void);

G_END_DECLS

#endif
