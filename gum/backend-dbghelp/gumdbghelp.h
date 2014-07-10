/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DBGHELP_H__
#define __GUM_DBGHELP_H__

#include "gumdefs.h"

#define _WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>

typedef struct _GumDbgHelpImpl        GumDbgHelpImpl;
typedef struct _GumDbgHelpImplPrivate GumDbgHelpImplPrivate;

struct _GumDbgHelpImpl
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
  PVOID (WINAPI * SymFunctionTableAccess64) (HANDLE hProcess,
      DWORD64 AddrBase);
  BOOL (WINAPI * SymGetLineFromAddr64) (HANDLE hProcess, DWORD64 qwAddr,
      PDWORD pdwDisplacement, PIMAGEHLP_LINE64 Line64);
  DWORD64 (WINAPI * SymGetModuleBase64) (HANDLE hProcess, DWORD64 qwAddr);
  BOOL (WINAPI * SymGetTypeInfo) (HANDLE hProcess, DWORD64 ModBase,
      ULONG TypeId, IMAGEHLP_SYMBOL_TYPE_INFO GetType, PVOID pInfo);

  void (* Lock) (void);
  void (* Unlock) (void);

  /*< private */
  GumDbgHelpImplPrivate * priv;
};

G_BEGIN_DECLS

GumDbgHelpImpl * gum_dbghelp_impl_obtain (void);
void gum_dbghelp_impl_release (GumDbgHelpImpl * impl);

G_END_DECLS

#endif
