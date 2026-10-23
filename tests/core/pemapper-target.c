/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <windows.h>

static int gum_test_pe_magic = 0;

BOOL WINAPI
DllMain (HINSTANCE instance,
         DWORD reason,
         LPVOID reserved)
{
  if (reason == DLL_PROCESS_ATTACH)
    gum_test_pe_magic = 0x1337;
  else if (reason == DLL_PROCESS_DETACH)
    gum_test_pe_magic = 0;

  return TRUE;
}

__declspec (dllexport) int
gum_test_pe_sum (int a,
                 int b)
{
  return a + b;
}

__declspec (dllexport) int
gum_test_pe_get_magic (void)
{
  return gum_test_pe_magic;
}

__declspec (dllexport) unsigned int
gum_test_pe_get_pid (void)
{
  return GetCurrentProcessId ();
}
