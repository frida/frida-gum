/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <windows.h>

static __declspec (thread) int gum_test_pe_tls_value = 0x1234;

BOOL WINAPI
DllMain (HINSTANCE instance,
         DWORD reason,
         LPVOID reserved)
{
  return TRUE;
}

__declspec (dllexport) int
gum_test_pe_tls_get (void)
{
  return gum_test_pe_tls_value;
}

__declspec (dllexport) void
gum_test_pe_tls_set (int value)
{
  gum_test_pe_tls_value = value;
}
