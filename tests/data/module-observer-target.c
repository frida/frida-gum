/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifdef _WIN32
__declspec (dllexport)
#endif
int
gum_module_observer_target_function (int n)
{
  volatile int a = n;
  volatile int b = n * 3;
  volatile int c = n * 5;
  volatile int d = n * 7;

  return a + b + c + d;
}
