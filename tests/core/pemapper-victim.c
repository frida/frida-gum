/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include <stdio.h>
#include <windows.h>

int
main (void)
{
  char name[64];

  snprintf (name, sizeof (name), "frida-pemapper-victim-%lu",
      GetCurrentProcessId ());
  SetEvent (CreateEventA (NULL, TRUE, FALSE, name));

  Sleep (INFINITE);
  return 0;
}
