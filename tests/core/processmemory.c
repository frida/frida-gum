/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gumnativeprocessmemory.h"

#include "testutil.h"

#include <string.h>

#define TESTCASE(NAME) \
    void test_process_memory_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/ProcessMemory", test_process_memory, NAME)

TESTLIST_BEGIN (process_memory)
  TESTENTRY (local_reports_identity)
  TESTENTRY (local_memory_can_be_written_and_read_back)
TESTLIST_END ()

TESTCASE (local_reports_identity)
{
  GumNativeProcessMemory * mem = gum_native_process_memory_new_local ();

  g_assert_cmpuint (gum_native_process_memory_get_pid (mem), ==,
      gum_process_get_id ());

  g_object_unref (mem);
}

TESTCASE (local_memory_can_be_written_and_read_back)
{
  guint i;
  guint8 pattern[256];
  GumProcessMemory * mem =
      GUM_PROCESS_MEMORY (gum_native_process_memory_new_local ());
  guint8 storage[256] = { 0, };
  guint8 readback[256];

  for (i = 0; i != sizeof (pattern); i++)
    pattern[i] = (guint8) i;

  g_assert_true (gum_process_memory_write (mem, GUM_ADDRESS (storage), pattern,
      sizeof (pattern)));
  g_assert_cmpint (memcmp (storage, pattern, sizeof (pattern)), ==, 0);

  memset (readback, 0, sizeof (readback));
  g_assert_true (gum_process_memory_read (mem, GUM_ADDRESS (storage), readback,
      sizeof (readback)));
  g_assert_cmpint (memcmp (readback, pattern, sizeof (pattern)), ==, 0);

  g_object_unref (mem);
}
