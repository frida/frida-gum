/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#ifdef HAVE_WINDOWS
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
#else
# include <pthread.h>
#endif

#define TESTCASE(NAME) \
    void test_tls_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("Core/Tls", test_tls, NAME)

TESTLIST_BEGIN (tls)
  TESTENTRY (get_should_work_like_the_system_implementation)
  TESTENTRY (set_should_work_like_the_system_implementation)
TESTLIST_END ()

TESTCASE (get_should_work_like_the_system_implementation)
{
  GumTlsKey key;

  key = gum_tls_key_new ();

#ifdef HAVE_WINDOWS
  TlsSetValue (key, GSIZE_TO_POINTER (0x11223344));
#else
  pthread_setspecific (key, GSIZE_TO_POINTER (0x11223344));
#endif
  g_assert_cmphex (GPOINTER_TO_SIZE (gum_tls_key_get_value (key)),
      ==, 0x11223344);

  gum_tls_key_free (key);
}

TESTCASE (set_should_work_like_the_system_implementation)
{
  GumTlsKey key;

  key = gum_tls_key_new ();

  gum_tls_key_set_value (key, GSIZE_TO_POINTER (0x11223344));
#ifdef HAVE_WINDOWS
  g_assert_cmphex (GPOINTER_TO_SIZE (TlsGetValue (key)), ==, 0x11223344);
#else
  g_assert_cmphex (GPOINTER_TO_SIZE (pthread_getspecific (key)),
      ==, 0x11223344);
#endif

  gum_tls_key_free (key);
}
