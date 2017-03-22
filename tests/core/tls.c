/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#ifdef G_OS_WIN32
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
#else
# include <pthread.h>
#endif

#define TLS_TESTCASE(NAME) \
    void test_tls_ ## NAME (void)
#define TLS_TESTENTRY(NAME) \
    TEST_ENTRY_SIMPLE ("Core/Tls", test_tls, NAME)

TEST_LIST_BEGIN (tls)
  TLS_TESTENTRY (get_should_work_like_the_system_implementation)
  TLS_TESTENTRY (set_should_work_like_the_system_implementation)
TEST_LIST_END ()

TLS_TESTCASE (get_should_work_like_the_system_implementation)
{
  GumTlsKey key;

  key = gum_tls_key_new ();

#ifdef G_OS_WIN32
  TlsSetValue (key, GSIZE_TO_POINTER (0x11223344));
#else
  pthread_setspecific (key, GSIZE_TO_POINTER (0x11223344));
#endif
  g_assert_cmphex (GPOINTER_TO_SIZE (gum_tls_key_get_value (key)),
      ==, 0x11223344);

  gum_tls_key_free (key);
}

TLS_TESTCASE (set_should_work_like_the_system_implementation)
{
  GumTlsKey key;

  key = gum_tls_key_new ();

  gum_tls_key_set_value (key, GSIZE_TO_POINTER (0x11223344));
#ifdef G_OS_WIN32
  g_assert_cmphex (GPOINTER_TO_SIZE (TlsGetValue (key)), ==, 0x11223344);
#else
  g_assert_cmphex (GPOINTER_TO_SIZE (pthread_getspecific (key)),
      ==, 0x11223344);
#endif

  gum_tls_key_free (key);
}
