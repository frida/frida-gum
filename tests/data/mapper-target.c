/*
 * Copyright (C) 2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifdef _WIN32
# include <windows.h>
# define GUM_TEST_EXPORT __declspec (dllexport)
# define GUM_TEST_THREAD __declspec (thread)
#else
# include <unistd.h>
# define GUM_TEST_EXPORT
# define GUM_TEST_THREAD __thread
#endif

static int gum_test_mapper_magic = 0;
static GUM_TEST_THREAD int gum_test_mapper_tls_value = 0x1234;

#ifdef _WIN32

BOOL WINAPI
DllMain (HINSTANCE instance,
         DWORD reason,
         LPVOID reserved)
{
  if (reason == DLL_PROCESS_ATTACH)
    gum_test_mapper_magic = 0x1337;
  else if (reason == DLL_PROCESS_DETACH)
    gum_test_mapper_magic = 0;

  return TRUE;
}

#else

# ifndef __APPLE__
__attribute__ ((section (".init_array"), used)) static void *
    gum_test_mapper_null_initializer = NULL;
# endif

__attribute__ ((constructor)) static void
gum_test_mapper_on_load (void)
{
  gum_test_mapper_magic = 0x1337;
}

__attribute__ ((destructor)) static void
gum_test_mapper_on_unload (void)
{
  gum_test_mapper_magic = 0;
}

#endif

GUM_TEST_EXPORT int
gum_test_mapper_sum (int a,
                     int b)
{
  return a + b;
}

GUM_TEST_EXPORT int
gum_test_mapper_get_magic (void)
{
  return gum_test_mapper_magic;
}

GUM_TEST_EXPORT unsigned int
gum_test_mapper_get_pid (void)
{
#ifdef _WIN32
  return GetCurrentProcessId ();
#else
  return getpid ();
#endif
}

GUM_TEST_EXPORT int
gum_test_mapper_tls_get (void)
{
  return gum_test_mapper_tls_value;
}

GUM_TEST_EXPORT void
gum_test_mapper_tls_set (int value)
{
  gum_test_mapper_tls_value = value;
}
