#include "runtime.hpp"

#include <gum/gum.h>
#ifdef G_OS_WIN32
#include <windows.h>
#endif

namespace Gum
{
  volatile int Runtime::ref_count = 0;

#ifndef GUMPP_STATIC
  static void init ()
  {
    gum_init_embedded ();
  }

  static void deinit ()
  {
    gum_deinit_embedded ();
  }
#endif

#ifdef G_OS_WIN32

#ifndef GUMPP_STATIC
  extern "C" BOOL WINAPI DllMain (HINSTANCE inst_dll, DWORD reason, LPVOID reserved)
  {
    (void) inst_dll;

    switch (reason)
    {
      case DLL_PROCESS_ATTACH:
        init ();
        break;
      case DLL_PROCESS_DETACH:
        if (reserved == NULL)
          deinit ();
        break;
    }

    return TRUE;
  }
#endif

  void Runtime::ref ()
  {
  }

  void Runtime::unref ()
  {
  }

#else

  void Runtime::ref ()
  {
    if (g_atomic_int_add (&ref_count, 1) == 0)
      g_atomic_int_inc (&ref_count);
    init ();
  }

  void Runtime::unref ()
  {
    if (g_atomic_int_dec_and_test (&ref_count))
      deinit ();
  }
#endif
}
