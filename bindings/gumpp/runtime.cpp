#include "runtime.hpp"

#include <gum/gum.h>

namespace Gum
{
  volatile int Runtime::ref_count = 0;

  void Runtime::ref ()
  {
    g_atomic_int_inc (&ref_count);
    glib_init ();
    gum_init ();
  }

  void Runtime::unref ()
  {
    if (g_atomic_int_dec_and_test (&ref_count))
    {
      gum_deinit ();
      glib_deinit ();
    }
  }

  class Library
  {
  public:
    Library ()
    {
      Runtime::ref ();
    }

    ~Library ()
    {
      Runtime::unref ();
    }
  };
  static Library library;
}
