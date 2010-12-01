#include "gumpp.hpp"

#include <gum/gum-heap.h>
#include <iostream>

namespace Gum
{
  static void output_to_stderr (const gchar * text, gpointer user_data)
  {
    (void) user_data;

    std::cerr << text;
  }

  class SanityCheckerImpl : public SanityChecker
  {
  public:
    SanityCheckerImpl ()
      : checker (gum_sanity_checker_new (output_to_stderr, NULL))
    {
    }

    ~SanityCheckerImpl ()
    {
      gum_sanity_checker_destroy (checker);
    }

    virtual void Begin (unsigned int flags)
    {
      gum_sanity_checker_begin (checker, flags);
    }

    virtual bool End ()
    {
      return gum_sanity_checker_end (checker) != FALSE;
    }

  private:
    GumSanityChecker * checker;
  };

  extern "C" SanityChecker * SanityCheckerCreate (void) { gum_init (); return new SanityCheckerImpl; }
  extern "C" void SanityCheckerDestroy (SanityChecker * checker) { delete static_cast<SanityCheckerImpl *> (checker); }
}