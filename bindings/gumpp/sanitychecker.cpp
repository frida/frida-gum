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
      : refcount (1),
        checker (gum_sanity_checker_new (output_to_stderr, NULL))
    {
    }

    ~SanityCheckerImpl ()
    {
      gum_sanity_checker_destroy (checker);
    }

    virtual void ref ()
    {
      g_atomic_int_add (&refcount, 1);
    }

    virtual void unref ()
    {
      if (g_atomic_int_dec_and_test (&refcount))
        delete this;
    }

    virtual void * get_handle () const
    {
      return checker;
    } 

    virtual void begin (unsigned int flags)
    {
      gum_sanity_checker_begin (checker, flags);
    }

    virtual bool end ()
    {
      return gum_sanity_checker_end (checker) != FALSE;
    }

  private:
    volatile gint refcount;
    GumSanityChecker * checker;
  };

  extern "C" SanityChecker * SanityChecker_new (void) { gum_init (); return new SanityCheckerImpl; }
}