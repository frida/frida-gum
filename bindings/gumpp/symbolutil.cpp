#include "gumpp.hpp"

#include <gum/gum.h>

namespace Gum
{
  class SymbolPtrArray : public PtrArray
  {
  public:
    SymbolPtrArray (GArray * arr)
      : refcount (1),
        arr (arr)
    {
    }

    virtual void Retain ()
    {
      g_atomic_int_add (&refcount, 1);
    }

    virtual void Release ()
    {
      if (g_atomic_int_dec_and_test (&refcount))
        delete this;
    }

    virtual void * GetHandle () const
    {
      return arr;
    }

    virtual int Length ()
    {
      return arr->len;
    }

    virtual void * Nth (int n)
    {
      return g_array_index (arr, gpointer, n);
    }

  private:
    volatile gint refcount;
    GArray * arr;
  };

  extern "C" void * FindFunctionAsPtr (const char * name) { gum_init (); return gum_find_function (name); }
  extern "C" PtrArray * FindFunctionsMatchingAsPtrArray (const char * str) { gum_init (); return new SymbolPtrArray (gum_find_functions_matching (str)); }
}