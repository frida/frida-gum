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
      return arr;
    }

    virtual int length ()
    {
      return arr->len;
    }

    virtual void * nth (int n)
    {
      return g_array_index (arr, gpointer, n);
    }

  private:
    volatile gint refcount;
    GArray * arr;
  };

  extern "C" void * find_function_ptr (const char * name) { gum_init (); return gum_find_function (name); }
  extern "C" PtrArray * find_matching_functions_array (const char * str) { gum_init (); return new SymbolPtrArray (gum_find_functions_matching (str)); }
}