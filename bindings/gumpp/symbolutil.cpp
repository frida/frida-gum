#include "gumpp.hpp"

#include "podwrapper.hpp"

#include <gum/gum.h>

namespace Gum
{
  class SymbolPtrArray : public PodWrapper<SymbolPtrArray, PtrArray, GArray>
  {
  public:
    SymbolPtrArray (GArray * arr)
    {
      assign_handle (arr);
    }

    ~SymbolPtrArray ()
    {
      g_array_free (handle, TRUE);
    }

    virtual int length ()
    {
      return handle->len;
    }

    virtual void * nth (int n)
    {
      return g_array_index (handle, gpointer, n);
    }
  };

  extern "C" void * find_function_ptr (const char * name) { gum_init (); return gum_find_function (name); }
  extern "C" PtrArray * find_matching_functions_array (const char * str) { gum_init (); return new SymbolPtrArray (gum_find_functions_matching (str)); }
}