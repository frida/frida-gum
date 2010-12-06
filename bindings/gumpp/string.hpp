#include "gumpp.hpp"

#include "podwrapper.hpp"

namespace Gum
{
  class StringImpl : public PodWrapper<StringImpl, String, gchar>
  {
  public:
    StringImpl (gchar * str)
    {
      assign_handle (str);
    }

    ~StringImpl ()
    {
      g_free (handle);
    }

    virtual const char * c_str ()
    {
      return handle;
    }

    virtual size_t length () const
    {
      return strlen (handle);
    }
  };
}