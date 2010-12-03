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

    virtual void destroy_handle ()
    {
      g_free (handle);
      handle = NULL;
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