#include "gumpp.hpp"

#include "invocationcontext.hpp"
#include "objectwrapper.hpp"

#include <gum/gum.h>

namespace Gum
{
  class InterceptorImpl : public ObjectWrapper<InterceptorImpl, Interceptor, GumInterceptor>
  {
  public:
    InterceptorImpl ()
    {
      assign_handle (gum_interceptor_obtain ());
    }

    virtual bool attach_listener (void * function_address, InvocationListener * listener, void * listener_function_data)
    {
      GumAttachReturn attach_ret = gum_interceptor_attach_listener (handle, function_address, GUM_INVOCATION_LISTENER (listener->get_handle ()), listener_function_data);
      return (attach_ret == GUM_ATTACH_OK);
    }

    virtual void detach_listener (InvocationListener * listener)
    {
      gum_interceptor_detach_listener (handle, GUM_INVOCATION_LISTENER (listener->get_handle ()));
    }

    virtual void replace_function (void * function_address, void * replacement_address, void * replacement_function_data)
    {
      gum_interceptor_replace_function (handle, function_address, replacement_address, replacement_function_data);
    }

    virtual void revert_function (void * function_address)
    {
      gum_interceptor_revert_function (handle, function_address);
    }

    virtual InvocationContext * get_current_invocation ()
    {
      GumInvocationContext * context = gum_interceptor_get_current_invocation ();
      if (context == NULL)
        return NULL;
      return new InvocationContextImpl (context);
    }

    virtual void ignore_caller ()
    {
      gum_interceptor_ignore_caller (handle);
    }

    virtual void unignore_caller ()
    {
      gum_interceptor_unignore_caller (handle);
    }
  };

  extern "C" Interceptor * Interceptor_obtain (void) { gum_init (); return new InterceptorImpl; }
}