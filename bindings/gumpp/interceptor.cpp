#include "gumpp.hpp"

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

    virtual bool attach_listener (void * function_address, InvocationListener * listener, void * user_data)
    {
      GumAttachReturn attach_ret = gum_interceptor_attach_listener (handle, function_address, GUM_INVOCATION_LISTENER (listener->get_handle ()), user_data);
      return (attach_ret == GUM_ATTACH_OK);
    }

    virtual void detach_listener (InvocationListener * listener)
    {
      gum_interceptor_detach_listener (handle, GUM_INVOCATION_LISTENER (listener->get_handle ()));
    }
  };

  extern "C" Interceptor * Interceptor_obtain (void) { gum_init (); return new InterceptorImpl; }
}