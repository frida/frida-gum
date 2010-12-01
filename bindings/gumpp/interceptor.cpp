#include "gumpp.hpp"

#include <gum/gum.h>

namespace Gum
{
  class InterceptorImpl : public Interceptor
  {
  public:
    InterceptorImpl ()
      : interceptor (gum_interceptor_obtain ())
    {
      g_object_weak_ref (G_OBJECT (interceptor), delete_wrapper, this);
    }

    virtual void ref ()
    {
      g_object_ref (interceptor);
    }

    virtual void unref ()
    {
      g_object_unref (interceptor);
    }

    virtual void * get_handle () const
    {
      return interceptor;
    }

    virtual bool attach_listener (void * function_address, InvocationListener * listener, void * user_data)
    {
      GumAttachReturn attach_ret = gum_interceptor_attach_listener (interceptor, function_address, GUM_INVOCATION_LISTENER (listener->get_handle ()), user_data);
      return (attach_ret == GUM_ATTACH_OK);
    }

    virtual void detach_listener (InvocationListener * listener)
    {
      gum_interceptor_detach_listener (interceptor, GUM_INVOCATION_LISTENER (listener->get_handle ()));
    }

  private:
    static void delete_wrapper (gpointer data, GObject * where_the_object_was)
    {
      InterceptorImpl * impl = static_cast<InterceptorImpl *> (data);
      g_assert (impl->interceptor == (gpointer) where_the_object_was);
      delete impl;
    }

    GumInterceptor * interceptor;
  };

  extern "C" Interceptor * Interceptor_obtain (void) { gum_init (); return new InterceptorImpl; }
}