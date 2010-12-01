#include "gumpp.hpp"

#include <gum/gum.h>
#include <stdexcept>

namespace Gum
{
  class InterceptorImpl : public Interceptor
  {
  public:
    InterceptorImpl ()
      : interceptor (gum_interceptor_obtain ())
    {
      g_object_weak_ref (G_OBJECT (interceptor), DeleteWrapper, this);
    }

    virtual void Retain ()
    {
      g_object_ref (interceptor);
    }

    virtual void Release ()
    {
      g_object_unref (interceptor);
    }

    virtual void * GetHandle () const
    {
      return interceptor;
    }

    virtual bool AttachListener (void * function_address, InvocationListener * listener, void * user_data)
    {
      GumAttachReturn attach_ret = gum_interceptor_attach_listener (interceptor, function_address, GUM_INVOCATION_LISTENER (listener->GetHandle ()), user_data);
      return (attach_ret == GUM_ATTACH_OK);
    }

    virtual void DetachListener (InvocationListener * listener)
    {
      gum_interceptor_detach_listener (interceptor, GUM_INVOCATION_LISTENER (listener->GetHandle ()));
    }

  private:
    static void DeleteWrapper (gpointer data, GObject * where_the_object_was)
    {
      InterceptorImpl * impl = static_cast<InterceptorImpl *> (data);
      g_assert (impl->interceptor == (gpointer) where_the_object_was);
      delete impl;
    }

    GumInterceptor * interceptor;
  };

  extern "C" Interceptor * InterceptorObtain (void) { gum_init (); return new InterceptorImpl; }
}