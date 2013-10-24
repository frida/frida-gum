#include "gumpp.hpp"

#include "invocationcontext.hpp"
#include "invocationlistener.hpp"
#include "objectwrapper.hpp"

#include <gum/gum.h>
#include <cassert>
#include <map>

namespace Gum
{
  class InterceptorImpl : public ObjectWrapper<InterceptorImpl, Interceptor, GumInterceptor>
  {
  public:
    InterceptorImpl ()
      : mutex (g_mutex_new ())
    {
      assign_handle (gum_interceptor_obtain ());
    }

    virtual ~InterceptorImpl ()
    {
      g_mutex_free (mutex);
    }

    virtual bool attach_listener (void * function_address, InvocationListener * listener, void * listener_function_data)
    {
      RefPtr<InvocationListenerProxy> proxy;

      g_mutex_lock (mutex);
      ProxyMap::iterator it = proxy_by_listener.find (listener);
      if (it == proxy_by_listener.end ())
      {
        proxy = RefPtr<InvocationListenerProxy> (new InvocationListenerProxy (listener));
        proxy_by_listener[listener] = proxy;
      }
      else
      {
        proxy = it->second;
      }
      g_mutex_unlock (mutex);

      GumAttachReturn attach_ret = gum_interceptor_attach_listener (handle, function_address, GUM_INVOCATION_LISTENER (proxy->get_handle ()), listener_function_data);
      return (attach_ret == GUM_ATTACH_OK);
    }

    virtual void detach_listener (InvocationListener * listener)
    {
      RefPtr<InvocationListenerProxy> proxy;

      g_mutex_lock (mutex);
      ProxyMap::iterator it = proxy_by_listener.find (listener);
      if (it != proxy_by_listener.end ())
      {
        proxy = RefPtr<InvocationListenerProxy> (it->second);
        proxy_by_listener.erase (it);
      }
      g_mutex_unlock (mutex);

      if (proxy.is_null ())
        return;

      gum_interceptor_detach_listener (handle, GUM_INVOCATION_LISTENER (proxy->get_handle ()));
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

    virtual void ignore_current_thread ()
    {
      gum_interceptor_ignore_current_thread (handle);
    }

    virtual void unignore_current_thread ()
    {
      gum_interceptor_unignore_current_thread (handle);
    }

    virtual void ignore_other_threads ()
    {
      gum_interceptor_ignore_other_threads (handle);
    }

    virtual void unignore_other_threads ()
    {
      gum_interceptor_unignore_other_threads (handle);
    }

  private:
    GMutex * mutex;

    typedef std::map<InvocationListener *, RefPtr<InvocationListenerProxy> > ProxyMap;
    ProxyMap proxy_by_listener;
  };

  extern "C" Interceptor * Interceptor_obtain (void) { gum_init (); return new InterceptorImpl; }
}
