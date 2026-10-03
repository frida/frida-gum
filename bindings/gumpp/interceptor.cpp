#include "gumpp.hpp"

#include "invocationcontext.hpp"
#include "invocationlistener.hpp"
#include "objectwrapper.hpp"
#include "runtime.hpp"

#include <gum/gum.h>
#include <cassert>
#include <map>

namespace Gum
{
  class InterceptorImpl : public ObjectWrapper<InterceptorImpl, Interceptor, GumInterceptor>
  {
  public:
    InterceptorImpl ()
    {
      Runtime::ref ();
      g_mutex_init (&mutex);
      assign_handle (gum_interceptor_obtain ());
    }

    virtual ~InterceptorImpl ()
    {
      g_mutex_clear (&mutex);
      Runtime::unref ();
    }

    virtual bool attach (void * function_address, InvocationListener * listener, void * listener_function_data)
    {
      return attach_listener (function_address, listener, listener_function_data, proxy_by_listener);
    }

    virtual void detach (InvocationListener * listener)
    {
      detach_listener (listener, proxy_by_listener);
    }

    virtual bool attach (void * instruction_address, ProbeListener * listener, void * listener_function_data)
    {
      return attach_listener (instruction_address, listener, listener_function_data, probe_proxy_by_listener);
    }

    virtual void detach (ProbeListener * listener)
    {
      detach_listener (listener, probe_proxy_by_listener);
    }

    virtual void replace (void * function_address, void * replacement_address, void * replacement_data)
    {
      GumReplaceOptions options = {};
      options.replacement_data = replacement_data;
      gum_interceptor_replace (handle, function_address, replacement_address, NULL, &options);
    }

    virtual void revert (void * function_address)
    {
      gum_interceptor_revert (handle, function_address);
    }

    virtual void begin_transaction ()
    {
      gum_interceptor_begin_transaction (handle);
    }

    virtual void end_transaction ()
    {
      gum_interceptor_end_transaction (handle);
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
    template <typename Listener, typename Proxy>
    bool attach_listener (void * address, Listener * listener, void * listener_function_data, std::map<Listener *, RefPtr<Proxy> > & proxies)
    {
      RefPtr<Proxy> proxy;

      g_mutex_lock (&mutex);
      typename std::map<Listener *, RefPtr<Proxy> >::iterator it = proxies.find (listener);
      if (it == proxies.end ())
      {
        proxy = RefPtr<Proxy> (new Proxy (listener));
        proxies[listener] = proxy;
      }
      else
      {
        proxy = it->second;
      }
      g_mutex_unlock (&mutex);

      GumAttachOptions options = {};
      options.listener_function_data = listener_function_data;
      GumAttachReturn attach_ret = gum_interceptor_attach (handle, address, GUM_INVOCATION_LISTENER (proxy->get_handle ()),
          &options);
      return (attach_ret == GUM_ATTACH_OK);
    }

    template <typename Listener, typename Proxy>
    void detach_listener (Listener * listener, std::map<Listener *, RefPtr<Proxy> > & proxies)
    {
      RefPtr<Proxy> proxy;

      g_mutex_lock (&mutex);
      typename std::map<Listener *, RefPtr<Proxy> >::iterator it = proxies.find (listener);
      if (it != proxies.end ())
      {
        proxy = RefPtr<Proxy> (it->second);
        proxies.erase (it);
      }
      g_mutex_unlock (&mutex);

      if (proxy.is_null ())
        return;

      gum_interceptor_detach (handle, GUM_INVOCATION_LISTENER (proxy->get_handle ()));
    }

    GMutex mutex;

    typedef std::map<InvocationListener *, RefPtr<InvocationListenerProxy> > ProxyMap;
    typedef std::map<ProbeListener *, RefPtr<ProbeListenerProxy> > ProbeProxyMap;
    ProxyMap proxy_by_listener;
    ProbeProxyMap probe_proxy_by_listener;
  };

  extern "C" Interceptor * Interceptor_obtain (void) { return new InterceptorImpl; }
}
