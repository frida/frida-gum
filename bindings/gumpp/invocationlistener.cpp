#include "gumpp.hpp"

#include "invocationcontext.hpp"

#include <gum/gum.h>

namespace Gum
{
  typedef struct _GumInvocationListenerProxy GumInvocationListenerProxy;
  typedef struct _GumInvocationListenerProxyClass GumInvocationListenerProxyClass;

  struct _GumInvocationListenerProxy
  {
    GObject parent;
    InvocationListener * proxy;
  };

  struct _GumInvocationListenerProxyClass
  {
    GObjectClass parent_class;
  };

  static GType gum_invocation_listener_proxy_get_type ();
  static void gum_invocation_listener_proxy_iface_init (gpointer g_iface, gpointer iface_data);

  class InvocationListenerProxy : public InvocationListener
  {
  public:
    InvocationListenerProxy (InvocationListenerCallbacks * callbacks)
      : cproxy (static_cast<GumInvocationListenerProxy *> (g_object_new (gum_invocation_listener_proxy_get_type (), NULL))),
        callbacks (callbacks)
    {
      cproxy->proxy = this;
    }

    virtual void ref ()
    {
      g_object_ref (cproxy);
    }

    virtual void unref ()
    {
      g_object_unref (cproxy);
    }

    virtual void * get_handle () const
    {
      return cproxy;
    }

    virtual void on_enter (InvocationContext * context)
    {
      callbacks->on_enter (context);
    }

    virtual void on_leave (InvocationContext * context)
    {
      callbacks->on_leave (context);
    }

  protected:
    GumInvocationListenerProxy * cproxy;
    InvocationListenerCallbacks * callbacks;
  };

  extern "C" GUMPP_CAPI InvocationListener * InvocationListenerProxy_new (InvocationListenerCallbacks * callbacks) { gum_init (); return new InvocationListenerProxy (callbacks); }

  G_DEFINE_TYPE_EXTENDED (GumInvocationListenerProxy,
                          gum_invocation_listener_proxy,
                          G_TYPE_OBJECT,
                          0,
                          G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                              gum_invocation_listener_proxy_iface_init));

  static void
  gum_invocation_listener_proxy_init (GumInvocationListenerProxy * self)
  {
    (void) self;
  }

  static void
  gum_invocation_listener_proxy_finalize (GObject * obj)
  {
    delete reinterpret_cast<GumInvocationListenerProxy *> (obj)->proxy;

    G_OBJECT_CLASS (gum_invocation_listener_proxy_parent_class)->finalize (obj);
  }

  static void
  gum_invocation_listener_proxy_class_init (GumInvocationListenerProxyClass * klass)
  {
    G_OBJECT_CLASS (klass)->finalize = gum_invocation_listener_proxy_finalize;
  }

  static void
  gum_invocation_listener_proxy_on_enter (GumInvocationListener * listener,
                                          GumInvocationContext * context)
  {
    InvocationContextImpl ic (context);
    reinterpret_cast<GumInvocationListenerProxy *> (listener)->proxy->on_enter (&ic);
  }

  static void
  gum_invocation_listener_proxy_on_leave (GumInvocationListener * listener,
                                          GumInvocationContext * context)
  {
    InvocationContextImpl ic (context);
    reinterpret_cast<GumInvocationListenerProxy *> (listener)->proxy->on_leave (&ic);
  }

  static void
  gum_invocation_listener_proxy_iface_init (gpointer g_iface,
                                            gpointer iface_data)
  {
    GumInvocationListenerIface * iface = static_cast<GumInvocationListenerIface *> (g_iface);

    (void) iface_data;

    iface->on_enter = gum_invocation_listener_proxy_on_enter;
    iface->on_leave = gum_invocation_listener_proxy_on_leave;
  }
}