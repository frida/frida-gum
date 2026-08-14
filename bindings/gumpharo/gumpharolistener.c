#include "gumpharo.h"

#include <gum/gum.h>

typedef struct _GumPharoListener GumPharoListener;
typedef struct _GumPharoListenerClass GumPharoListenerClass;
typedef void (* GumPharoListenerFunc) (GumInvocationContext * context);

struct _GumPharoListener
{
  GObject parent;

  GumPharoListenerFunc on_enter;
  GumPharoListenerFunc on_leave;
};

struct _GumPharoListenerClass
{
  GObjectClass parent_class;
};

static void gum_pharo_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_pharo_listener_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_pharo_listener_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);

G_DEFINE_TYPE_EXTENDED (GumPharoListener, gum_pharo_listener, G_TYPE_OBJECT, 0,
    G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
        gum_pharo_listener_iface_init))

sqInt
prim_gum_pharo_listener_new (void)
{
  GumPharoListener * listener;

  listener = g_object_new (gum_pharo_listener_get_type (), NULL);
  listener->on_enter = gum_pharo_pointer_at (1);
  listener->on_leave = gum_pharo_pointer_at (0);

  return gum_pharo_return_pointer (listener);
}

static void
gum_pharo_listener_iface_init (gpointer g_iface,
                               gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_pharo_listener_on_enter;
  iface->on_leave = gum_pharo_listener_on_leave;
}

static void
gum_pharo_listener_on_enter (GumInvocationListener * listener,
                             GumInvocationContext * context)
{
  GumPharoListener * self = (GumPharoListener *) listener;

  if (self->on_enter != NULL)
    self->on_enter (context);
}

static void
gum_pharo_listener_on_leave (GumInvocationListener * listener,
                             GumInvocationContext * context)
{
  GumPharoListener * self = (GumPharoListener *) listener;

  if (self->on_leave != NULL)
    self->on_leave (context);
}

static void
gum_pharo_listener_class_init (GumPharoListenerClass * klass)
{
}

static void
gum_pharo_listener_init (GumPharoListener * self)
{
}
