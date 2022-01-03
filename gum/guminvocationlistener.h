/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_INVOCATION_LISTENER_H__
#define __GUM_INVOCATION_LISTENER_H__

#include <glib-object.h>
#include <gum/gumdefs.h>
#include <gum/guminvocationcontext.h>

G_BEGIN_DECLS

typedef void (* GumInvocationCallback) (GumInvocationContext * context,
    gpointer user_data);

#ifndef GUM_DIET

# define GUM_TYPE_INVOCATION_LISTENER (gum_invocation_listener_get_type ())
G_DECLARE_INTERFACE (GumInvocationListener, gum_invocation_listener, GUM,
    INVOCATION_LISTENER, GObject)

struct _GumInvocationListenerInterface
{
  GTypeInterface parent;

  void (* on_enter) (GumInvocationListener * self,
      GumInvocationContext * context);
  void (* on_leave) (GumInvocationListener * self,
      GumInvocationContext * context);
};

#else

# define GUM_INVOCATION_LISTENER(o) ((GumInvocationListener *) (o))
typedef struct _GumInvocationListener GumInvocationListener;

struct _GumInvocationListener
{
  GumObject parent;

  GumInvocationCallback on_enter;
  GumInvocationCallback on_leave;

  gpointer data;
  GDestroyNotify data_destroy;
};

#endif

GUM_API GumInvocationListener * gum_make_call_listener (
    GumInvocationCallback on_enter, GumInvocationCallback on_leave,
    gpointer data, GDestroyNotify data_destroy);
GUM_API GumInvocationListener * gum_make_probe_listener (
    GumInvocationCallback on_hit, gpointer data, GDestroyNotify data_destroy);

GUM_API void gum_invocation_listener_on_enter (GumInvocationListener * self,
    GumInvocationContext * context);
GUM_API void gum_invocation_listener_on_leave (GumInvocationListener * self,
    GumInvocationContext * context);

G_END_DECLS

#endif
