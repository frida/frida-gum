/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_INVOCATION_LISTENER_H__
#define __GUM_INVOCATION_LISTENER_H__

#include <glib-object.h>
#include <gum/gumdefs.h>
#include <gum/guminvocationcontext.h>

#define GUM_TYPE_INVOCATION_LISTENER (gum_invocation_listener_get_type ())
#define GUM_INVOCATION_LISTENER(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj),\
    GUM_TYPE_INVOCATION_LISTENER, GumInvocationListener))
#define GUM_INVOCATION_LISTENER_CAST(obj) ((GumInvocationListener *) (obj))
#define GUM_IS_INVOCATION_LISTENER(obj) (G_TYPE_CHECK_INSTANCE_TYPE ((obj),\
    GUM_TYPE_INVOCATION_LISTENER))
#define GUM_INVOCATION_LISTENER_GET_INTERFACE(inst) (G_TYPE_INSTANCE_GET_INTERFACE (\
    (inst), GUM_TYPE_INVOCATION_LISTENER, GumInvocationListenerIface))

typedef struct _GumInvocationListener GumInvocationListener;
typedef struct _GumInvocationListenerIface GumInvocationListenerIface;

struct _GumInvocationListenerIface
{
  GTypeInterface parent;

  void (* on_enter) (GumInvocationListener * self,
      GumInvocationContext * context);
  void (* on_leave) (GumInvocationListener * self,
      GumInvocationContext * context);
};

G_BEGIN_DECLS

GUM_API GType gum_invocation_listener_get_type (void);

GUM_API void gum_invocation_listener_on_enter (GumInvocationListener * self,
    GumInvocationContext * context);
GUM_API void gum_invocation_listener_on_leave (GumInvocationListener * self,
    GumInvocationContext * context);

G_END_DECLS

#endif
