/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminvocationlistener.h"

GType
gum_invocation_listener_get_type (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GType gtype;

    gtype = g_type_register_static_simple (G_TYPE_INTERFACE,
        "GumInvocationListener", sizeof (GumInvocationListenerIface),
        NULL, 0, NULL, 0);
    g_type_interface_add_prerequisite (gtype, G_TYPE_OBJECT);

    g_once_init_leave (&gonce_value, (GType) gtype);
  }

  return (GType) gonce_value;
}

void
gum_invocation_listener_on_enter (GumInvocationListener * self,
                                  GumInvocationContext * context)
{
  GUM_INVOCATION_LISTENER_GET_INTERFACE (self)->on_enter (self, context);
}

void
gum_invocation_listener_on_leave (GumInvocationListener * self,
                                  GumInvocationContext * context)
{
  GUM_INVOCATION_LISTENER_GET_INTERFACE (self)->on_leave (self, context);
}
