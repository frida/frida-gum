/*
 * Copyright (C) 2008-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminvocationlistener.h"

G_DEFINE_INTERFACE (GumInvocationListener, gum_invocation_listener,
    G_TYPE_OBJECT)

static void
gum_invocation_listener_default_init (GumInvocationListenerInterface * iface)
{
}

void
gum_invocation_listener_on_enter (GumInvocationListener * self,
                                  GumInvocationContext * context)
{
  GUM_INVOCATION_LISTENER_GET_IFACE (self)->on_enter (self, context);
}

void
gum_invocation_listener_on_leave (GumInvocationListener * self,
                                  GumInvocationContext * context)
{
  GUM_INVOCATION_LISTENER_GET_IFACE (self)->on_leave (self, context);
}
