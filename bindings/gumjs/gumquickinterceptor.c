/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickinterceptor.h"

void
_gum_quick_interceptor_init (GumQuickInterceptor * self,
                             GumQuickCore * core)
{
  self->core = core;

  self->interceptor = gum_interceptor_obtain ();
}

void
_gum_quick_interceptor_flush (GumQuickInterceptor * self)
{
}

void
_gum_quick_interceptor_dispose (GumQuickInterceptor * self)
{
}

void
_gum_quick_interceptor_finalize (GumQuickInterceptor * self)
{
  g_clear_pointer (&self->interceptor, g_object_unref);
}
