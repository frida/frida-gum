/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_INTERCEPTOR_H__
#define __GUM_QUICK_INTERCEPTOR_H__

#include "gumquickcore.h"

#include <gum/guminterceptor.h>

G_BEGIN_DECLS

struct _GumQuickInterceptor
{
  GumQuickCore * core;

  GumInterceptor * interceptor;
};

G_GNUC_INTERNAL void _gum_quick_interceptor_init (GumQuickInterceptor * self,
    GumQuickCore * core);
G_GNUC_INTERNAL void _gum_quick_interceptor_flush (GumQuickInterceptor * self);
G_GNUC_INTERNAL void _gum_quick_interceptor_dispose (
    GumQuickInterceptor * self);
G_GNUC_INTERNAL void _gum_quick_interceptor_finalize (
    GumQuickInterceptor * self);

G_END_DECLS

#endif
