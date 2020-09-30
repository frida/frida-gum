/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_QUICK_VALUE_H__
#define __GUM_QUICK_VALUE_H__

#include "gumquickcore.h"

G_BEGIN_DECLS

typedef struct _GumQuickArgs GumQuickArgs;

struct _GumQuickArgs
{
  int argc;
  JSValueConst * argv;

  JSContext * ctx;
  GumQuickCore * core;
};

G_GNUC_INTERNAL void _gum_quick_args_parse (const GumQuickArgs * args,
    const gchar * format, ...);

G_GNUC_INTERNAL JSValue _gum_quick_native_pointer_new (gpointer address,
    GumQuickCore * core);
G_GNUC_INTERNAL gboolean _gum_quick_native_pointer_get (JSValueConst value,
    gpointer * ptr, GumQuickCore * core);
G_GNUC_INTERNAL gboolean _gum_quick_native_pointer_parse (JSValueConst value,
    gpointer * ptr, GumQuickCore * core);

G_END_DECLS

#endif
