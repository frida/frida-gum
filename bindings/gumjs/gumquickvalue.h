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

G_GNUC_INTERNAL gboolean _gum_quick_args_parse (const GumQuickArgs * args,
    const gchar * format, ...);

G_GNUC_INTERNAL void _gum_quick_store_module_data (JSContext * ctx,
    const gchar * module_id, gpointer data);
G_GNUC_INTERNAL gpointer _gum_quick_load_module_data (JSContext * ctx,
    const gchar * module_id);

G_GNUC_INTERNAL JSValue _gum_quick_int64_new (gint64 value,
    GumQuickCore * core);

G_GNUC_INTERNAL JSValue _gum_quick_uint64_new (guint64 value,
    GumQuickCore * core);

G_GNUC_INTERNAL JSValue _gum_quick_native_pointer_new (gpointer address,
    GumQuickCore * core);
G_GNUC_INTERNAL gboolean _gum_quick_native_pointer_get (JSValueConst value,
    gpointer * ptr, GumQuickCore * core);
G_GNUC_INTERNAL gboolean _gum_quick_native_pointer_parse (JSValueConst value,
    gpointer * ptr, GumQuickCore * core);

G_GNUC_INTERNAL JSValue _gum_quick_throw (JSContext * ctx, const gchar * format,
    ...);
G_GNUC_INTERNAL JSValue _gum_quick_throw_literal (JSContext * ctx,
    const gchar * message);

G_END_DECLS

#endif
