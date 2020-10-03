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

G_GNUC_INTERNAL gboolean _gum_quick_int_get (JSContext * ctx, JSValueConst val,
    gint * i);

G_GNUC_INTERNAL gboolean _gum_quick_uint_get (JSContext * ctx, JSValueConst val,
    guint * u);

G_GNUC_INTERNAL JSValue _gum_quick_int64_new (JSContext * ctx, gint64 i,
    GumQuickCore * core);
G_GNUC_INTERNAL gboolean _gum_quick_int64_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, gint64 * i);

G_GNUC_INTERNAL JSValue _gum_quick_uint64_new (JSContext * ctx, guint64 u,
    GumQuickCore * core);
G_GNUC_INTERNAL gboolean _gum_quick_uint64_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, guint64 * u);

G_GNUC_INTERNAL gboolean _gum_quick_float64_get (JSContext * ctx,
    JSValueConst val, gdouble * d);

G_GNUC_INTERNAL JSValue _gum_quick_native_pointer_new (JSContext * ctx,
    gpointer ptr, GumQuickCore * core);
G_GNUC_INTERNAL gboolean _gum_quick_native_pointer_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, gpointer * ptr);
G_GNUC_INTERNAL gboolean _gum_quick_native_pointer_parse (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, gpointer * ptr);

G_GNUC_INTERNAL gboolean _gum_quick_array_get_length (JSContext * ctx,
    JSValueConst array, guint * length);

G_GNUC_INTERNAL JSValue _gum_quick_throw (JSContext * ctx, const gchar * format,
    ...);
G_GNUC_INTERNAL JSValue _gum_quick_throw_literal (JSContext * ctx,
    const gchar * message);
G_GNUC_INTERNAL JSValue _gum_quick_throw_native (JSContext * ctx,
    GumExceptionDetails * details, GumQuickCore * core);

G_END_DECLS

#endif
