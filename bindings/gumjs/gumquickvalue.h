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
  JSContext * ctx;
  int count;
  JSValueConst * elements;

  GumQuickCore * core;

  GArray * values;
  GSList * cstrings;
  GSList * arrays;
  GSList * bytes;
};

G_GNUC_INTERNAL void _gum_quick_args_init (GumQuickArgs * args,
    JSContext * ctx, int count, JSValueConst * elements);
G_GNUC_INTERNAL void _gum_quick_args_destroy (GumQuickArgs * args);
G_GNUC_INTERNAL gboolean _gum_quick_args_parse (GumQuickArgs * self,
    const gchar * format, ...);

G_GNUC_INTERNAL void _gum_quick_store_module_data (JSContext * ctx,
    const gchar * module_id, gpointer data);
G_GNUC_INTERNAL gpointer _gum_quick_load_module_data (JSContext * ctx,
    const gchar * module_id);

G_GNUC_INTERNAL gboolean _gum_quick_string_get (JSContext * ctx,
    JSValueConst val, const char ** str);

G_GNUC_INTERNAL gboolean _gum_quick_bytes_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, GBytes ** bytes);
G_GNUC_INTERNAL gboolean _gum_quick_bytes_parse (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, GBytes ** bytes);

G_GNUC_INTERNAL gboolean _gum_quick_boolean_get (JSContext * ctx,
    JSValueConst val, gboolean * b);

G_GNUC_INTERNAL gboolean _gum_quick_int_get (JSContext * ctx, JSValueConst val,
    gint * i);

G_GNUC_INTERNAL gboolean _gum_quick_uint_get (JSContext * ctx, JSValueConst val,
    guint * u);

G_GNUC_INTERNAL JSValue _gum_quick_int64_new (JSContext * ctx, gint64 i,
    GumQuickCore * core);
G_GNUC_INTERNAL gboolean _gum_quick_int64_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, gint64 * i);
G_GNUC_INTERNAL gboolean _gum_quick_int64_parse (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, gint64 * i);

G_GNUC_INTERNAL JSValue _gum_quick_uint64_new (JSContext * ctx, guint64 u,
    GumQuickCore * core);
G_GNUC_INTERNAL gboolean _gum_quick_uint64_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, guint64 * u);
G_GNUC_INTERNAL gboolean _gum_quick_uint64_parse (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, guint64 * u);

G_GNUC_INTERNAL gboolean _gum_quick_size_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, gsize * size);
G_GNUC_INTERNAL gboolean _gum_quick_ssize_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, gssize * size);

G_GNUC_INTERNAL gboolean _gum_quick_float64_get (JSContext * ctx,
    JSValueConst val, gdouble * d);

G_GNUC_INTERNAL JSValue _gum_quick_native_pointer_new (JSContext * ctx,
    gpointer ptr, GumQuickCore * core);
G_GNUC_INTERNAL gboolean _gum_quick_native_pointer_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, gpointer * ptr);
G_GNUC_INTERNAL gboolean _gum_quick_native_pointer_parse (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, gpointer * ptr);

G_GNUC_INTERNAL gboolean _gum_quick_cpu_context_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, GumCpuContext ** cpu_context);

G_GNUC_INTERNAL gboolean _gum_quick_memory_ranges_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, GArray ** ranges);

G_GNUC_INTERNAL gboolean _gum_quick_page_protection_get (JSContext * ctx,
    JSValueConst val, GumPageProtection * prot);

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
