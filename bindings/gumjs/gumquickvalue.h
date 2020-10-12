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
    JSContext * ctx, int count, JSValueConst * elements, GumQuickCore * core);
G_GNUC_INTERNAL void _gum_quick_args_destroy (GumQuickArgs * args);
G_GNUC_INTERNAL gboolean _gum_quick_args_parse (GumQuickArgs * self,
    const gchar * format, ...);

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
G_GNUC_INTERNAL gboolean _gum_quick_native_pointer_try_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, gpointer * ptr);
G_GNUC_INTERNAL gboolean _gum_quick_native_pointer_parse (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, gpointer * ptr);

G_GNUC_INTERNAL JSValue _gum_quick_native_resource_new (JSContext * ctx,
    gpointer data, GDestroyNotify notify, GumQuickCore * core);

G_GNUC_INTERNAL JSValue _gum_quick_cpu_context_new (JSContext * ctx,
    GumCpuContext * handle, GumQuickCpuContextAccess access,
    GumQuickCore * core, GumQuickCpuContext ** cpu_context);
G_GNUC_INTERNAL void _gum_quick_cpu_context_reset (GumQuickCpuContext * self,
    GumCpuContext * handle, GumQuickCpuContextAccess access);
G_GNUC_INTERNAL void _gum_quick_cpu_context_make_read_only (
    GumQuickCpuContext * self);
G_GNUC_INTERNAL gboolean _gum_quick_cpu_context_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, GumCpuContext ** cpu_context);

G_GNUC_INTERNAL gboolean _gum_quick_memory_ranges_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, GArray ** ranges);

G_GNUC_INTERNAL gboolean _gum_quick_page_protection_get (JSContext * ctx,
    JSValueConst val, GumPageProtection * prot);

G_GNUC_INTERNAL gboolean _gum_quick_array_get_length (JSContext * ctx,
    JSValueConst array, GumQuickCore * core, guint * length);

G_GNUC_INTERNAL void _gum_quick_array_buffer_free (JSRuntime * rt,
    void * opaque, void * ptr);

G_GNUC_INTERNAL JSValue _gum_quick_throw (JSContext * ctx, const gchar * format,
    ...);
G_GNUC_INTERNAL JSValue _gum_quick_throw_literal (JSContext * ctx,
    const gchar * message);
G_GNUC_INTERNAL JSValue _gum_quick_throw_native (JSContext * ctx,
    GumExceptionDetails * details, GumQuickCore * core);

G_GNUC_INTERNAL const gchar * _gum_quick_memory_operation_to_string (
    GumMemoryOperation operation);

G_END_DECLS

#endif
