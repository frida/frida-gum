/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_DUK_VALUE_H__
#define __GUM_DUK_VALUE_H__

#include "gumdukcore.h"

G_BEGIN_DECLS

typedef struct _GumDukValue GumDukValue;
typedef struct _GumDukArgs GumDukArgs;

union _GumDukValueData
{
  guint _uint;
  gint _int;
  gboolean _boolean;
  const gchar * _string;
  GumDukHeapPtr _heapptr;
  gdouble _number;
};

struct _GumDukValue
{
  union _GumDukValueData data;
  gint type;
};

struct _GumDukArgs
{
  gsize count;

  duk_context * ctx;
  GumDukCore * core;
};

G_GNUC_INTERNAL gboolean _gumjs_args_parse (duk_context * ctx,
    const gchar * format, ...);

G_GNUC_INTERNAL GumDukWeakRef * _gumjs_weak_ref_new (duk_context * ctx,
    GumDukValue * value, GumDukWeakNotify notify, gpointer data,
    GDestroyNotify data_destroy);
G_GNUC_INTERNAL GumDukValue * _gumjs_weak_ref_get (GumDukWeakRef * ref);
G_GNUC_INTERNAL void _gumjs_weak_ref_free (GumDukWeakRef * ref);

G_GNUC_INTERNAL gboolean _gumjs_value_int_try_get (duk_context * ctx,
    GumDukValue * value, gint * i);
G_GNUC_INTERNAL gboolean _gumjs_value_uint_try_get (duk_context * ctx,
    GumDukValue * value, guint * u);
G_GNUC_INTERNAL gboolean _gumjs_value_int64_try_get (duk_context * ctx,
    GumDukValue * value, gint64 * i);
G_GNUC_INTERNAL gboolean _gumjs_value_uint64_try_get (duk_context * ctx,
    GumDukValue * value, guint64 * u);
G_GNUC_INTERNAL gboolean _gumjs_value_number_try_get (duk_context * ctx,
    GumDukValue * value, gdouble * number);
G_GNUC_INTERNAL gboolean _gumjs_uint_try_parse (duk_context * ctx,
    const gchar * str, guint * u);

G_GNUC_INTERNAL gboolean _gumjs_value_string_try_get (duk_context * ctx,
    GumDukValue * value, gchar ** str);
G_GNUC_INTERNAL gboolean _gumjs_value_string_try_get_opt (duk_context * ctx,
    GumDukValue * value, gchar ** str);

G_GNUC_INTERNAL GumDukValue * _gumjs_object_get (duk_context * ctx,
    GumDukHeapPtr object, const gchar * key);
G_GNUC_INTERNAL gboolean _gumjs_object_try_get (duk_context * ctx,
    GumDukHeapPtr object, const gchar * key, GumDukValue ** value);
G_GNUC_INTERNAL gboolean _gumjs_object_try_get_uint (duk_context * ctx,
    GumDukHeapPtr object, const gchar * key, guint * value);

G_GNUC_INTERNAL GumDukHeapPtr _gumjs_native_pointer_new_priv (duk_context * ctx,
    GumDukHeapPtr object, gpointer address, GumDukCore * core);
G_GNUC_INTERNAL GumDukHeapPtr _gumjs_native_pointer_new (duk_context * ctx,
    gpointer address, GumDukCore * core);
G_GNUC_INTERNAL gpointer _gumjs_native_pointer_value (duk_context * ctx,
    GumDukHeapPtr value);

G_GNUC_INTERNAL GumDukHeapPtr _gumjs_cpu_context_new (duk_context * ctx,
    GumCpuContext * handle, GumDukCpuContextAccess access,
    GumDukCore * core);
G_GNUC_INTERNAL void _gumjs_cpu_context_detach (duk_context * ctx,
    GumDukHeapPtr value);

G_GNUC_INTERNAL GumDukNativeResource * _gumjs_native_resource_new (
    duk_context * ctx, gpointer data, GDestroyNotify notify,
    GumDukCore * core, GumDukHeapPtr * handle);
G_GNUC_INTERNAL void _gumjs_native_resource_free (
    GumDukNativeResource * resource);

G_GNUC_INTERNAL GumDukHeapPtr _gumjs_array_buffer_new (duk_context * ctx,
    gsize size, GumDukCore * core);
G_GNUC_INTERNAL gpointer _gumjs_array_buffer_get_data (duk_context * ctx,
    GumDukHeapPtr value, gsize * size);
G_GNUC_INTERNAL gboolean _gumjs_array_buffer_try_get_data (duk_context * ctx,
    GumDukHeapPtr value, gpointer * data, gsize * size);

G_GNUC_INTERNAL void _gumjs_throw (duk_context * ctx,
    const gchar * format, ...);
G_GNUC_INTERNAL void _gumjs_throw_native (duk_context * ctx,
    GumExceptionDetails * details, GumDukCore * core);
G_GNUC_INTERNAL void _gumjs_parse_exception_details (duk_context * ctx,
    GumExceptionDetails * details, GumDukCore * core,
    GumDukHeapPtr * exception, GumDukHeapPtr * cpu_context);

G_GNUC_INTERNAL const gchar * _gumjs_thread_state_to_string (
    GumThreadState state);
G_GNUC_INTERNAL const gchar * _gumjs_memory_operation_to_string (
    GumMemoryOperation operation);

G_GNUC_INTERNAL gpointer _gumjs_get_private_data (duk_context * ctx,
    GumDukHeapPtr object);
G_GNUC_INTERNAL void _gumjs_set_private_data (duk_context * ctx,
    GumDukHeapPtr object, gpointer privatedata);
G_GNUC_INTERNAL GumDukValue * _gumjs_get_value (duk_context * ctx,
    gint idx);
G_GNUC_INTERNAL gboolean _gumjs_value_is_array (duk_context * ctx,
    GumDukValue * value);
G_GNUC_INTERNAL gboolean _gumjs_value_native_pointer_try_get (
    duk_context * ctx, GumDukValue * value, GumDukCore * core,
    gpointer * target);
G_GNUC_INTERNAL gboolean _gumjs_is_instanceof (duk_context * ctx,
    GumDukHeapPtr object, gchar * classname);
G_END_DECLS

#endif
