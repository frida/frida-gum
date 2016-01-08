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
typedef struct _GumDukPropertyEntry GumDukPropertyEntry;

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

struct _GumDukPropertyEntry
{
  gchar * name;
  gpointer getter;
  gpointer setter;
};

G_GNUC_INTERNAL void _gum_duk_require_args (duk_context * ctx,
    const gchar * format, ...);

G_GNUC_INTERNAL gboolean _gum_duk_get_uint (duk_context * ctx,
    duk_idx_t index, guint * u);
G_GNUC_INTERNAL gboolean _gum_duk_get_pointer (duk_context * ctx,
    duk_idx_t index, gpointer * ptr);
G_GNUC_INTERNAL gboolean _gum_duk_parse_pointer (duk_context * ctx,
    duk_idx_t index, gpointer * ptr);
G_GNUC_INTERNAL gboolean _gum_duk_parse_protection (duk_context * ctx,
    duk_idx_t index, GumPageProtection * prot);
G_GNUC_INTERNAL gboolean _gum_duk_parse_bytes (duk_context * ctx,
    duk_idx_t index, GBytes ** bytes);
G_GNUC_INTERNAL gboolean _gum_duk_get_cpu_context (duk_context * ctx,
    duk_idx_t index, GumCpuContext ** cpu_context);

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
G_GNUC_INTERNAL guint _gumjs_uint_parse (duk_context * ctx, const gchar * str);

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

G_GNUC_INTERNAL GumDukHeapPtr _gumjs_native_pointer_new (duk_context * ctx,
    gpointer address, GumDukCore * core);
G_GNUC_INTERNAL void _gumjs_native_pointer_push (duk_context * ctx,
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
G_GNUC_INTERNAL gboolean _gumjs_byte_array_try_get (duk_context * ctx,
    GumDukValue * value, GBytes ** bytes);
G_GNUC_INTERNAL gboolean _gumjs_byte_array_try_get_opt (duk_context * ctx,
    GumDukValue * value, GBytes ** bytes);

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
    GumDukHeapPtr object, gpointer data);
G_GNUC_INTERNAL GumDukValue * _gumjs_get_value (duk_context * ctx,
    gint index);
G_GNUC_INTERNAL void _gumjs_release_value (duk_context * ctx,
    GumDukValue * value);
G_GNUC_INTERNAL void _gumjs_push_value (duk_context * ctx, GumDukValue * value);
G_GNUC_INTERNAL gboolean _gumjs_value_is_array (duk_context * ctx,
    GumDukValue * value);
G_GNUC_INTERNAL gboolean _gumjs_value_native_pointer_try_get (
    duk_context * ctx, GumDukValue * value, GumDukCore * core,
    gpointer * target);
G_GNUC_INTERNAL gboolean _gumjs_is_instanceof (duk_context * ctx,
    GumDukHeapPtr object, gchar * class_name);

G_GNUC_INTERNAL void _gumjs_duk_create_subclass (duk_context * ctx,
    const gchar * parent, const gchar * name, gpointer constructor,
    gint constructor_nargs, gpointer finalize);

G_GNUC_INTERNAL void _gumjs_duk_add_properties_to_class_by_heapptr (
    duk_context * ctx, GumDukHeapPtr klass,
    const GumDukPropertyEntry * entries);
G_GNUC_INTERNAL void _gumjs_duk_add_properties_to_class (duk_context * ctx,
    const gchar * class_name, const GumDukPropertyEntry * entries);

G_GNUC_INTERNAL gboolean _gumjs_is_arg0_equal_to_prototype (duk_context * ctx,
    const gchar * class_name);

G_GNUC_INTERNAL GumDukHeapPtr _gumjs_duk_get_this (duk_context * ctx);
G_GNUC_INTERNAL void _gumjs_duk_protect (duk_context * ctx,
    GumDukHeapPtr object);
G_GNUC_INTERNAL void _gumjs_duk_unprotect (duk_context * ctx,
    GumDukHeapPtr object);
G_GNUC_INTERNAL GumDukHeapPtr _gumjs_duk_get_heapptr (duk_context * ctx,
    gint index);
G_GNUC_INTERNAL GumDukHeapPtr _gumjs_duk_require_heapptr (duk_context * ctx,
    gint index);
G_GNUC_INTERNAL void _gumjs_duk_release_heapptr (duk_context * ctx,
    GumDukHeapPtr heapptr);
G_GNUC_INTERNAL GumDukHeapPtr _gumjs_duk_create_proxy_accessors (
    duk_context * ctx, GumDukHeapPtr target, gpointer getter, gpointer setter);

G_GNUC_INTERNAL GumDukWeakRef * _gumjs_weak_ref_new (duk_context * ctx,
    GumDukValue * value, GumDukWeakNotify notify, gpointer data,
    GDestroyNotify data_destroy);
G_GNUC_INTERNAL GumDukValue * _gumjs_weak_ref_get (GumDukWeakRef * ref);
G_GNUC_INTERNAL void _gumjs_weak_ref_free (GumDukWeakRef * ref);

G_END_DECLS

#endif
