/*
 * Copyright (C) 2025-2026 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef __GUM_BAREBONE_H__
#define __GUM_BAREBONE_H__

#include <gio/gio.h>
#include <gum/gumexceptor.h>
#include <gum/gummemory.h>
#include <gum/gummoduleregistry.h>
#include <gum/gumprocess.h>
#include <gum/gumthreadregistry.h>

G_BEGIN_DECLS

typedef struct _GumBareboneStreamOps GumBareboneStreamOps;

struct _GumBareboneStreamOps
{
  gint (* poll) (GPollFD * fds, guint nfds, gint timeout);
  gssize (* read) (gpointer handle, gpointer buffer, gsize count,
      GError ** error);
  gssize (* write) (gpointer handle, gconstpointer buffer, gsize count,
      GError ** error);
  gboolean (* close) (gpointer handle, GError ** error);
};

GUM_API const gchar * gum_barebone_query_platform (void);
GUM_API guint gum_barebone_query_page_size (void);
GUM_API gsize gum_barebone_query_stack_size (void);
GUM_API gpointer gum_barebone_try_remap_writable_pages (gconstpointer * addrs,
    guint n_addrs);

GUM_API gboolean gum_barebone_handle_exception (GumExceptionType type,
    gpointer pc, gpointer accessed_address, GumCpuContext * cpu_context);

GUM_API void gum_barebone_on_registry_activating (GumModuleRegistry * registry);
GUM_API void gum_barebone_on_registry_deactivating (
    GumModuleRegistry * registry);
GUM_API void gum_barebone_register_module (GumModuleRegistry * registry,
    GumModule * module);
GUM_API void gum_barebone_unregister_module (GumModuleRegistry * registry,
    GumAddress base_address);

GUM_API GumThreadDetails * gum_barebone_find_thread_by_id (
    GumThreadId thread_id, GumThreadFlags flags);
GUM_API gboolean gum_barebone_modify_thread (GumThreadId thread_id,
    GumModifyThreadFunc func, gpointer user_data, GumModifyThreadFlags flags);
GUM_API void gum_barebone_enumerate_threads (GumFoundThreadFunc func,
    gpointer user_data, GumThreadFlags flags);

GUM_API void gum_barebone_on_thread_registry_activating (
    GumThreadRegistry * registry);
GUM_API void gum_barebone_on_thread_registry_deactivating (
    GumThreadRegistry * registry);
GUM_API void gum_barebone_register_thread (GumThreadRegistry * registry,
    const GumThreadDetails * thread);
GUM_API void gum_barebone_unregister_thread (GumThreadRegistry * registry,
    GumThreadId id);
GUM_API void gum_barebone_rename_thread (GumThreadRegistry * registry,
    GumThreadId id, const gchar * name);

GUM_API gchar * gum_barebone_ansi_string_to_utf8 (const gchar * str_ansi,
    gint length);
GUM_API gchar * gum_barebone_ansi_string_from_utf8 (const gchar * str_utf8);

GUM_API GInputStream * gum_barebone_input_stream_new (gpointer handle,
    gboolean close_handle);
GUM_API GOutputStream * gum_barebone_output_stream_new (gpointer handle,
    gboolean close_handle);
GUM_API const GumBareboneStreamOps * gum_barebone_query_stream_ops (void);

G_END_DECLS

#endif
