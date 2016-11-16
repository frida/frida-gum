/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptbackend.h"

#include "gumdukscriptbackend.h"
#include "gumv8scriptbackend.h"

#include <gum/gum-init.h>
#include <gum/guminterceptor.h>

static void gum_script_backend_adjust_ignore_level (GumThreadId thread_id,
    gint adjustment);
static void gum_script_backend_adjust_ignore_level_unlocked (
    GumThreadId thread_id, gint adjustment);
static gboolean gum_script_backend_flush_pending_unignores (gpointer user_data);

static GHashTable * ignored_threads;
static GSList * pending_unignores = NULL;
static GSource * pending_timeout = NULL;
static GRWLock ignored_lock;

static GMainContext * main_context;
static GumInterceptor * interceptor;

#include <stdio.h>

static void
gum_script_backend_init (void)
{
  ignored_threads = g_hash_table_new_full (NULL, NULL, NULL, NULL);

  main_context = g_main_context_get_thread_default ();

  interceptor = gum_interceptor_obtain ();
}

static void
gum_script_backend_deinit (void)
{
  if (pending_timeout != NULL)
  {
    g_source_destroy (pending_timeout);
    g_source_unref (pending_timeout);
    pending_timeout = NULL;
  }
  g_slist_free (pending_unignores);
  pending_unignores = NULL;

  g_object_unref (interceptor);
  interceptor = NULL;

  main_context = NULL;

  g_hash_table_unref (ignored_threads);
  ignored_threads = NULL;
}

static void
gum_script_backend_deinit_v8 (void)
{
  g_object_unref (gum_script_backend_obtain_v8 ());
}

static void
gum_script_backend_deinit_duk (void)
{
  g_object_unref (gum_script_backend_obtain_duk ());
}

GType
gum_script_backend_get_type (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GType gtype;

    gtype = g_type_register_static_simple (G_TYPE_INTERFACE, "GumScriptBackend",
        sizeof (GumScriptBackendIface), NULL, 0, NULL, 0);
    g_type_interface_add_prerequisite (gtype, G_TYPE_OBJECT);

    gum_script_backend_init ();
    _gum_register_destructor (gum_script_backend_deinit);

    g_once_init_leave (&gonce_value, gtype);
  }

  return (GType) gonce_value;
}

GumScriptBackend *
gum_script_backend_obtain (void)
{
  GumScriptBackend * backend = NULL;

#ifdef HAVE_V8
  backend = gum_script_backend_obtain_v8 ();
#endif
  if (backend == NULL)
    backend = gum_script_backend_obtain_duk ();

  return backend;
}

GumScriptBackend *
gum_script_backend_obtain_v8 (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GumScriptBackend * backend = NULL;

    if (gum_query_is_rwx_supported ())
    {
#ifdef HAVE_V8
      backend = GUM_SCRIPT_BACKEND (
          g_object_new (GUM_V8_TYPE_SCRIPT_BACKEND, NULL));
#endif

      if (backend != NULL)
        _gum_register_destructor (gum_script_backend_deinit_v8);
    }

    g_once_init_leave (&gonce_value, GPOINTER_TO_SIZE (backend) + 1);
  }

  return GUM_SCRIPT_BACKEND (GSIZE_TO_POINTER (gonce_value - 1));
}

GumScriptBackend *
gum_script_backend_obtain_duk (void)
{
  static volatile gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GumScriptBackend * backend;

    backend = GUM_SCRIPT_BACKEND (
        g_object_new (GUM_DUK_TYPE_SCRIPT_BACKEND, NULL));

    _gum_register_destructor (gum_script_backend_deinit_duk);

    g_once_init_leave (&gonce_value, GPOINTER_TO_SIZE (backend) + 1);
  }

  return GUM_SCRIPT_BACKEND (GSIZE_TO_POINTER (gonce_value - 1));
}

void
gum_script_backend_create (GumScriptBackend * self,
                           const gchar * name,
                           const gchar * source,
                           GCancellable * cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create (self, name, source,
      cancellable, callback, user_data);
}

GumScript *
gum_script_backend_create_finish (GumScriptBackend * self,
                                  GAsyncResult * result,
                                  GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create_finish (self, result,
      error);
}

GumScript *
gum_script_backend_create_sync (GumScriptBackend * self,
                                const gchar * name,
                                const gchar * source,
                                GCancellable * cancellable,
                                GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create_sync (self, name,
      source, cancellable, error);
}

void
gum_script_backend_create_from_bytes (GumScriptBackend * self,
                                      const gchar * name,
                                      GBytes * bytes,
                                      GCancellable * cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create_from_bytes (self, name, bytes,
      cancellable, callback, user_data);
}

GumScript *
gum_script_backend_create_from_bytes_finish (GumScriptBackend * self,
                                             GAsyncResult * result,
                                             GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create_from_bytes_finish (
      self, result, error);
}

GumScript *
gum_script_backend_create_from_bytes_sync (GumScriptBackend * self,
                                           const gchar * name,
                                           GBytes * bytes,
                                           GCancellable * cancellable,
                                           GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create_from_bytes_sync (self,
      name, bytes, cancellable, error);
}

void
gum_script_backend_compile (GumScriptBackend * self,
                            const gchar * source,
                            GCancellable * cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->compile (self, source, cancellable,
      callback, user_data);
}

GBytes *
gum_script_backend_compile_finish (GumScriptBackend * self,
                                   GAsyncResult * result,
                                   GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->compile_finish (self, result,
      error);
}

GBytes *
gum_script_backend_compile_sync (GumScriptBackend * self,
                                 const gchar * source,
                                 GCancellable * cancellable,
                                 GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->compile_sync (self, source,
      cancellable, error);
}

void
gum_script_backend_set_debug_message_handler (
    GumScriptBackend * self,
    GumScriptBackendDebugMessageHandler handler,
    gpointer data,
    GDestroyNotify data_destroy)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->set_debug_message_handler (self,
      handler, data, data_destroy);
}

void
gum_script_backend_post_debug_message (GumScriptBackend * self,
                                       const gchar * message)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->post_debug_message (self, message);
}

void
gum_script_backend_ignore (GumThreadId thread_id)
{
  gum_script_backend_adjust_ignore_level (thread_id, 1);
}

void
gum_script_backend_unignore (GumThreadId thread_id)
{
  gum_script_backend_adjust_ignore_level (thread_id, -1);
}

static void
gum_script_backend_adjust_ignore_level (GumThreadId thread_id,
                                        gint adjustment)
{
  gum_interceptor_ignore_current_thread (interceptor);

  g_rw_lock_writer_lock (&ignored_lock);
  gum_script_backend_adjust_ignore_level_unlocked (thread_id, adjustment);
  g_rw_lock_writer_unlock (&ignored_lock);

  gum_interceptor_unignore_current_thread (interceptor);
}

static void
gum_script_backend_adjust_ignore_level_unlocked (GumThreadId thread_id,
                                                 gint adjustment)
{
  gpointer thread_id_ptr = GSIZE_TO_POINTER (thread_id);
  gint level;

  level = GPOINTER_TO_INT (g_hash_table_lookup (ignored_threads,
      thread_id_ptr));
  level += adjustment;

  if (level > 0)
  {
    g_hash_table_insert (ignored_threads, thread_id_ptr,
        GINT_TO_POINTER (level));
  }
  else
  {
    g_hash_table_remove (ignored_threads, thread_id_ptr);
  }
}

void
gum_script_backend_unignore_later (GumThreadId thread_id)
{
  GSource * source;

  gum_interceptor_ignore_current_thread (interceptor);

  g_rw_lock_writer_lock (&ignored_lock);

  pending_unignores = g_slist_prepend (pending_unignores,
      GSIZE_TO_POINTER (thread_id));
  source = pending_timeout;
  pending_timeout = NULL;

  g_rw_lock_writer_unlock (&ignored_lock);

  if (source != NULL)
  {
    g_source_destroy (source);
    g_source_unref (source);
  }
  source = g_timeout_source_new_seconds (5);
  g_source_set_callback (source, gum_script_backend_flush_pending_unignores,
      NULL, NULL);
  g_source_attach (source, main_context);

  g_rw_lock_writer_lock (&ignored_lock);

  if (pending_timeout == NULL)
  {
    pending_timeout = source;
    source = NULL;
  }

  g_rw_lock_writer_unlock (&ignored_lock);

  if (source != NULL)
  {
    g_source_destroy (source);
    g_source_unref (source);
  }

  gum_interceptor_unignore_current_thread (interceptor);
}

static gboolean
gum_script_backend_flush_pending_unignores (gpointer user_data)
{
  (void) user_data;

  gum_interceptor_ignore_current_thread (interceptor);

  g_rw_lock_writer_lock (&ignored_lock);

  if (pending_timeout == g_main_current_source ())
  {
    g_source_unref (pending_timeout);
    pending_timeout = NULL;
  }

  while (pending_unignores != NULL)
  {
    GumThreadId thread_id;

    thread_id = GPOINTER_TO_SIZE (pending_unignores->data);
    pending_unignores = g_slist_delete_link (pending_unignores,
        pending_unignores);
    gum_script_backend_adjust_ignore_level_unlocked (thread_id, -1);
  }

  g_rw_lock_writer_unlock (&ignored_lock);

  gum_interceptor_unignore_current_thread (interceptor);

  return FALSE;
}

gboolean
gum_script_backend_is_ignoring (GumThreadId thread_id)
{
  gboolean is_ignored;

  g_rw_lock_reader_lock (&ignored_lock);

  is_ignored = g_hash_table_contains (ignored_threads,
      GSIZE_TO_POINTER (thread_id));

  g_rw_lock_reader_unlock (&ignored_lock);

  return is_ignored;
}
