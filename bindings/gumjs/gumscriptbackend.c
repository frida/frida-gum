/*
 * Copyright (C) 2015-2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptbackend.h"

#include "gumdukscriptbackend.h"
#include "gumv8scriptbackend.h"
#include "sqlite3.h"

#include <gum/gum-init.h>

#define GUM_SQLITE_BLOCK_ALLOC_SIZE(s) (sizeof (GumSqliteBlock) + (s))
#define GUM_SQLITE_BLOCK_TO_CLIENT(b) (((GumSqliteBlock *) (b)) + 1)
#define GUM_SQLITE_BLOCK_FROM_CLIENT(b) (((GumSqliteBlock *) (b)) - 1)

typedef struct _GumSqliteBlock GumSqliteBlock;

struct _GumSqliteBlock
{
  int size;
  int padding;
};

static void gum_script_backend_init_sqlite (void);
static void gum_script_backend_deinit_sqlite (void);

static int gum_sqlite_allocator_init (void * data);
static void gum_sqlite_allocator_shutdown (void * data);
static void * gum_sqlite_allocator_malloc (int size);
static void gum_sqlite_allocator_free (void * mem);
static void * gum_sqlite_allocator_realloc (void * mem, int n_bytes);
static int gum_sqlite_allocator_size (void * mem);
static int gum_sqlite_allocator_roundup (int size);

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

    gum_script_backend_init_sqlite ();

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
        _gum_register_early_destructor (gum_script_backend_deinit_v8);
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

    _gum_register_early_destructor (gum_script_backend_deinit_duk);

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
                                      GBytes * bytes,
                                      GCancellable * cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create_from_bytes (self, bytes,
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
                                           GBytes * bytes,
                                           GCancellable * cancellable,
                                           GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->create_from_bytes_sync (self,
      bytes, cancellable, error);
}

void
gum_script_backend_compile (GumScriptBackend * self,
                            const gchar * name,
                            const gchar * source,
                            GCancellable * cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
  GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->compile (self, name, source,
      cancellable, callback, user_data);
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
                                 const gchar * name,
                                 const gchar * source,
                                 GCancellable * cancellable,
                                 GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->compile_sync (self, name,
      source, cancellable, error);
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

GMainContext *
gum_script_backend_get_main_context (GumScriptBackend * self)
{
  return GUM_SCRIPT_BACKEND_GET_INTERFACE (self)->get_main_context (self);
}

static void
gum_script_backend_init_sqlite (void)
{
  sqlite3_mem_methods gum_mem_methods = {
    gum_sqlite_allocator_malloc,
    gum_sqlite_allocator_free,
    gum_sqlite_allocator_realloc,
    gum_sqlite_allocator_size,
    gum_sqlite_allocator_roundup,
    gum_sqlite_allocator_init,
    gum_sqlite_allocator_shutdown,
    NULL,
  };

  sqlite3_config (SQLITE_CONFIG_MALLOC, &gum_mem_methods);

  sqlite3_initialize ();
  _gum_register_early_destructor (gum_script_backend_deinit_sqlite);
}

static void
gum_script_backend_deinit_sqlite (void)
{
  sqlite3_shutdown ();
}

static int
gum_sqlite_allocator_init (void * data)
{
  return SQLITE_OK;
}

static void
gum_sqlite_allocator_shutdown (void * data)
{
}

static void *
gum_sqlite_allocator_malloc (int size)
{
  GumSqliteBlock * block;

  block = g_malloc (GUM_SQLITE_BLOCK_ALLOC_SIZE (size));
  block->size = size;

  return GUM_SQLITE_BLOCK_TO_CLIENT (block);
}

static void
gum_sqlite_allocator_free (void * mem)
{
  GumSqliteBlock * block = GUM_SQLITE_BLOCK_FROM_CLIENT (mem);

  g_free (block);
}

static void *
gum_sqlite_allocator_realloc (void * mem,
                              int n_bytes)
{
  GumSqliteBlock * block = GUM_SQLITE_BLOCK_FROM_CLIENT (mem);

  block = g_realloc (block, GUM_SQLITE_BLOCK_ALLOC_SIZE (n_bytes));
  block->size = n_bytes;

  return GUM_SQLITE_BLOCK_TO_CLIENT (block);
}

static int
gum_sqlite_allocator_size (void * mem)
{
  GumSqliteBlock * block = GUM_SQLITE_BLOCK_FROM_CLIENT (mem);

  return block->size;
}

static int
gum_sqlite_allocator_roundup (int size)
{
  return size;
}
