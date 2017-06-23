/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukdatabase.h"

#include "gumdukmacros.h"
#include "sqlite3.h"

typedef struct _GumDatabase GumDatabase;

struct _GumDatabase
{
  gchar * path;
  sqlite3 * handle;
  GumDukDatabase * module;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_database_module_construct)
GUMJS_DECLARE_FUNCTION (gumjs_database_load_from_string)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_database_construct)
GUMJS_DECLARE_FINALIZER (gumjs_database_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_database_prepare)
GUMJS_DECLARE_FUNCTION (gumjs_database_query)

static GumDatabase * gum_database_new (const gchar * path, sqlite3 * handle,
    GumDukDatabase * module);
static void gum_database_free (GumDatabase * self);

static const duk_function_list_entry gumjs_database_module_functions[] =
{
  { "loadFromString", gumjs_database_load_from_string, 1 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_database_functions[] =
{
  { "prepare", gumjs_database_prepare, 1 },
  { "query", gumjs_database_query, 2 },

  { NULL, NULL, 0 }
};

void
_gum_duk_database_init (GumDukDatabase * self,
                        GumDukCore * core)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  _gum_duk_store_module_data (ctx, "database", self);

  duk_push_c_function (ctx, gumjs_database_module_construct, 0);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_database_module_functions);
  duk_put_prop_string (ctx, -2, "prototype");
  duk_new (ctx, 0);
  duk_put_global_string (ctx, "Database");

  duk_push_c_function (ctx, gumjs_database_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_database_functions);
  duk_push_c_function (ctx, gumjs_database_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->database = _gum_duk_require_heapptr (ctx, -1);
  duk_pop (ctx);

  self->memory_vfs = gum_memory_vfs_new ();
  sqlite3_vfs_register (&self->memory_vfs->vfs, FALSE);
}

void
_gum_duk_database_dispose (GumDukDatabase * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);

  _gum_duk_release_heapptr (scope.ctx, self->database);
}

void
_gum_duk_database_finalize (GumDukDatabase * self)
{
  sqlite3_vfs_unregister (&self->memory_vfs->vfs);
  gum_memory_vfs_free (self->memory_vfs);
}

static GumDukDatabase *
gumjs_database_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "database");
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_database_module_construct)
{
  (void) ctx;
  (void) args;

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_database_load_from_string)
{
  GumDukDatabase * self;
  const gchar * data, * path;
  sqlite3 * handle;
  int result;

  self = gumjs_database_module_from_args (args);

  _gum_duk_args_parse (args, "s", &data);

  path = gum_memory_vfs_add_file (self->memory_vfs, data);
  if (path == NULL)
    goto invalid_data;

  handle = NULL;
  result = sqlite3_open_v2 (path, &handle, SQLITE_OPEN_READWRITE,
      self->memory_vfs->name);
  if (result != SQLITE_OK)
    goto invalid_database;

  duk_push_heapptr (ctx, self->database);
  duk_push_string (ctx, path);
  duk_push_pointer (ctx, handle);
  duk_new (ctx, 2);
  return 1;

invalid_data:
  {
    _gum_duk_throw (ctx, "invalid data");
    return 0;
  }
invalid_database:
  {
    sqlite3_close_v2 (handle);
    gum_memory_vfs_remove_file (self->memory_vfs, path);
    _gum_duk_throw (ctx, "invalid database");
    return 0;
  }
}

static GumDatabase *
gumjs_database_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumDatabase * self;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_database_construct)
{
  const gchar * path;
  sqlite3 * handle;
  GumDatabase * database;

  if (!duk_is_constructor_call (ctx))
    _gum_duk_throw (ctx, "use `new Database()` to create a new instance");

  _gum_duk_args_parse (args, "sp", &path, &handle);

  database = gum_database_new (path, handle,
      gumjs_database_module_from_args (args));

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, database);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_database_finalize)
{
  GumDatabase * self;

  (void) args;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "Database"))
    return 0;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  gum_database_free (self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_database_prepare)
{
  GumDatabase * self = gumjs_database_from_args (args);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_database_query)
{
  GumDatabase * self = gumjs_database_from_args (args);

  return 0;
}

static GumDatabase *
gum_database_new (const gchar * path,
                  sqlite3 * handle,
                  GumDukDatabase * module)
{
  GumDatabase * database;

  database = g_slice_new (GumDatabase);
  database->path = g_strdup (path);
  database->handle = handle;
  database->module = module;

  return database;
}

static void
gum_database_free (GumDatabase * self)
{
  sqlite3_close_v2 (self->handle);
  gum_memory_vfs_remove_file (self->module->memory_vfs, self->path);
  g_free (self->path);

  g_slice_free (GumDatabase, self);
}
