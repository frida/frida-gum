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

static GumDatabase * gum_database_new (const gchar * path, sqlite3 * handle,
    GumDukDatabase * module);
static void gum_database_free (GumDatabase * self);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_statement_construct)
GUMJS_DECLARE_FINALIZER (gumjs_statement_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_integer)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_float)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_text)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_blob)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_null)
GUMJS_DECLARE_FUNCTION (gumjs_statement_step)
GUMJS_DECLARE_FUNCTION (gumjs_statement_reset)

static void gum_push_row (duk_context * ctx, sqlite3_stmt * statement);
static void gum_push_column (duk_context * ctx, sqlite3_stmt * statement,
    guint index);

static const duk_function_list_entry gumjs_database_module_functions[] =
{
  { "loadFromString", gumjs_database_load_from_string, 1 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_database_functions[] =
{
  { "prepare", gumjs_database_prepare, 1 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_statement_functions[] =
{
  { "bindInteger", gumjs_statement_bind_integer, 2 },
  { "bindFloat", gumjs_statement_bind_float, 2 },
  { "bindText", gumjs_statement_bind_text, 2 },
  { "bindBlob", gumjs_statement_bind_blob, 2 },
  { "bindNull", gumjs_statement_bind_null, 1 },
  { "step", gumjs_statement_step, 0 },
  { "reset", gumjs_statement_reset, 0 },

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
  duk_put_global_string (ctx, "SqliteDatabase");

  duk_push_c_function (ctx, gumjs_statement_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_statement_functions);
  duk_push_c_function (ctx, gumjs_statement_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->statement = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "SqliteStatement");

  self->memory_vfs = gum_memory_vfs_new ();
  sqlite3_vfs_register (&self->memory_vfs->vfs, FALSE);
}

void
_gum_duk_database_dispose (GumDukDatabase * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);

  _gum_duk_release_heapptr (scope.ctx, self->statement);
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
  gint status;

  self = gumjs_database_module_from_args (args);

  _gum_duk_args_parse (args, "s", &data);

  path = gum_memory_vfs_add_file (self->memory_vfs, data);
  if (path == NULL)
    goto invalid_data;

  handle = NULL;
  status = sqlite3_open_v2 (path, &handle, SQLITE_OPEN_READWRITE,
      self->memory_vfs->name);
  if (status != SQLITE_OK)
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
    _gum_duk_throw (ctx, "%s", sqlite3_errstr (status));
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
    _gum_duk_throw (ctx, "use constructor syntax to create a new instance");

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

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  gum_database_free (self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_database_prepare)
{
  GumDatabase * self = gumjs_database_from_args (args);
  const gchar * sql;
  sqlite3_stmt * statement;
  gint status;

  _gum_duk_args_parse (args, "s", &sql);

  statement = NULL;
  status = sqlite3_prepare_v2 (self->handle, sql, -1, &statement, NULL);
  if (statement == NULL)
    goto invalid_sql;

  duk_push_heapptr (ctx, self->module->statement);
  duk_push_pointer (ctx, statement);
  duk_new (ctx, 1);
  return 1;

invalid_sql:
  {
    if (status == SQLITE_OK)
      _gum_duk_throw (ctx, "invalid statement");
    else
      _gum_duk_throw (ctx, "%s", sqlite3_errstr (status));
    return 0;
  }
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

static sqlite3_stmt *
gumjs_statement_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  sqlite3_stmt * statement;

  duk_push_this (ctx);
  statement = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  return statement;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_statement_construct)
{
  sqlite3_stmt * statement;

  if (!duk_is_constructor_call (ctx))
    _gum_duk_throw (ctx, "use constructor syntax to create a new instance");

  _gum_duk_args_parse (args, "p", &statement);

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, statement);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_statement_finalize)
{
  sqlite3_stmt * statement;

  (void) args;

  statement = _gum_duk_steal_data (ctx, 0);
  if (statement == NULL)
    return 0;

  sqlite3_finalize (statement);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_integer)
{
  gint index, value, status;

  _gum_duk_args_parse (args, "ii", &index, &value);

  status = sqlite3_bind_int64 (gumjs_statement_from_args (args), index, value);
  if (status != SQLITE_OK)
    _gum_duk_throw (ctx, "%s", sqlite3_errstr (status));

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_float)
{
  gint index;
  gdouble value;
  gint status;

  _gum_duk_args_parse (args, "in", &index, &value);

  status = sqlite3_bind_double (gumjs_statement_from_args (args), index, value);
  if (status != SQLITE_OK)
    _gum_duk_throw (ctx, "%s", sqlite3_errstr (status));

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_text)
{
  gint index;
  const gchar * value;
  gint status;

  _gum_duk_args_parse (args, "is", &index, &value);

  status = sqlite3_bind_text (gumjs_statement_from_args (args), index, value,
      -1, SQLITE_TRANSIENT);
  if (status != SQLITE_OK)
    _gum_duk_throw (ctx, "%s", sqlite3_errstr (status));

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_blob)
{
  gint index;
  GBytes * bytes;
  gpointer data;
  gsize size;
  gint status;

  _gum_duk_args_parse (args, "iB~", &index, &bytes);

  data = g_bytes_unref_to_data (bytes, &size);

  status = sqlite3_bind_blob64 (gumjs_statement_from_args (args), index, data,
      size, g_free);
  if (status != SQLITE_OK)
    _gum_duk_throw (ctx, "%s", sqlite3_errstr (status));

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_null)
{
  gint index, status;

  _gum_duk_args_parse (args, "i", &index);

  status = sqlite3_bind_null (gumjs_statement_from_args (args), index);
  if (status != SQLITE_OK)
    _gum_duk_throw (ctx, "%s", sqlite3_errstr (status));

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_step)
{
  sqlite3_stmt * statement;
  gint status;

  statement = gumjs_statement_from_args (args);

  status = sqlite3_step (statement);
  switch (status)
  {
    case SQLITE_ROW:
      gum_push_row (ctx, statement);
      return 1;
    case SQLITE_DONE:
      duk_push_null (ctx);
      return 1;
    default:
      _gum_duk_throw (ctx, "%s", sqlite3_errstr (status));
      return 0;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_reset)
{
  gint status;

  status = sqlite3_reset (gumjs_statement_from_args (args));
  if (status != SQLITE_OK)
    _gum_duk_throw (ctx, "%s", sqlite3_errstr (status));

  return 0;
}

static void
gum_push_row (duk_context * ctx,
              sqlite3_stmt * statement)
{
  gint num_columns, index;

  duk_push_array (ctx);

  num_columns = sqlite3_column_count (statement);
  for (index = 0; index != num_columns; index++)
  {
    gum_push_column (ctx, statement, index);
    duk_put_prop_index (ctx, -2, index);
  }
}

static void
gum_push_column (duk_context * ctx,
                 sqlite3_stmt * statement,
                 guint index)
{
  gint type;

  type = sqlite3_column_type (statement, index);
  switch (type)
  {
    case SQLITE_INTEGER:
      duk_push_int (ctx, sqlite3_column_int64 (statement, index));
      break;
    case SQLITE_FLOAT:
      duk_push_number (ctx, sqlite3_column_double (statement, index));
      break;
    case SQLITE_TEXT:
      duk_push_string (ctx,
          (const char *) sqlite3_column_text (statement, index));
      break;
    case SQLITE_BLOB:
    {
      gint size;
      gpointer buffer_data;

      size = sqlite3_column_bytes (statement, index);

      if (size > 0)
      {
        buffer_data = duk_push_fixed_buffer (ctx, size);
        memcpy (buffer_data, sqlite3_column_blob (statement, index), size);
      }
      else
      {
        duk_push_fixed_buffer (ctx, 0);
      }

      duk_push_buffer_object (ctx, -1, 0, size, DUK_BUFOBJ_ARRAYBUFFER);

      duk_swap (ctx, -2, -1);
      duk_pop (ctx);

      break;
    }
    case SQLITE_NULL:
      duk_push_null (ctx);
      break;
    default:
      g_assert_not_reached ();
  }
}
