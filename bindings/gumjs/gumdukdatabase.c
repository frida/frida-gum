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
  sqlite3 * handle;
  gchar * path;
  gboolean is_virtual;
  GumDukDatabase * module;
};

GUMJS_DECLARE_FUNCTION (gumjs_database_open)
GUMJS_DECLARE_FUNCTION (gumjs_database_open_inline)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_database_construct)
GUMJS_DECLARE_FINALIZER (gumjs_database_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_database_close)
GUMJS_DECLARE_FUNCTION (gumjs_database_exec)
GUMJS_DECLARE_FUNCTION (gumjs_database_prepare)
GUMJS_DECLARE_FUNCTION (gumjs_database_dump)

static GumDatabase * gum_database_new (sqlite3 * handle, const gchar * path,
    gboolean is_virtual, GumDukDatabase * module);
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
  { "open", gumjs_database_open, 1 },
  { "openInline", gumjs_database_open_inline, 1 },

  { NULL, NULL, 0 }
};

static const duk_function_list_entry gumjs_database_functions[] =
{
  { "close", gumjs_database_close, 0 },
  { "exec", gumjs_database_exec, 1 },
  { "prepare", gumjs_database_prepare, 1 },
  { "dump", gumjs_database_dump, 0 },

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

  duk_push_c_function (ctx, gumjs_database_construct, 3);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_database_functions);
  duk_push_c_function (ctx, gumjs_database_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->database = _gum_duk_require_heapptr (ctx, -1);
  duk_put_function_list (ctx, -1, gumjs_database_module_functions);
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
gumjs_module_from_args (const GumDukArgs * args)
{
  return _gum_duk_load_module_data (args->ctx, "database");
}

GUMJS_DEFINE_FUNCTION (gumjs_database_open)
{
  GumDukDatabase * self;
  const gchar * path;
  sqlite3 * handle;
  gint status;

  self = gumjs_module_from_args (args);

  _gum_duk_args_parse (args, "s", &path);

  handle = NULL;
  status = sqlite3_open_v2 (path, &handle,
      SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL);
  if (status != SQLITE_OK)
    goto invalid_database;

  duk_push_heapptr (ctx, self->database);
  duk_push_string (ctx, path);
  duk_push_pointer (ctx, handle);
  duk_push_boolean (ctx, FALSE);
  duk_new (ctx, 3);
  return 1;

invalid_database:
  {
    sqlite3_close_v2 (handle);
    _gum_duk_throw (ctx, "%s", sqlite3_errstr (status));
    return 0;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_database_open_inline)
{
  GumDukDatabase * self;
  const gchar * encoded_contents;
  gpointer contents;
  gsize size;
  gboolean valid;
  const gchar * path;
  sqlite3 * handle;
  gint status;

  self = gumjs_module_from_args (args);

  _gum_duk_args_parse (args, "s", &encoded_contents);

  valid =
      gum_memory_vfs_contents_from_string (encoded_contents, &contents, &size);
  if (!valid)
    goto invalid_data;

  path = gum_memory_vfs_add_file (self->memory_vfs, contents, size);

  handle = NULL;
  status = sqlite3_open_v2 (path, &handle, SQLITE_OPEN_READWRITE,
      self->memory_vfs->name);
  if (status != SQLITE_OK)
    goto invalid_database;

  duk_push_heapptr (ctx, self->database);
  duk_push_string (ctx, path);
  duk_push_pointer (ctx, handle);
  duk_push_boolean (ctx, TRUE);
  duk_new (ctx, 3);
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
  if (self == NULL)
    _gum_duk_throw (ctx, "database is closed");
  duk_pop (ctx);

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_database_construct)
{
  const gchar * path;
  sqlite3 * handle;
  gboolean is_virtual;
  GumDatabase * database;

  if (!duk_is_constructor_call (ctx))
    _gum_duk_throw (ctx, "use constructor syntax to create a new instance");

  _gum_duk_args_parse (args, "spt", &path, &handle, &is_virtual);

  database = gum_database_new (handle, path, is_virtual,
      gumjs_module_from_args (args));

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

GUMJS_DEFINE_FUNCTION (gumjs_database_close)
{
  GumDatabase * self;

  duk_push_this (ctx);
  self = _gum_duk_steal_data (ctx, -1);
  duk_pop (ctx);

  if (self != NULL)
    gum_database_free (self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_database_exec)
{
  GumDatabase * self;
  const gchar * sql;
  gchar * error_message;
  gint status;

  self = gumjs_database_from_args (args);

  _gum_duk_args_parse (args, "s", &sql);

  status = sqlite3_exec (self->handle, sql, NULL, NULL, &error_message);
  if (status != SQLITE_OK)
    goto error;

  return 0;

error:
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", error_message);
    sqlite3_free (error_message);

    (void) duk_throw (ctx);

    return 0;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_database_prepare)
{
  GumDatabase * self;
  const gchar * sql;
  sqlite3_stmt * statement;
  gint status;

  self = gumjs_database_from_args (args);

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

GUMJS_DEFINE_FUNCTION (gumjs_database_dump)
{
  GumDatabase * self;
  gpointer data, malloc_data;
  gsize size;
  GError * error;
  gchar * data_str;

  self = gumjs_database_from_args (args);

  if (self->is_virtual)
  {
    gboolean found;

    found = gum_memory_vfs_get_file_contents (self->module->memory_vfs,
        self->path, &data, &size);
    g_assert (found);

    malloc_data = NULL;
  }
  else
  {
    error = NULL;
    if (!g_file_get_contents (self->path, (gchar **) &data, &size, &error))
      goto io_error;

    malloc_data = data;
  }

  data_str = gum_memory_vfs_contents_to_string (data, size);

  duk_push_string (ctx, data_str);

  g_free (data_str);
  g_free (malloc_data);

  return 1;

io_error:
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR, "%s", error->message);
    g_error_free (error);

    (void) duk_throw (ctx);

    return 0;
  }
}

static GumDatabase *
gum_database_new (sqlite3 * handle,
                  const gchar * path,
                  gboolean is_virtual,
                  GumDukDatabase * module)
{
  GumDatabase * database;

  database = g_slice_new (GumDatabase);
  database->handle = handle;
  database->path = g_strdup (path);
  database->is_virtual = is_virtual;
  database->module = module;

  return database;
}

static void
gum_database_free (GumDatabase * self)
{
  sqlite3_close_v2 (self->handle);
  if (self->is_virtual)
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
  switch (sqlite3_column_type (statement, index))
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
