/*
 * Copyright (C) 2017 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8database.h"

#include "gumv8macros.h"

#define GUMJS_MODULE_NAME Database

using namespace v8;

struct GumDatabase
{
  GumPersistent<v8::Object>::type * wrapper;
  sqlite3 * handle;
  gchar * path;
  gboolean is_virtual;
  GumV8Database * module;
};

GUMJS_DECLARE_FUNCTION (gumjs_database_open)
GUMJS_DECLARE_FUNCTION (gumjs_database_open_inline)

GUMJS_DECLARE_FUNCTION (gumjs_database_close)
GUMJS_DECLARE_FUNCTION (gumjs_database_exec)
GUMJS_DECLARE_FUNCTION (gumjs_database_prepare)

static Local<Object> gum_database_new (sqlite3 * handle, const gchar * path,
    gboolean is_virtual, GumV8Database * module);
static void gum_database_free (GumDatabase * self);
static void gum_database_on_weak_notify (
    const WeakCallbackInfo<GumDatabase> & info);

GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_integer)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_float)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_text)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_blob)
GUMJS_DECLARE_FUNCTION (gumjs_statement_bind_null)
GUMJS_DECLARE_FUNCTION (gumjs_statement_step)
GUMJS_DECLARE_FUNCTION (gumjs_statement_reset)

static const GumV8Function gumjs_database_module_functions[] =
{
  { "open", gumjs_database_open },
  { "openInline", gumjs_database_open_inline },

  { NULL, NULL }
};

static const GumV8Function gumjs_database_functions[] =
{
  { "close", gumjs_database_close },
  { "exec", gumjs_database_exec },
  { "prepare", gumjs_database_prepare },

  { NULL, NULL }
};

static const GumV8Function gumjs_statement_functions[] =
{
  { "bindInteger", gumjs_statement_bind_integer },
  { "bindFloat", gumjs_statement_bind_float },
  { "bindText", gumjs_statement_bind_text },
  { "bindBlob", gumjs_statement_bind_blob },
  { "bindNull", gumjs_statement_bind_null },
  { "step", gumjs_statement_step },
  { "reset", gumjs_statement_reset },

  { NULL, NULL }
};

void
_gum_v8_database_init (GumV8Database * self,
                     GumV8Core * core,
                     Handle<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto db = _gum_v8_create_class ("SqliteDatabase", nullptr, scope, module,
      isolate);
  _gum_v8_class_add_static (db, gumjs_database_module_functions, module,
      isolate);
  _gum_v8_class_add (db, gumjs_database_functions, module, isolate);
  self->database = new GumPersistent<FunctionTemplate>::type (isolate, db);

  auto statement = _gum_v8_create_class ("SqliteStatement", nullptr, scope,
      module, isolate);
  _gum_v8_class_add (db, gumjs_statement_functions, module, isolate);
  self->statement =
      new GumPersistent<FunctionTemplate>::type (isolate, statement);

  self->memory_vfs = gum_memory_vfs_new ();
  sqlite3_vfs_register (&self->memory_vfs->vfs, FALSE);
}

void
_gum_v8_database_realize (GumV8Database * self)
{
  self->databases = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_database_free);
}

void
_gum_v8_database_dispose (GumV8Database * self)
{
  g_hash_table_unref (self->databases);
  self->databases = NULL;

  delete self->statement;
  self->statement = nullptr;

  delete self->database;
  self->database = nullptr;
}

void
_gum_v8_database_finalize (GumV8Database * self)
{
  sqlite3_vfs_unregister (&self->memory_vfs->vfs);
  gum_memory_vfs_free (self->memory_vfs);
}

GUMJS_DEFINE_FUNCTION (gumjs_database_open)
{
  gchar * path;
  sqlite3 * handle;
  gint status;
  Local<Object> object;

  if (!_gum_v8_args_parse (args, "s", &path))
    return;

  handle = NULL;
  status = sqlite3_open_v2 (path, &handle, SQLITE_OPEN_READWRITE |
      SQLITE_OPEN_CREATE, NULL);
  if (status != SQLITE_OK)
    goto invalid_database;

  object = gum_database_new (handle, path, FALSE, module);

  info.GetReturnValue ().Set (object);

  g_free (path);

  return;

invalid_database:
  {
    sqlite3_close_v2 (handle);
    g_free (path);
    _gum_v8_throw (isolate, "%s", sqlite3_errstr (status));
    return;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_database_open_inline)
{
  gchar * data;
  const gchar * path;
  sqlite3 * handle;
  gint status;
  Local<Object> object;

  if (!_gum_v8_args_parse (args, "s", &data))
    return;

  path = gum_memory_vfs_add_file (module->memory_vfs, data);
  g_free (data);
  if (path == NULL)
    goto invalid_data;

  handle = NULL;
  status = sqlite3_open_v2 (path, &handle, SQLITE_OPEN_READWRITE,
      module->memory_vfs->name);
  if (status != SQLITE_OK)
    goto invalid_database;

  object = gum_database_new (handle, path, TRUE, module);

  info.GetReturnValue ().Set (object);

  return;

invalid_data:
  {
    _gum_v8_throw (isolate, "invalid data");
    return;
  }
invalid_database:
  {
    sqlite3_close_v2 (handle);
    gum_memory_vfs_remove_file (module->memory_vfs, path);
    _gum_v8_throw (isolate, "%s", sqlite3_errstr (status));
    return;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_database_close)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_database_exec)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_database_prepare)
{
}

static Local<Object>
gum_database_new (sqlite3 * handle,
                  const gchar * path,
                  gboolean is_virtual,
                  GumV8Database * module)
{
  auto isolate = module->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto constructor = Local<FunctionTemplate>::New (isolate,
      *module->database);
  auto object = constructor->GetFunction ()->NewInstance (context, 0, nullptr)
      .ToLocalChecked ();

  auto db = g_slice_new (GumDatabase);
  db->wrapper = new GumPersistent<Object>::type (isolate, object);
  db->wrapper->MarkIndependent ();
  db->wrapper->SetWeak (db, gum_database_on_weak_notify,
      WeakCallbackType::kParameter);
  db->handle = handle;
  db->path = g_strdup (path);
  db->is_virtual = is_virtual;
  db->module = module;

  object->SetAlignedPointerInInternalField (0, db);

  g_hash_table_insert (module->databases, db, db);

  return object;
}

static void
gum_database_free (GumDatabase * self)
{
  delete self->wrapper;

  sqlite3_close_v2 (self->handle);
  if (self->is_virtual)
    gum_memory_vfs_remove_file (self->module->memory_vfs, self->path);
  g_free (self->path);

  g_slice_free (GumDatabase, self);
}

static void
gum_database_on_weak_notify (const WeakCallbackInfo<GumDatabase> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->databases, self);
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_integer)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_float)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_text)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_blob)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_bind_null)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_step)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_statement_reset)
{
}
