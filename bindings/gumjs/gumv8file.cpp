/*
 * Copyright (C) 2013-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8file.h"

#include "gumv8macros.h"

#include <errno.h>
#include <string.h>

#define GUMJS_MODULE_NAME File

using namespace v8;

struct GumFile
{
  GumPersistent<Object>::type * wrapper;
  FILE * handle;
  GumV8File * module;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_file_construct)
GUMJS_DECLARE_FUNCTION (gumjs_file_write)
GUMJS_DECLARE_FUNCTION (gumjs_file_flush)
GUMJS_DECLARE_FUNCTION (gumjs_file_close)

static GumFile * gum_file_new (Local<Object> wrapper, FILE * handle,
    GumV8File * module);
static void gum_file_free (GumFile * file);
static gboolean gum_file_check_open (GumFile * self, Isolate * isolate);
static void gum_file_close (GumFile * self);
static void gum_file_on_weak_notify (const WeakCallbackInfo<GumFile> & info);

static const GumV8Function gumjs_file_functions[] =
{
  { "write", gumjs_file_write },
  { "flush", gumjs_file_flush },
  { "close", gumjs_file_close },

  { NULL, NULL }
};

void
_gum_v8_file_init (GumV8File * self,
                   GumV8Core * core,
                   Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto file = _gum_v8_create_class ("File", gumjs_file_construct, scope,
      module, isolate);
  _gum_v8_class_add (file, gumjs_file_functions, module, isolate);
}

void
_gum_v8_file_realize (GumV8File * self)
{
  self->files = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_file_free);
}

void
_gum_v8_file_dispose (GumV8File * self)
{
  g_hash_table_unref (self->files);
  self->files = NULL;
}

void
_gum_v8_file_finalize (GumV8File * self)
{
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_file_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new File()` to create a new instance");
    return;
  }

  gchar * filename, * mode;
  if (!_gum_v8_args_parse (args, "ss", &filename, &mode))
    return;

  auto handle = fopen (filename, mode);

  g_free (filename);
  g_free (mode);

  if (handle == NULL)
  {
    _gum_v8_throw (isolate, "failed to open file (%s)", g_strerror (errno));
    return;
  }

  auto file = gum_file_new (wrapper, handle, module);
  wrapper->SetAlignedPointerInInternalField (0, file);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_file_write, GumFile)
{
  if (!gum_file_check_open (self, isolate))
    return;

  GBytes * bytes;
  if (!_gum_v8_args_parse (args, "B~", &bytes))
    return;

  gsize size;
  auto data = g_bytes_get_data (bytes, &size);
  fwrite (data, size, 1, self->handle);

  g_bytes_unref (bytes);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_file_flush, GumFile)
{
  if (!gum_file_check_open (self, isolate))
    return;

  fflush (self->handle);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_file_close, GumFile)
{
  if (!gum_file_check_open (self, isolate))
    return;

  gum_file_close (self);
}

static GumFile *
gum_file_new (Local<Object> wrapper,
              FILE * handle,
              GumV8File * module)
{
  auto file = g_slice_new (GumFile);
  file->wrapper =
      new GumPersistent<Object>::type (module->core->isolate, wrapper);
  file->wrapper->SetWeak (file, gum_file_on_weak_notify,
      WeakCallbackType::kParameter);
  file->handle = handle;
  file->module = module;

  g_hash_table_add (module->files, file);

  return file;
}

static void
gum_file_free (GumFile * self)
{
  gum_file_close (self);

  delete self->wrapper;

  g_slice_free (GumFile, self);
}

static gboolean
gum_file_check_open (GumFile * self,
                     Isolate * isolate)
{
  if (self->handle == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate, "file is closed");
    return FALSE;
  }

  return TRUE;
}

static void
gum_file_close (GumFile * self)
{
  g_clear_pointer (&self->handle, fclose);
}

static void
gum_file_on_weak_notify (const WeakCallbackInfo<GumFile> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->files, self);
}
