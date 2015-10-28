/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptfile.h"

#include "gumjscriptmacros.h"

#include <errno.h>
#include <string.h>

#define GUMJS_FILE(o) \
  ((GumFile *) JSObjectGetPrivate (o))

typedef struct _GumFile GumFile;

struct _GumFile
{
  FILE * handle;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_file_construct)
GUMJS_DECLARE_FINALIZER (gumjs_file_finalize)
static void gum_file_close (GumFile * self);
GUMJS_DECLARE_FUNCTION (gumjs_file_write)
GUMJS_DECLARE_FUNCTION (gumjs_file_flush)
GUMJS_DECLARE_FUNCTION (gumjs_file_close)

static const JSStaticFunction gumjs_file_functions[] =
{
  { "write", gumjs_file_write, GUMJS_RO },
  { "flush", gumjs_file_flush, GUMJS_RO },
  { "close", gumjs_file_close, GUMJS_RO },

  { NULL, NULL, 0 }
};

void
_gum_script_file_init (GumScriptFile * self,
                       GumScriptCore * core,
                       JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef constructor;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "File";
  def.staticFunctions = gumjs_file_functions;
  def.finalize = gumjs_file_finalize;
  self->file = JSClassCreate (&def);

  def = kJSClassDefinitionEmpty;
  def.className = "FileConstructor";
  def.callAsConstructor = gumjs_file_construct;
  constructor = JSClassCreate (&def);
  _gumjs_object_set (ctx, scope, "File",
      JSObjectMake (ctx, constructor, self));
  JSClassRelease (constructor);
}

void
_gum_script_file_dispose (GumScriptFile * self)
{
  g_clear_pointer (&self->file, JSClassRelease);
}

void
_gum_script_file_finalize (GumScriptFile * self)
{
  (void) self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_file_construct)
{
  GumScriptFile * parent;
  JSObjectRef result = NULL;
  gchar * filename = NULL;
  gchar * mode = NULL;
  FILE * handle;
  GumFile * file;

  parent = JSObjectGetPrivate (constructor);

  if (!_gumjs_args_parse (args, "ss", &filename, &mode))
    goto beach;

  handle = fopen (filename, mode);
  if (handle == NULL)
    goto open_failed;

  file = g_slice_new (GumFile);
  file->handle = handle;

  result = JSObjectMake (ctx, parent->file, file);
  goto beach;

open_failed:
  {
    _gumjs_throw (ctx, exception, "failed to open file (%s)", strerror (errno));
    goto beach;
  }
beach:
  {
    g_free (mode);
    g_free (filename);

    return result;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_file_finalize)
{
  GumFile * file = GUMJS_FILE (object);

  gum_file_close (file);

  g_slice_free (GumFile, file);
}

static gboolean
gum_file_check_open (GumFile * self,
                     JSContextRef ctx,
                     JSValueRef * exception)
{
  if (self->handle == NULL)
  {
    _gumjs_throw (ctx, exception, "file is closed");
    return FALSE;
  }

  return TRUE;
}

static void
gum_file_close (GumFile * self)
{
  g_clear_pointer (&self->handle, fclose);
}

GUMJS_DEFINE_FUNCTION (gumjs_file_write)
{
  GumFile * self;
  JSValueRef value;
  gchar * str;
  GBytes * bytes;

  self = GUMJS_FILE (this_object);

  if (!_gumjs_args_parse (args, "V", &value))
    return NULL;

  if (!gum_file_check_open (self, ctx, exception))
    return NULL;

  if (_gumjs_string_try_get (ctx, value, &str, NULL))
  {
    fwrite (str, strlen (str), 1, self->handle);

    g_free (str);
  }
  else if (_gumjs_byte_array_try_get (ctx, value, &bytes, NULL))
  {
    gconstpointer data;
    gsize size;

    data = g_bytes_get_data (bytes, &size);
    fwrite (data, size, 1, self->handle);

    g_bytes_unref (bytes);
  }
  else
  {
    goto invalid_argument;
  }

  return JSValueMakeUndefined (ctx);

invalid_argument:
  {
    _gumjs_throw (ctx, exception, "argument must be a string or byte array");
    return NULL;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_file_flush)
{
  GumFile * self = GUMJS_FILE (this_object);

  if (!gum_file_check_open (self, ctx, exception))
    return NULL;

  fflush (self->handle);

  return JSValueMakeUndefined (ctx);
}

GUMJS_DEFINE_FUNCTION (gumjs_file_close)
{
  GumFile * self = GUMJS_FILE (this_object);

  if (!gum_file_check_open (self, ctx, exception))
    return NULL;

  gum_file_close (self);

  return JSValueMakeUndefined (ctx);
}
