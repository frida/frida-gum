/*
 * Copyright (C) 2020-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickfile.h"

#include "gumquickmacros.h"

#include <errno.h>
#include <string.h>

typedef struct _GumFile GumFile;

struct _GumFile
{
  FILE * handle;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_file_construct)
GUMJS_DECLARE_FINALIZER (gumjs_file_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_file_write)
GUMJS_DECLARE_FUNCTION (gumjs_file_flush)
GUMJS_DECLARE_FUNCTION (gumjs_file_close)

static GumFile * gum_file_new (FILE * handle);
static void gum_file_free (GumFile * self);
static void gum_file_close (GumFile * self);

static const JSClassDef gumjs_file_def =
{
  .class_name = "File",
  .finalizer = gumjs_file_finalize,
};

static const JSCFunctionListEntry gumjs_file_entries[] =
{
  JS_CFUNC_DEF ("write", 0, gumjs_file_write),
  JS_CFUNC_DEF ("flush", 0, gumjs_file_flush),
  JS_CFUNC_DEF ("close", 0, gumjs_file_close),
};

void
_gum_quick_file_init (GumQuickFile * self,
                      JSValue ns,
                      GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue proto, ctor;

  self->core = core;

  _gum_quick_core_store_module_data (core, "file", self);

  _gum_quick_create_class (ctx, &gumjs_file_def, core, &self->file_class,
      &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_file_construct,
      gumjs_file_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_file_entries,
      G_N_ELEMENTS (gumjs_file_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_file_def.class_name, ctor,
      JS_PROP_C_W_E);
}

void
_gum_quick_file_dispose (GumQuickFile * self)
{
}

void
_gum_quick_file_finalize (GumQuickFile * self)
{
}

static GumQuickFile *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "file");
}

static gboolean
gum_file_get (JSContext * ctx,
              JSValueConst val,
              GumQuickCore * core,
              GumFile ** file)
{
  GumFile * f;

  if (!_gum_quick_unwrap (ctx, val, gumjs_get_parent_module (core)->file_class,
      core, (gpointer *) &f))
    return FALSE;

  if (f->handle == NULL)
  {
    _gum_quick_throw_literal (ctx, "file is closed");
    return FALSE;
  }

  *file = f;
  return TRUE;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_file_construct)
{
  JSValue wrapper = JS_NULL;
  const gchar * filename, * mode;
  JSValue proto;
  FILE * handle;
  GumFile * file;

  if (!_gum_quick_args_parse (args, "ss", &filename, &mode))
    goto propagate_exception;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto,
      gumjs_get_parent_module (core)->file_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  handle = fopen (filename, mode);
  if (handle == NULL)
    goto fopen_failed;

  file = gum_file_new (handle);

  JS_SetOpaque (wrapper, file);

  return wrapper;

fopen_failed:
  {
    _gum_quick_throw (ctx, "failed to open file (%s)", g_strerror (errno));
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeValue (ctx, wrapper);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_file_finalize)
{
  GumFile * f;

  f = JS_GetOpaque (val, gumjs_get_parent_module (core)->file_class);
  if (f == NULL)
    return;

  gum_file_free (f);
}

GUMJS_DEFINE_FUNCTION (gumjs_file_write)
{
  GumFile * self;
  GBytes * bytes;
  gconstpointer data;
  gsize size;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "B~", &bytes))
    return JS_EXCEPTION;

  data = g_bytes_get_data (bytes, &size);
  fwrite (data, size, 1, self->handle);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_flush)
{
  GumFile * self;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  fflush (self->handle);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_close)
{
  GumFile * self;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  gum_file_close (self);

  return JS_UNDEFINED;
}

static GumFile *
gum_file_new (FILE * handle)
{
  GumFile * file;

  file = g_slice_new (GumFile);
  file->handle = handle;

  return file;
}

static void
gum_file_free (GumFile * self)
{
  gum_file_close (self);

  g_slice_free (GumFile, self);
}

static void
gum_file_close (GumFile * self)
{
  g_clear_pointer (&self->handle, fclose);
}
