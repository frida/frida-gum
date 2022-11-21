/*
 * Copyright (C) 2020-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickfile.h"

#include "gumquickinterceptor.h"
#include "gumquickmacros.h"

#include <errno.h>
#include <string.h>

typedef struct _GumFile GumFile;

struct _GumFile
{
  FILE * handle;
};

GUMJS_DECLARE_FUNCTION (gumjs_file_read_all_bytes)
GUMJS_DECLARE_FUNCTION (gumjs_file_read_all_text)
GUMJS_DECLARE_FUNCTION (gumjs_file_write_all_bytes)
GUMJS_DECLARE_FUNCTION (gumjs_file_write_all_text)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_file_construct)
GUMJS_DECLARE_FINALIZER (gumjs_file_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_file_tell)
GUMJS_DECLARE_FUNCTION (gumjs_file_seek)
GUMJS_DECLARE_FUNCTION (gumjs_file_read_bytes)
GUMJS_DECLARE_FUNCTION (gumjs_file_read_text)
GUMJS_DECLARE_FUNCTION (gumjs_file_read_line)
GUMJS_DECLARE_FUNCTION (gumjs_file_write)
GUMJS_DECLARE_FUNCTION (gumjs_file_flush)
GUMJS_DECLARE_FUNCTION (gumjs_file_close)

static GumFile * gum_file_new (FILE * handle);
static void gum_file_free (GumFile * self);
static void gum_file_close (GumFile * self);
static gsize gum_file_query_num_bytes_available (GumFile * self);
static gboolean gum_file_set_contents (const gchar * filename,
    const gchar * contents, gssize length, GError ** error);

static const JSClassDef gumjs_file_def =
{
  .class_name = "File",
  .finalizer = gumjs_file_finalize,
};

static const JSCFunctionListEntry gumjs_file_module_entries[] =
{
  JS_PROP_INT32_DEF ("SEEK_SET", SEEK_SET, JS_PROP_C_W_E),
  JS_PROP_INT32_DEF ("SEEK_CUR", SEEK_CUR, JS_PROP_C_W_E),
  JS_PROP_INT32_DEF ("SEEK_END", SEEK_END, JS_PROP_C_W_E),

  JS_CFUNC_DEF ("readAllBytes", 0, gumjs_file_read_all_bytes),
  JS_CFUNC_DEF ("readAllText", 0, gumjs_file_read_all_text),
  JS_CFUNC_DEF ("writeAllBytes", 0, gumjs_file_write_all_bytes),
  JS_CFUNC_DEF ("writeAllText", 0, gumjs_file_write_all_text),
};

static const JSCFunctionListEntry gumjs_file_entries[] =
{
  JS_CFUNC_DEF ("tell", 0, gumjs_file_tell),
  JS_CFUNC_DEF ("seek", 0, gumjs_file_seek),
  JS_CFUNC_DEF ("readBytes", 0, gumjs_file_read_bytes),
  JS_CFUNC_DEF ("readText", 0, gumjs_file_read_text),
  JS_CFUNC_DEF ("readLine", 0, gumjs_file_read_line),
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
  JS_SetPropertyFunctionList (ctx, ctor, gumjs_file_module_entries,
      G_N_ELEMENTS (gumjs_file_module_entries));
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

GUMJS_DEFINE_FUNCTION (gumjs_file_read_all_bytes)
{
  const gchar * filename;
  gchar * contents;
  gsize length;
  GError * error;

  if (!_gum_quick_args_parse (args, "s", &filename))
    return JS_EXCEPTION;

  error = NULL;
  if (!g_file_get_contents (filename, &contents, &length, &error))
    goto propagate_error;

  return JS_NewArrayBuffer (ctx, (uint8_t *) contents, length,
      _gum_quick_array_buffer_free, contents, FALSE);

propagate_error:
  {
    _gum_quick_throw_literal (ctx, error->message);
    g_error_free (error);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_file_read_all_text)
{
  JSValue result;
  const gchar * filename;
  gchar * contents;
  gsize length;
  GError * error;
  const gchar * end;

  if (!_gum_quick_args_parse (args, "s", &filename))
    return JS_EXCEPTION;

  error = NULL;
  if (!g_file_get_contents (filename, &contents, &length, &error))
    goto propagate_error;

  if (g_utf8_validate (contents, length, &end))
  {
    result = JS_NewStringLen (ctx, contents, length);
  }
  else
  {
    result = _gum_quick_throw (ctx, "can't decode byte 0x%02x in position %u",
        (guint8) *end, (guint) (end - contents));
  }

  g_free (contents);

  return result;

propagate_error:
  {
    _gum_quick_throw_literal (ctx, error->message);
    g_error_free (error);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_file_write_all_bytes)
{
  const gchar * filename;
  GBytes * bytes;
  gconstpointer data;
  gsize size;
  GError * error;

  if (!_gum_quick_args_parse (args, "sB", &filename, &bytes))
    return JS_EXCEPTION;

  data = g_bytes_get_data (bytes, &size);

  error = NULL;
  if (!gum_file_set_contents (filename, data, size, &error))
    goto propagate_error;

  return JS_UNDEFINED;

propagate_error:
  {
    _gum_quick_throw_literal (ctx, error->message);
    g_error_free (error);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_file_write_all_text)
{
  const gchar * filename, * text;
  GError * error;

  if (!_gum_quick_args_parse (args, "ss", &filename, &text))
    return JS_EXCEPTION;

  error = NULL;
  if (!gum_file_set_contents (filename, text, -1, &error))
    goto propagate_error;

  return JS_UNDEFINED;

propagate_error:
  {
    _gum_quick_throw_literal (ctx, error->message);
    g_error_free (error);

    return JS_EXCEPTION;
  }
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
  GumInterceptor * interceptor = core->interceptor->interceptor;
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

  gum_interceptor_ignore_current_thread (interceptor);

  handle = fopen (filename, mode);

  gum_interceptor_unignore_current_thread (interceptor);

  if (handle == NULL)
    goto fopen_failed;

  file = gum_file_new (handle);

  JS_SetOpaque (wrapper, file);

  return wrapper;

fopen_failed:
  {
    _gum_quick_throw_literal (ctx, g_strerror (errno));
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

GUMJS_DEFINE_FUNCTION (gumjs_file_tell)
{
  GumFile * self;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewInt64 (ctx, ftell (self->handle));
}

GUMJS_DEFINE_FUNCTION (gumjs_file_seek)
{
  GumInterceptor * interceptor = core->interceptor->interceptor;
  GumFile * self;
  gssize offset;
  gint whence;
  int result;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  whence = SEEK_SET;
  if (!_gum_quick_args_parse (args, "z|i", &offset, &whence))
    return JS_EXCEPTION;

  gum_interceptor_ignore_current_thread (interceptor);

  result = fseek (self->handle, offset, whence);

  gum_interceptor_unignore_current_thread (interceptor);

  if (result == -1)
    goto seek_failed;

  return JS_NewInt64 (ctx, result);

seek_failed:
  {
    return _gum_quick_throw_literal (ctx, strerror (errno));
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_file_read_bytes)
{
  GumInterceptor * interceptor = core->interceptor->interceptor;
  JSValue result;
  GumFile * self;
  gsize n;
  gpointer data;
  size_t num_bytes_read;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  n = G_MAXSIZE;
  if (!_gum_quick_args_parse (args, "|Z", &n))
    return JS_EXCEPTION;

  gum_interceptor_ignore_current_thread (interceptor);

  if (n == G_MAXSIZE)
    n = gum_file_query_num_bytes_available (self);

  if (n == 0)
  {
    gum_interceptor_unignore_current_thread (interceptor);
    return JS_NewArrayBufferCopy (ctx, NULL, 0);
  }

  data = g_malloc (n);
  result = JS_NewArrayBuffer (ctx, data, n, _gum_quick_array_buffer_free, data,
      FALSE);

  num_bytes_read = fread (data, 1, n, self->handle);

  gum_interceptor_unignore_current_thread (interceptor);

  if (num_bytes_read < n)
  {
    JSValue r;

    r = JS_NewArrayBufferCopy (ctx, data, num_bytes_read);
    JS_FreeValue (ctx, result);
    result = r;
  }

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_read_text)
{
  GumInterceptor * interceptor = core->interceptor->interceptor;
  JSValue result;
  GumFile * self;
  gsize n;
  gchar * data;
  size_t num_bytes_read;
  const gchar * end;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  n = G_MAXSIZE;
  if (!_gum_quick_args_parse (args, "|Z", &n))
    return JS_EXCEPTION;

  gum_interceptor_ignore_current_thread (interceptor);

  if (n == G_MAXSIZE)
    n = gum_file_query_num_bytes_available (self);

  if (n == 0)
  {
    gum_interceptor_unignore_current_thread (interceptor);
    return JS_NewString (ctx, "");
  }

  data = g_malloc (n);
  num_bytes_read = fread (data, 1, n, self->handle);

  gum_interceptor_unignore_current_thread (interceptor);

  if (g_utf8_validate (data, num_bytes_read, &end))
  {
    result = JS_NewStringLen (ctx, data, num_bytes_read);
  }
  else
  {
    result = _gum_quick_throw (ctx, "can't decode byte 0x%02x in position %u",
        (guint8) *end, (guint) (end - data));

    gum_interceptor_ignore_current_thread (interceptor);

    fseek (self->handle, -((long) num_bytes_read), SEEK_CUR);

    gum_interceptor_unignore_current_thread (interceptor);
  }

  g_free (data);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_read_line)
{
  GumInterceptor * interceptor = core->interceptor->interceptor;
  JSValue result;
  GumFile * self;
  gsize offset, capacity;
  GString * buffer;
  const gchar * end;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  offset = 0;
  capacity = 256;
  buffer = g_string_sized_new (capacity);

  gum_interceptor_ignore_current_thread (interceptor);

  while (TRUE)
  {
    gsize num_bytes_read;

    g_string_set_size (buffer, capacity);

    if (fgets (buffer->str + offset, capacity - offset, self->handle) == NULL)
      break;

    num_bytes_read = strlen (buffer->str + offset);
    offset += num_bytes_read;

    if (buffer->str[offset - 1] == '\n')
      break;

    if (offset == capacity - 1)
      capacity += 256;
    else
      break;
  }

  gum_interceptor_unignore_current_thread (interceptor);

  g_string_set_size (buffer, offset);

  if (g_utf8_validate (buffer->str, buffer->len, &end))
  {
    result = JS_NewStringLen (ctx, buffer->str, buffer->len);
  }
  else
  {
    result = _gum_quick_throw (ctx, "can't decode byte 0x%02x in position %u",
        (guint8) *end, (guint) (end - buffer->str));

    gum_interceptor_ignore_current_thread (interceptor);

    fseek (self->handle, -((long) buffer->len), SEEK_CUR);

    gum_interceptor_unignore_current_thread (interceptor);
  }

  g_string_free (buffer, TRUE);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_write)
{
  GumInterceptor * interceptor = core->interceptor->interceptor;
  GumFile * self;
  GBytes * bytes;
  gconstpointer data;
  gsize size;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "B~", &bytes))
    return JS_EXCEPTION;

  data = g_bytes_get_data (bytes, &size);

  gum_interceptor_ignore_current_thread (interceptor);

  fwrite (data, size, 1, self->handle);

  gum_interceptor_unignore_current_thread (interceptor);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_flush)
{
  GumInterceptor * interceptor = core->interceptor->interceptor;
  GumFile * self;

  if (!gum_file_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  gum_interceptor_ignore_current_thread (interceptor);

  fflush (self->handle);

  gum_interceptor_unignore_current_thread (interceptor);

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

static gsize
gum_file_query_num_bytes_available (GumFile * self)
{
  FILE * handle = self->handle;
  long offset, size;

  offset = ftell (handle);

  fseek (handle, 0, SEEK_END);
  size = ftell (handle);

  fseek (handle, offset, SEEK_SET);

  return size - offset;
}

static gboolean
gum_file_set_contents (const gchar * filename,
                       const gchar * contents,
                       gssize length,
                       GError ** error)
{
#if GLIB_CHECK_VERSION (2, 66, 0)
  return g_file_set_contents_full (filename, contents, length,
      G_FILE_SET_CONTENTS_NONE, 0666, error);
#else
  return g_file_set_contents (filename, contents, length, error);
#endif
}
