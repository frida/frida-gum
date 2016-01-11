/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukfile.h"

#include "gumdukmacros.h"

#include <errno.h>
#include <string.h>

#define GUMJS_FILE(o) \
  ((GumFile *) _gumjs_get_private_data (ctx, o))

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

static const duk_function_list_entry gumjs_file_functions[] =
{
  { "write", gumjs_file_write, 1 },
  { "flush", gumjs_file_flush, 0 },
  { "close", gumjs_file_close, 0 },

  { NULL, NULL, 0 }
};

void
_gum_duk_file_init (GumDukFile * self,
                    GumDukCore * core)
{
  duk_context * ctx = core->ctx;

  self->core = core;

  duk_push_c_function (ctx, gumjs_file_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_file_functions);
  duk_push_c_function (ctx, gumjs_file_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->file = _gumjs_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "File");
}

void
_gum_duk_file_dispose (GumDukFile * self)
{
  _gumjs_duk_release_heapptr (self->core->ctx, self->file);
}

void
_gum_duk_file_finalize (GumDukFile * self)
{
  (void) self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_file_construct)
{
  const gchar * filename;
  const gchar * mode;
  FILE * handle;
  GumFile * file;

  if (!duk_is_constructor_call (ctx))
  {
    duk_push_error_object (ctx, DUK_ERR_ERROR,
        "Use `new File()` to create a new instance");
    duk_throw (ctx);
  }

  _gum_duk_require_args (ctx, "ss", &filename, &mode);

  handle = fopen (filename, mode);
  if (handle == NULL)
    _gumjs_throw (ctx, "failed to open file (%s)", strerror (errno));

  file = g_slice_new (GumFile);
  file->handle = handle;

  _gumjs_set_private_data (ctx, _gumjs_duk_get_this (ctx), file);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_file_finalize)
{
  GumFile * self;

  if (_gumjs_is_arg0_equal_to_prototype (ctx, "File"))
    return 0;

  self = _gumjs_steal_private_data (ctx, duk_require_heapptr (ctx, 0));
  if (self == NULL)
    return 0;

  gum_file_close (self);

  g_slice_free (GumFile, self);

  return 0;
}

static void
gum_file_check_open (GumFile * self,
                     duk_context * ctx)
{
  if (self->handle == NULL)
    _gumjs_throw (ctx, "file is closed");
}

static void
gum_file_close (GumFile * self)
{
  g_clear_pointer (&self->handle, fclose);
}

GUMJS_DEFINE_FUNCTION (gumjs_file_write)
{
  GumFile * self;
  GumDukHeapPtr value;
  GBytes * bytes;

  self = GUMJS_FILE (_gumjs_duk_get_this (ctx));

  _gum_duk_require_args (ctx, "V", &value);

  gum_file_check_open (self, ctx);

  duk_push_heapptr (ctx, value);
  if (duk_is_string (ctx, -1))
  {
    const gchar * str;

    str = duk_get_string (ctx, -1);

    fwrite (str, strlen (str), 1, self->handle);
  }
  else if (_gum_duk_parse_bytes (ctx, -1, &bytes))
  {
    gconstpointer data;
    gsize size;

    data = g_bytes_get_data (bytes, &size);
    fwrite (data, size, 1, self->handle);

    g_bytes_unref (bytes);
  }
  else
  {
    _gumjs_throw (ctx, "argument must be a string or byte array");
  }
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_flush)
{
  GumFile * self = GUMJS_FILE (_gumjs_duk_get_this (ctx));

  gum_file_check_open (self, ctx);

  fflush (self->handle);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_close)
{
  GumFile * self = GUMJS_FILE (_gumjs_duk_get_this (ctx));

  gum_file_check_open (self, ctx);

  gum_file_close (self);

  return 0;
}
