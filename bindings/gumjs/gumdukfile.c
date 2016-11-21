/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumdukfile.h"

#include "gumdukmacros.h"

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
static void gum_file_check_open (GumFile * self, duk_context * ctx);

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
  GumDukScope scope = GUM_DUK_SCOPE_INIT (core);
  duk_context * ctx = scope.ctx;

  self->core = core;

  duk_push_c_function (ctx, gumjs_file_construct, 2);
  duk_push_object (ctx);
  duk_put_function_list (ctx, -1, gumjs_file_functions);
  duk_push_c_function (ctx, gumjs_file_finalize, 1);
  duk_set_finalizer (ctx, -2);
  duk_put_prop_string (ctx, -2, "prototype");
  self->file = _gum_duk_require_heapptr (ctx, -1);
  duk_put_global_string (ctx, "File");
}

void
_gum_duk_file_dispose (GumDukFile * self)
{
  GumDukScope scope = GUM_DUK_SCOPE_INIT (self->core);

  _gum_duk_release_heapptr (scope.ctx, self->file);
}

void
_gum_duk_file_finalize (GumDukFile * self)
{
  (void) self;
}

static GumFile *
gumjs_file_from_args (const GumDukArgs * args)
{
  duk_context * ctx = args->ctx;
  GumFile * self;

  duk_push_this (ctx);
  self = _gum_duk_require_data (ctx, -1);
  duk_pop (ctx);

  return self;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_file_construct)
{
  const gchar * filename, * mode;
  FILE * handle;
  GumFile * file;

  if (!duk_is_constructor_call (ctx))
    _gum_duk_throw (ctx, "use `new File()` to create a new instance");

  _gum_duk_args_parse (args, "ss", &filename, &mode);

  handle = fopen (filename, mode);
  if (handle == NULL)
    _gum_duk_throw (ctx, "failed to open file (%s)", strerror (errno));

  file = gum_file_new (handle);

  duk_push_this (ctx);
  _gum_duk_put_data (ctx, -1, file);
  duk_pop (ctx);

  return 0;
}

GUMJS_DEFINE_FINALIZER (gumjs_file_finalize)
{
  GumFile * self;

  (void) args;

  if (_gum_duk_is_arg0_equal_to_prototype (ctx, "File"))
    return 0;

  self = _gum_duk_steal_data (ctx, 0);
  if (self == NULL)
    return 0;

  gum_file_free (self);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_write)
{
  GumFile * self;
  GBytes * bytes;
  gconstpointer data;
  gsize size;

  self = gumjs_file_from_args (args);

  gum_file_check_open (self, ctx);

  _gum_duk_args_parse (args, "B~", &bytes);

  data = g_bytes_get_data (bytes, &size);
  fwrite (data, size, 1, self->handle);

  g_bytes_unref (bytes);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_flush)
{
  GumFile * self = gumjs_file_from_args (args);

  gum_file_check_open (self, ctx);

  fflush (self->handle);

  return 0;
}

GUMJS_DEFINE_FUNCTION (gumjs_file_close)
{
  GumFile * self = gumjs_file_from_args (args);

  gum_file_check_open (self, ctx);

  gum_file_close (self);

  return 0;
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

static void
gum_file_check_open (GumFile * self,
                     duk_context * ctx)
{
  if (self->handle == NULL)
    _gum_duk_throw (ctx, "file is closed");
}
