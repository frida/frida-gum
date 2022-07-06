/*
 * Copyright (C) 2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8checksum.h"

#include "gumv8macros.h"

#define GUMJS_MODULE_NAME Checksum

using namespace v8;

struct GumChecksum
{
  GumPersistent<Object>::type * wrapper;
  GChecksum * handle;
  GChecksumType type;
  gboolean closed;
  GumV8Checksum * module;
};

GUMJS_DECLARE_FUNCTION (gumjs_checksum_compute)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_checksum_construct)
GUMJS_DECLARE_FUNCTION (gumjs_checksum_update)
GUMJS_DECLARE_FUNCTION (gumjs_checksum_get_string)
GUMJS_DECLARE_FUNCTION (gumjs_checksum_get_digest)

static GumChecksum * gum_checksum_new (Local<Object> wrapper,
    GChecksumType type, GumV8Checksum * module);
static void gum_checksum_free (GumChecksum * self);
static void gum_checksum_on_weak_notify (
    const WeakCallbackInfo<GumChecksum> & info);

static gboolean gum_v8_checksum_type_get (Isolate * isolate, const gchar * name,
    GChecksumType * type);

static const GumV8Function gumjs_checksum_module_functions[] =
{
  { "compute", gumjs_checksum_compute },

  { NULL, NULL }
};

static const GumV8Function gumjs_checksum_functions[] =
{
  { "update", gumjs_checksum_update },
  { "getString", gumjs_checksum_get_string },
  { "getDigest", gumjs_checksum_get_digest },

  { NULL, NULL }
};

void
_gum_v8_checksum_init (GumV8Checksum * self,
                       GumV8Core * core,
                       Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto checksum = _gum_v8_create_class ("Checksum", gumjs_checksum_construct,
      scope, module, isolate);
  _gum_v8_class_add_static (checksum, gumjs_checksum_module_functions, module,
      isolate);
  _gum_v8_class_add (checksum, gumjs_checksum_functions, module, isolate);
}

void
_gum_v8_checksum_realize (GumV8Checksum * self)
{
  self->checksums = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_checksum_free);
}

void
_gum_v8_checksum_dispose (GumV8Checksum * self)
{
  g_hash_table_unref (self->checksums);
  self->checksums = NULL;
}

void
_gum_v8_checksum_finalize (GumV8Checksum * self)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_checksum_compute)
{
  if (info.Length () < 2)
  {
    _gum_v8_throw_ascii_literal (isolate, "missing argument");
    return;
  }

  gchar * type_str, * str;
  GBytes * bytes;
  auto data_val = info[1];
  if (data_val->IsString ())
  {
    if (!_gum_v8_args_parse (args, "ss", &type_str, &str))
      return;
    bytes = NULL;
  }
  else
  {
    if (!_gum_v8_args_parse (args, "sB", &type_str, &bytes))
      return;
    str = NULL;
  }

  GChecksumType type;
  if (!gum_v8_checksum_type_get (isolate, type_str, &type))
    goto beach;

  gchar * result_str;
  if (str != NULL)
    result_str = g_compute_checksum_for_string (type, str, -1);
  else
    result_str = g_compute_checksum_for_bytes (type, bytes);

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, result_str));

  g_free (result_str);

beach:
  g_bytes_unref (bytes);
  g_free (str);
  g_free (type_str);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_checksum_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new Checksum()` to create a new instance");
    return;
  }

  gchar * type_str;
  if (!_gum_v8_args_parse (args, "s", &type_str))
    return;

  GChecksumType type;
  if (!gum_v8_checksum_type_get (isolate, type_str, &type))
  {
    g_free (type_str);
    return;
  }

  auto checksum = gum_checksum_new (wrapper, type, module);
  wrapper->SetAlignedPointerInInternalField (0, checksum);

  g_free (type_str);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_checksum_update, GumChecksum)
{
  if (self->closed)
  {
    _gum_v8_throw_ascii_literal (isolate, "checksum is closed");
    return;
  }

  if (info.Length () < 1)
  {
    _gum_v8_throw_ascii_literal (isolate, "missing argument");
    return;
  }

  gchar * str;
  GBytes * bytes;
  auto data_val = info[0];
  if (data_val->IsString ())
  {
    if (!_gum_v8_args_parse (args, "s", &str))
      return;
    bytes = NULL;
  }
  else
  {
    if (!_gum_v8_args_parse (args, "B", &bytes))
      return;
    str = NULL;
  }

  if (str != NULL)
  {
    g_checksum_update (self->handle, (const guchar *) str, -1);
  }
  else
  {
    gconstpointer data;
    gsize size;

    data = g_bytes_get_data (bytes, &size);

    g_checksum_update (self->handle, (const guchar *) data, size);
  }

  g_bytes_unref (bytes);
  g_free (str);

  info.GetReturnValue ().Set (info.This ());
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_checksum_get_string, GumChecksum)
{
  self->closed = TRUE;

  info.GetReturnValue ().Set (
      _gum_v8_string_new_ascii (isolate, g_checksum_get_string (self->handle)));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_checksum_get_digest, GumChecksum)
{
  self->closed = TRUE;

  size_t length = g_checksum_type_get_length (self->type);
  auto result = ArrayBuffer::New (isolate, length);
  auto store = result.As<ArrayBuffer> ()->GetBackingStore ();

  g_checksum_get_digest (self->handle, (guint8 *) store->Data (), &length);

  info.GetReturnValue ().Set (result);
}

static GumChecksum *
gum_checksum_new (Local<Object> wrapper,
                  GChecksumType type,
                  GumV8Checksum * module)
{
  auto cs = g_slice_new (GumChecksum);
  cs->wrapper =
      new GumPersistent<Object>::type (module->core->isolate, wrapper);
  cs->wrapper->SetWeak (cs, gum_checksum_on_weak_notify,
      WeakCallbackType::kParameter);
  cs->handle = g_checksum_new (type);
  cs->type = type;
  cs->closed = FALSE;
  cs->module = module;

  g_hash_table_add (module->checksums, cs);

  return cs;
}

static void
gum_checksum_free (GumChecksum * self)
{
  g_checksum_free (self->handle);

  delete self->wrapper;

  g_slice_free (GumChecksum, self);
}

static void
gum_checksum_on_weak_notify (const WeakCallbackInfo<GumChecksum> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->checksums, self);
}

static gboolean
gum_v8_checksum_type_get (Isolate * isolate,
                          const gchar * name,
                          GChecksumType * type)
{
  if (strcmp (name, "sha256") == 0)
    *type = G_CHECKSUM_SHA256;
  else if (strcmp (name, "sha384") == 0)
    *type = G_CHECKSUM_SHA384;
  else if (strcmp (name, "sha512") == 0)
    *type = G_CHECKSUM_SHA512;
  else if (strcmp (name, "sha1") == 0)
    *type = G_CHECKSUM_SHA1;
  else if (strcmp (name, "md5") == 0)
    *type = G_CHECKSUM_MD5;
  else
    goto invalid_type;

  return TRUE;

invalid_type:
  _gum_v8_throw_ascii_literal (isolate, "unsupported checksum type");
  return FALSE;
}
