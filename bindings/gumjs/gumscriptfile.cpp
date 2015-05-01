/*
 * Copyright (C) 2013-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptfile.h"

#include <errno.h>
#include <string.h>

using namespace v8;

typedef struct _GumFile GumFile;

struct _GumFile
{
  GumPersistent<v8::Object>::type * instance;
  FILE * handle;
  GumScriptFile * module;
};

static void gum_script_file_on_new_file (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_file_on_file_write (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_file_on_file_flush (
    const FunctionCallbackInfo<Value> & info);
static void gum_script_file_on_file_close (
    const FunctionCallbackInfo<Value> & info);

static GumFile * gum_file_new (Handle<Object> instance, FILE * handle,
    GumScriptFile * module);
static void gum_file_free (GumFile * file);
static gboolean gum_file_is_open (GumFile * self);
static void gum_file_close (GumFile * self);
static void gum_file_on_weak_notify (
    const WeakCallbackData<Object, GumFile> & data);

void
_gum_script_file_init (GumScriptFile * self,
                       GumScriptCore * core,
                       Handle<ObjectTemplate> scope)
{
  Isolate * isolate = core->isolate;

  self->core = core;

  Local<External> data (External::New (isolate, self));

  Local<FunctionTemplate> file = FunctionTemplate::New (isolate,
      gum_script_file_on_new_file, data);
  file->SetClassName (String::NewFromUtf8 (isolate, "File"));
  Local<ObjectTemplate> file_proto = file->PrototypeTemplate ();
  file_proto->Set (String::NewFromUtf8 (isolate, "write"),
      FunctionTemplate::New (isolate, gum_script_file_on_file_write, data));
  file_proto->Set (String::NewFromUtf8 (isolate, "flush"),
      FunctionTemplate::New (isolate, gum_script_file_on_file_flush, data));
  file_proto->Set (String::NewFromUtf8 (isolate, "close"),
      FunctionTemplate::New (isolate, gum_script_file_on_file_close, data));
  file->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::NewFromUtf8 (isolate, "File"), file);
}

void
_gum_script_file_realize (GumScriptFile * self)
{
  self->files = g_hash_table_new_full (NULL, NULL,
      NULL, reinterpret_cast<GDestroyNotify> (gum_file_free));
}

void
_gum_script_file_dispose (GumScriptFile * self)
{
  g_hash_table_unref (self->files);
  self->files = NULL;
}

void
_gum_script_file_finalize (GumScriptFile * self)
{
  (void) self;
}

static void
gum_script_file_on_new_file (const FunctionCallbackInfo<Value> & info)
{
  GumScriptFile * self = static_cast<GumScriptFile *> (
      info.Data ().As<External> ()->Value ());
  Isolate * isolate = self->core->isolate;

  if (!info.IsConstructCall ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "Use `new File()` to create a new instance")));
    return;
  }

  Local<Value> filename_val = info[0];
  if (!filename_val->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate, 
        "File: first argument must be a string specifying filename")));
    return;
  }
  String::Utf8Value filename (filename_val);

  Local<Value> mode_val = info[1];
  if (!mode_val->IsString ())
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate, 
        "File: second argument must be a string specifying mode")));
    return;
  }
  String::Utf8Value mode (mode_val);

  FILE * handle = fopen (*filename, *mode);
  if (handle == NULL)
  {
    gchar * message = g_strdup_printf ("File: failed to open file (%s)",
        strerror (errno));
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate,
        message)));
    g_free (message);
    return;
  }

  Local<Object> instance (info.Holder ());
  GumFile * file = gum_file_new (instance, handle, self);
  instance->SetAlignedPointerInInternalField (0, file);
}

/*
 * Prototype:
 * File.write(data_val)
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_script_file_on_file_write (const FunctionCallbackInfo<Value> & info)
{
  GumFile * file = static_cast<GumFile *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  Isolate * isolate = info.GetIsolate ();

  gboolean argument_valid = FALSE;
  const gchar * data = NULL;
  gint data_length = 0;

  Local<Value> data_val = info[0];
  if (data_val->IsString ())
  {
    argument_valid = TRUE;
  }
  else if (data_val->IsObject () && !data_val->IsNull ())
  {
    Local<Object> array = data_val->ToObject ();
    if (array->HasIndexedPropertiesInExternalArrayData () &&
        array->GetIndexedPropertiesExternalArrayDataType ()
        == kExternalUnsignedByteArray)
    {
      argument_valid = TRUE;
      data = static_cast<gchar *> (
          array->GetIndexedPropertiesExternalArrayData ());
      data_length = array->GetIndexedPropertiesExternalArrayDataLength ();
    }
  }

  if (!argument_valid)
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate, 
        "File.write: argument must be a string or raw byte array")));
    return;
  }

  if (gum_file_is_open (file))
  {
    if (data == NULL)
    {
      String::Utf8Value utf_val (data_val);
      fwrite (*utf_val, utf_val.length (), 1, file->handle);
    }
    else
    {
      fwrite (data, data_length, 1, file->handle);
    }
  }
  else
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (isolate, 
        "File.write: file is closed")));
  }
}

/*
 * Prototype:
 * File.flush()
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_script_file_on_file_flush (const FunctionCallbackInfo<Value> & info)
{
  GumFile * file = static_cast<GumFile *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  Isolate * isolate = info.GetIsolate ();

  if (gum_file_is_open (file))
  {
    fflush (file->handle);
  }
  else
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate, "File.flush: file is closed")));
  }
}

/*
 * Prototype:
 * File.close()
 *
 * Docs:
 * TBW
 *
 * Example:
 * TBW
 */
static void
gum_script_file_on_file_close (const FunctionCallbackInfo<Value> & info)
{
  GumFile * file = static_cast<GumFile *> (
      info.Holder ()->GetAlignedPointerFromInternalField (0));
  Isolate * isolate = info.GetIsolate ();

  if (gum_file_is_open (file))
  {
    gum_file_close (file);
  }
  else
  {
    isolate->ThrowException (Exception::TypeError (String::NewFromUtf8 (
        isolate,  "File.close: file is already closed")));
  }
}

static GumFile *
gum_file_new (Handle<Object> instance,
              FILE * handle,
              GumScriptFile * module)
{
  GumFile * file;

  file = g_slice_new (GumFile);
  file->instance =
      new GumPersistent<Object>::type (module->core->isolate, instance);
  file->instance->MarkIndependent ();
  file->instance->SetWeak (file, gum_file_on_weak_notify);
  file->handle = handle;
  file->module = module;

  g_hash_table_insert (module->files, handle, file);

  return file;
}

static void
gum_file_free (GumFile * file)
{
  gum_file_close (file);
  delete file->instance;
  g_slice_free (GumFile, file);
}

static gboolean
gum_file_is_open (GumFile * self)
{
  return self->handle != NULL;
}

static void
gum_file_close (GumFile * self)
{
  if (self->handle != NULL)
  {
    fclose (self->handle);
    self->handle = NULL;
  }
}

static void
gum_file_on_weak_notify (const WeakCallbackData<Object, GumFile> & data)
{
  HandleScope handle_scope (data.GetIsolate ());
  GumFile * self = data.GetParameter ();
  g_hash_table_remove (self->module->files, self->handle);
}
