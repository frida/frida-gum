/*
 * Copyright (C) 2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "gumscriptfile.h"

#include <errno.h>
#include <string.h>

using namespace v8;

static Handle<Value> gum_script_file_on_new_file (const Arguments & args);
static void gum_script_file_on_destroy (Persistent<Value> value, void * data);
static Handle<Value> gum_script_file_on_file_write (const Arguments & args);
static Handle<Value> gum_script_file_on_file_flush (const Arguments & args);
static Handle<Value> gum_script_file_on_file_close (const Arguments & args);

void
_gum_script_file_init (GumScriptFile * self,
                       GumScriptCore * core,
                       Handle<ObjectTemplate> scope)
{
  self->core = core;

  Local<FunctionTemplate> file = FunctionTemplate::New (
      gum_script_file_on_new_file);
  file->SetClassName (String::New ("File"));
  Local<ObjectTemplate> file_proto = file->PrototypeTemplate ();
  file_proto->Set (String::New ("write"),
      FunctionTemplate::New (gum_script_file_on_file_write,
      External::Wrap (self)));
  file_proto->Set (String::New ("flush"),
      FunctionTemplate::New (gum_script_file_on_file_flush,
      External::Wrap (self)));
  file_proto->Set (String::New ("close"),
      FunctionTemplate::New (gum_script_file_on_file_close,
      External::Wrap (self)));
  file->InstanceTemplate ()->SetInternalFieldCount (1);
  scope->Set (String::New ("File"), file);
}

void
_gum_script_file_realize (GumScriptFile * self)
{
}

void
_gum_script_file_dispose (GumScriptFile * self)
{
}

void
_gum_script_file_finalize (GumScriptFile * self)
{
}

static Handle<Value>
gum_script_file_on_new_file (const Arguments & args)
{
  Local<Value> filename_val = args[0];
  if (!filename_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
        "File: first argument must be a string specifying filename")));
    return Undefined ();
  }
  String::Utf8Value filename (filename_val);

  Local<Value> mode_val = args[1];
  if (!mode_val->IsString ())
  {
    ThrowException (Exception::TypeError (String::New (
        "File: second argument must be a string specifying mode")));
    return Undefined ();
  }
  String::Utf8Value mode (mode_val);

  FILE * file = fopen (*filename, *mode);
  if (file == NULL)
  {
    gchar * message = g_strdup_printf ("File: failed to open file (%s)",
        strerror (errno));
    ThrowException (Exception::TypeError (String::New (message)));
    g_free (message);
    return Undefined ();
  }

  Local<Object> instance (args.Holder ());
  instance->SetPointerInInternalField (0, file);

  Persistent<Object> persistent_instance (Persistent<Object>::New (instance));
  persistent_instance.MakeWeak (NULL, gum_script_file_on_destroy);
  persistent_instance.MarkIndependent ();

  return Undefined ();
}

static void
gum_script_file_on_destroy (Persistent<Value> value,
                            void * data)
{
  HandleScope handle_scope;
  Local<Object> object (value->ToObject ());
  FILE * file = static_cast<FILE *> (object->GetPointerFromInternalField (0));
  if (file != NULL)
    fclose (file);
  value.Dispose ();
}

static Handle<Value>
gum_script_file_on_file_write (const Arguments & args)
{
  FILE * file = static_cast<FILE *> (
      args.Holder ()->GetPointerFromInternalField (0));

  const gchar * data = NULL;
  gint data_length = 0;

  Local<Value> data_val = args[0];
  if (data_val->IsString ())
  {
    String::Utf8Value utf_val (data_val);
    data = *utf_val;
    data_length = utf_val.length ();
  }
  else if (data_val->IsObject () && !data_val->IsNull ())
  {
    Local<Object> array = data_val->ToObject ();
    if (array->HasIndexedPropertiesInExternalArrayData () &&
        array->GetIndexedPropertiesExternalArrayDataType ()
        == kExternalUnsignedByteArray)
    {
      data = static_cast<gchar *> (
          array->GetIndexedPropertiesExternalArrayData ());
      data_length = array->GetIndexedPropertiesExternalArrayDataLength ();
    }
  }

  if (data == NULL)
  {
    ThrowException (Exception::TypeError (String::New (
        "File.write: argument must be a string or raw byte array")));
    return Undefined ();
  }

  if (file != NULL)
  {
    fwrite (data, data_length, 1, file);
  }
  else
  {
    ThrowException (Exception::TypeError (String::New (
        "File.write: file is closed")));
  }

  return Undefined ();
}

static Handle<Value>
gum_script_file_on_file_flush (const Arguments & args)
{
  FILE * file = static_cast<FILE *> (
      args.Holder ()->GetPointerFromInternalField (0));

  if (file != NULL)
  {
    fflush (file);
  }
  else
  {
    ThrowException (Exception::TypeError (String::New (
        "File.flush: file is closed")));
  }

  return Undefined ();
}

static Handle<Value>
gum_script_file_on_file_close (const Arguments & args)
{
  FILE * file = static_cast<FILE *> (
      args.Holder ()->GetPointerFromInternalField (0));

  if (file != NULL)
  {
    fclose (file);
    args.Holder ()->SetPointerInInternalField (0, NULL);
  }
  else
  {
    ThrowException (Exception::TypeError (String::New (
        "File.close: file is already closed")));
  }

  return Undefined ();
}
