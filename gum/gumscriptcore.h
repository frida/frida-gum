/*
 * Copyright (C) 2010-2014 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#ifndef __GUM_SCRIPT_CORE_H__
#define __GUM_SCRIPT_CORE_H__

#define GUM_NATIVE_POINTER_VALUE(o) \
    (o)->GetInternalField (0).As<External> ()->Value ()

#include "gumscript.h"

#include <v8.h>

typedef struct _GumScriptCore GumScriptCore;

typedef struct _GumScheduledCallback GumScheduledCallback;
typedef struct _GumMessageSink GumMessageSink;

typedef struct _GumHeapBlock GumHeapBlock;
typedef struct _GumByteArray GumByteArray;

template <typename T>
struct GumPersistent
{
  typedef v8::Persistent<T, v8::CopyablePersistentTraits<T> > type;
};

struct _GumScriptCore
{
  GumScript * script;
  GMainContext * main_context;
  v8::Isolate * isolate;

  GMutex * mutex;

  GCond * event_cond;
  guint event_count;

  GumScriptMessageHandler message_handler_func;
  gpointer message_handler_data;
  GDestroyNotify message_handler_notify;

  GumMessageSink * incoming_message_sink;

  GHashTable * weak_refs;
  volatile gint last_weak_ref_id;

  GSList * scheduled_callbacks;
  volatile gint last_callback_id;

  GumPersistent<v8::FunctionTemplate>::type * native_pointer;
  GumPersistent<v8::Object>::type * native_pointer_value;
};

struct _GumHeapBlock
{
  GumPersistent<v8::Object>::type * instance;
  gpointer data;
  gsize size;
  v8::Isolate * isolate;
};

struct _GumByteArray
{
  GumPersistent<v8::Object>::type * instance;
  gpointer data;
  gsize size;
  v8::Isolate * isolate;
};

G_GNUC_INTERNAL void _gum_script_core_init (GumScriptCore * self,
    GumScript * script, GMainContext * main_context, v8::Isolate * isolate,
    v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_core_realize (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_flush (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_dispose (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_finalize (GumScriptCore * self);

G_GNUC_INTERNAL void _gum_script_core_set_message_handler (GumScriptCore * self,
    GumScriptMessageHandler func, gpointer data, GDestroyNotify notify);
G_GNUC_INTERNAL void _gum_script_core_emit_message (GumScriptCore * self,
    const gchar * message, const guint8 * data, gint data_length);
G_GNUC_INTERNAL void _gum_script_core_post_message (GumScriptCore * self,
    const gchar * message);

G_GNUC_INTERNAL GumByteArray * _gum_byte_array_new (gpointer data, gsize size,
    GumScriptCore * core);
G_GNUC_INTERNAL void _gum_byte_array_free (GumByteArray * buffer);

G_GNUC_INTERNAL GumHeapBlock * _gum_heap_block_new (gpointer data,
    gsize size, GumScriptCore * core);
G_GNUC_INTERNAL void _gum_heap_block_free (GumHeapBlock * block);

G_GNUC_INTERNAL v8::Local<v8::Object> _gum_script_pointer_new (gpointer address,
    GumScriptCore * core);
G_GNUC_INTERNAL gboolean _gum_script_pointer_get (v8::Handle<v8::Value> value,
    gpointer * target, GumScriptCore * core);

G_GNUC_INTERNAL gboolean _gum_script_callbacks_get (
    v8::Handle<v8::Object> callbacks, const gchar * name,
    v8::Handle<v8::Function> * callback_function, GumScriptCore * core);
G_GNUC_INTERNAL gboolean _gum_script_callbacks_get_opt (
    v8::Handle<v8::Object> callbacks, const gchar * name,
    v8::Handle<v8::Function> * callback_function, GumScriptCore * core);

G_GNUC_INTERNAL v8::Handle<v8::Object> _gum_script_cpu_context_to_object (
    const GumCpuContext * ctx, GumScriptCore * core);

G_GNUC_INTERNAL gboolean _gum_script_page_protection_get (
    v8::Handle<v8::Value> prot_val, GumPageProtection * prot,
    GumScriptCore * core);

#endif
