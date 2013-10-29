/*
 * Copyright (C) 2010-2013 Ole André Vadla Ravnås <ole.andre.ravnas@tillitech.com>
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

#include "gumscript.h"

#include <v8.h>

typedef struct _GumScriptCore GumScriptCore;

typedef struct _GumScheduledCallback GumScheduledCallback;
typedef struct _GumMessageSink GumMessageSink;

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

  GSList * scheduled_callbacks;
  volatile gint last_callback_id;

  v8::Persistent<v8::FunctionTemplate> native_pointer;
  v8::Persistent<v8::Object> native_pointer_value;
};

G_GNUC_INTERNAL void _gum_script_core_init (GumScriptCore * self,
    GumScript * script, GMainContext * main_context, v8::Isolate * isolate,
    v8::Handle<v8::ObjectTemplate> scope);
G_GNUC_INTERNAL void _gum_script_core_realize (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_dispose (GumScriptCore * self);
G_GNUC_INTERNAL void _gum_script_core_finalize (GumScriptCore * self);

G_GNUC_INTERNAL void _gum_script_core_set_message_handler (GumScriptCore * self,
    GumScriptMessageHandler func, gpointer data, GDestroyNotify notify);
G_GNUC_INTERNAL void _gum_script_core_emit_message (GumScriptCore * self,
    const gchar * message, const guint8 * data, gint data_length);
G_GNUC_INTERNAL void _gum_script_core_post_message (GumScriptCore * self,
    const gchar * message);

G_GNUC_INTERNAL v8::Handle<v8::Object> _gum_script_pointer_new (
    GumScriptCore * core, gpointer address);
G_GNUC_INTERNAL gboolean _gum_script_pointer_get (GumScriptCore * core,
    v8::Handle<v8::Value> value, gpointer * target);

G_GNUC_INTERNAL gboolean _gum_script_callbacks_get (
    v8::Handle<v8::Object> callbacks, const gchar * name,
    v8::Handle<v8::Function> * callback_function);
G_GNUC_INTERNAL gboolean _gum_script_callbacks_get_opt (
    v8::Handle<v8::Object> callbacks, const gchar * name,
    v8::Handle<v8::Function> * callback_function);

G_GNUC_INTERNAL v8::Handle<v8::Object> _gum_script_cpu_context_to_object (
    GumScriptCore * core, const GumCpuContext * ctx);

G_GNUC_INTERNAL gboolean _gum_script_page_protection_get (
    v8::Handle<v8::Value> prot_val, GumPageProtection * prot);

#endif
