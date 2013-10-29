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

#include "gumscriptprocess.h"

#include <string.h>

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_SCRIPT_ARCH "ia32"
# else
#  define GUM_SCRIPT_ARCH "x64"
# endif
#elif defined (HAVE_ARM)
# define GUM_SCRIPT_ARCH "arm"
#endif

#if defined (HAVE_LINUX)
# define GUM_SCRIPT_PLATFORM "linux"
#elif defined (HAVE_DARWIN)
# define GUM_SCRIPT_PLATFORM "darwin"
#elif defined (G_OS_WIN32)
# define GUM_SCRIPT_PLATFORM "windows"
#endif

using namespace v8;

typedef struct _GumScriptMatchContext GumScriptMatchContext;

struct _GumScriptMatchContext
{
  GumScriptProcess * self;
  Local<Function> on_match;
  Local<Function> on_complete;
  Local<Object> receiver;
};

static Handle<Value> gum_script_process_on_get_current_thread_id (
    const Arguments & args);
static Handle<Value> gum_script_process_on_enumerate_threads (
    const Arguments & args);
static gboolean gum_script_process_thread_match (GumThreadDetails * details,
    gpointer user_data);
static const gchar * gum_script_thread_state_to_string (GumThreadState state);
static Handle<Value> gum_script_process_on_enumerate_modules (
    const Arguments & args);
static gboolean gum_script_process_handle_module_match (const gchar * name,
    const GumMemoryRange * range, const gchar * path, gpointer user_data);
static Handle<Value> gum_script_process_on_enumerate_ranges (
    const Arguments & args);
static gboolean gum_script_process_handle_range_match (const GumMemoryRange * range,
    GumPageProtection prot, gpointer user_data);

void
_gum_script_process_init (GumScriptProcess * self,
                          GumScriptCore * core,
                          Handle<ObjectTemplate> scope)
{
  self->core = core;

  Handle<ObjectTemplate> process = ObjectTemplate::New ();
  process->Set (String::New ("arch"),
      String::New (GUM_SCRIPT_ARCH), ReadOnly);
  process->Set (String::New ("platform"),
      String::New (GUM_SCRIPT_PLATFORM), ReadOnly);
  process->Set (String::New ("getCurrentThreadId"),
      FunctionTemplate::New (gum_script_process_on_get_current_thread_id));
  process->Set (String::New ("enumerateThreads"),
      FunctionTemplate::New (gum_script_process_on_enumerate_threads,
      External::Wrap (self)));
  process->Set (String::New ("enumerateModules"),
      FunctionTemplate::New (gum_script_process_on_enumerate_modules,
      External::Wrap (self)));
  process->Set (String::New ("enumerateRanges"),
      FunctionTemplate::New (gum_script_process_on_enumerate_ranges,
      External::Wrap (self)));
  scope->Set (String::New ("Process"), process);
}

void
_gum_script_process_realize (GumScriptProcess * self)
{
}

void
_gum_script_process_dispose (GumScriptProcess * self)
{
}

void
_gum_script_process_finalize (GumScriptProcess * self)
{
}

static Handle<Value>
gum_script_process_on_get_current_thread_id (const Arguments & args)
{
  (void) args;

  return Number::New (gum_process_get_current_thread_id ());
}

static Handle<Value>
gum_script_process_on_enumerate_threads (const Arguments & args)
{
  GumScriptMatchContext ctx;

  ctx.self = static_cast<GumScriptProcess *> (External::Unwrap (args.Data ()));

  Local<Value> callbacks_value = args[0];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Process.enumerateThreads: argument must be a callback object")));
    return Undefined ();
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match))
    return Undefined ();
  if (!_gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete))
    return Undefined ();

  ctx.receiver = args.This ();

  gum_process_enumerate_threads (gum_script_process_thread_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);

  return Undefined ();
}

static gboolean
gum_script_process_thread_match (GumThreadDetails * details,
                                 gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);

  Local<Object> thread (Object::New ());
  thread->Set (String::New ("id"), Number::New (details->id), ReadOnly);
  thread->Set (String::New ("state"),
      String::New (gum_script_thread_state_to_string (details->state)),
      ReadOnly);
  thread->Set (String::New ("registers"),
      _gum_script_cpu_context_to_object (ctx->self->core,
          &details->cpu_context),
      ReadOnly);
  Handle<Value> argv[] = { thread };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 1, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

static const gchar *
gum_script_thread_state_to_string (GumThreadState state)
{
  switch (state)
  {
    case GUM_THREAD_RUNNING: return "running";
    case GUM_THREAD_STOPPED: return "stopped";
    case GUM_THREAD_WAITING: return "waiting";
    case GUM_THREAD_UNINTERRUPTIBLE: return "uninterruptible";
    case GUM_THREAD_HALTED: return "halted";
    default:
      break;
  }

  g_assert_not_reached ();
  return NULL;
}

static Handle<Value>
gum_script_process_on_enumerate_modules (const Arguments & args)
{
  GumScriptMatchContext ctx;

  ctx.self = static_cast<GumScriptProcess *> (External::Unwrap (args.Data ()));

  Local<Value> callbacks_value = args[0];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Process.enumerateModules: argument must be a callback object")));
    return Undefined ();
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match))
    return Undefined ();
  if (!_gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete))
    return Undefined ();

  ctx.receiver = args.This ();

  gum_process_enumerate_modules (gum_script_process_handle_module_match, &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);

  return Undefined ();
}

static gboolean
gum_script_process_handle_module_match (const gchar * name,
                                        const GumMemoryRange * range,
                                        const gchar * path,
                                        gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);

  Handle<Value> argv[] = {
    String::New (name),
    _gum_script_pointer_new (ctx->self->core,
        GSIZE_TO_POINTER (range->base_address)),
    Integer::NewFromUnsigned (range->size),
    String::New (path)
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 4, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

static Handle<Value>
gum_script_process_on_enumerate_ranges (const Arguments & args)
{
  GumScriptMatchContext ctx;

  ctx.self = static_cast<GumScriptProcess *> (External::Unwrap (args.Data ()));

  GumPageProtection prot;
  if (!_gum_script_page_protection_get (args[0], &prot))
    return Undefined ();

  Local<Value> callbacks_value = args[1];
  if (!callbacks_value->IsObject ())
  {
    ThrowException (Exception::TypeError (String::New (
        "Process.enumerateRanges: second argument must be a callback object")));
    return Undefined ();
  }

  Local<Object> callbacks = Local<Object>::Cast (callbacks_value);
  if (!_gum_script_callbacks_get (callbacks, "onMatch", &ctx.on_match))
    return Undefined ();
  if (!_gum_script_callbacks_get (callbacks, "onComplete", &ctx.on_complete))
    return Undefined ();

  ctx.receiver = args.This ();

  gum_process_enumerate_ranges (prot, gum_script_process_handle_range_match,
      &ctx);

  ctx.on_complete->Call (ctx.receiver, 0, 0);

  return Undefined ();
}

static gboolean
gum_script_process_handle_range_match (const GumMemoryRange * range,
                                       GumPageProtection prot,
                                       gpointer user_data)
{
  GumScriptMatchContext * ctx =
      static_cast<GumScriptMatchContext *> (user_data);

  char prot_str[4] = "---";
  if ((prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  Handle<Value> argv[] = {
    _gum_script_pointer_new (ctx->self->core,
        GSIZE_TO_POINTER (range->base_address)),
    Integer::NewFromUnsigned (range->size),
    String::New (prot_str)
  };
  Local<Value> result = ctx->on_match->Call (ctx->receiver, 3, argv);

  gboolean proceed = TRUE;
  if (!result.IsEmpty () && result->IsString ())
  {
    String::Utf8Value str (result);
    proceed = (strcmp (*str, "stop") != 0);
  }

  return proceed;
}

