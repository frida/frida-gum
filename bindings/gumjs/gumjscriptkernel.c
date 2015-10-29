/*
 * Copyright (C) 2015 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumjscriptkernel.h"

#include "gumjscriptmacros.h"

#include <gum/gumkernel.h>
#include <string.h>

typedef struct _GumScriptMatchContext GumScriptMatchContext;

struct _GumScriptMatchContext
{
  GumScriptKernel * self;
  JSObjectRef on_match;
  JSObjectRef on_complete;
  JSContextRef ctx;
};

GUMJS_DECLARE_FUNCTION (gumjs_kernel_enumerate_threads)
static gboolean gum_emit_thread (const GumThreadDetails * details,
    gpointer user_data);

GUMJS_DECLARE_FUNCTION (gumjs_kmemory_read_byte_array)
GUMJS_DECLARE_FUNCTION (gumjs_kmemory_write_byte_array)
GUMJS_DECLARE_FUNCTION (gumjs_kmemory_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    gpointer user_data);

static const JSStaticFunction gumjs_kernel_functions[] =
{
  { "enumerateThreads", gumjs_kernel_enumerate_threads, GUMJS_RO },

  { NULL, NULL, 0 }
};

static const JSStaticFunction gumjs_kmemory_functions[] =
{
  { "readByteArray", gumjs_kmemory_read_byte_array, GUMJS_RO },
  { "writeByteArray", gumjs_kmemory_write_byte_array, GUMJS_RO },
  { "_enumerateRanges", gumjs_kmemory_enumerate_ranges, GUMJS_RO },

  { NULL, NULL, 0 }
};

void
_gum_script_kernel_init (GumScriptKernel * self,
                          GumScriptCore * core,
                          JSObjectRef scope)
{
  JSContextRef ctx = core->ctx;
  JSClassDefinition def;
  JSClassRef klass;
  JSObjectRef kernel, memory;

  self->core = core;

  def = kJSClassDefinitionEmpty;
  def.className = "Kernel";
  def.staticFunctions = gumjs_kernel_functions;
  klass = JSClassCreate (&def);
  kernel = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, def.className, kernel);

  def = kJSClassDefinitionEmpty;
  def.className = "Memory";
  def.staticFunctions = gumjs_kmemory_functions;
  klass = JSClassCreate (&def);
  memory = JSObjectMake (ctx, klass, self);
  JSClassRelease (klass);
  _gumjs_object_set (ctx, scope, def.className, memory);
}

void
_gum_script_kernel_dispose (GumScriptKernel * self)
{
  (void) self;
}

void
_gum_script_kernel_finalize (GumScriptKernel * self)
{
  (void) self;
}

GUMJS_DEFINE_FUNCTION (gumjs_kernel_enumerate_threads)
{
  GumScriptMatchContext mc;
  GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (args->core);

  mc.self = JSObjectGetPrivate (this_object);
  if (!_gumjs_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return NULL;
  mc.ctx = ctx;

  gum_kernel_enumerate_threads (gum_emit_thread, &mc);

  JSObjectCallAsFunction (ctx, mc.on_complete, NULL, 0, NULL, &scope.exception);
  _gum_script_scope_flush (&scope);

  return JSValueMakeUndefined (ctx);
}

static gboolean
gum_emit_thread (const GumThreadDetails * details,
                 gpointer user_data)
{
  GumScriptMatchContext * mc = user_data;
  GumScriptCore * core = mc->self->core;
  GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (core);
  JSContextRef ctx = mc->ctx;
  JSObjectRef thread;
  JSValueRef result;
  gboolean proceed;
  gchar * str;

  thread = JSObjectMake (ctx, NULL, NULL);
  _gumjs_object_set_uint (ctx, thread, "id", details->id);
  _gumjs_object_set_string (ctx, thread, "state",
      _gumjs_thread_state_to_string (details->state));
  _gumjs_object_set (ctx, thread, "context", _gumjs_cpu_context_new (ctx,
      (GumCpuContext *) &details->cpu_context, GUM_CPU_CONTEXT_READONLY, core));

  result = JSObjectCallAsFunction (ctx, mc->on_match, NULL, 1,
      (JSValueRef *) &thread, &scope.exception);
  _gum_script_scope_flush (&scope);

  proceed = TRUE;
  if (result != NULL && _gumjs_string_try_get (ctx, result, &str, NULL))
  {
    proceed = strcmp (str, "stop") != 0;
    g_free (str);
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_kmemory_read_byte_array)
{
  GumScriptCore * core = args->core;
  gpointer address;
  guint size;
  JSObjectRef buffer;

  if (!_gumjs_args_parse (args, "pu", &address, &size))
    return NULL;

  if (address == NULL)
    return JSValueMakeNull (ctx);

  if (size > 0)
  {
    guint8 * data;
    gsize n_bytes_read;
    gpointer buffer_data;

    data = gum_kernel_read (GUM_ADDRESS (address), size, &n_bytes_read);
    if (data == NULL)
      goto read_failed;

    buffer = _gumjs_array_buffer_new (ctx, n_bytes_read, core);
    buffer_data = _gumjs_array_buffer_get_data (ctx, buffer, NULL);
    memcpy (buffer_data, data, n_bytes_read);

    g_free (data);
  }
  else
  {
    buffer = _gumjs_array_buffer_new (ctx, 0, core);
  }

  return buffer;

read_failed:
  {
    _gumjs_throw (ctx, exception,
        "access violation reading 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (address));
    return NULL;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_kmemory_write_byte_array)
{
  gpointer address;
  GBytes * bytes;
  const guint8 * data;
  gsize size;

  if (!_gumjs_args_parse (args, "pB", &address, &bytes))
    return NULL;
  data = g_bytes_get_data (bytes, &size);

  if (!gum_kernel_write (GUM_ADDRESS (address), data, size))
    goto write_failed;

  g_bytes_unref (bytes);

  return JSValueMakeUndefined (ctx);

write_failed:
  {
    g_bytes_unref (bytes);

    _gumjs_throw (ctx, exception,
        "access violation writing to 0x%" G_GSIZE_MODIFIER "x",
        GPOINTER_TO_SIZE (address));
    return NULL;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_kmemory_enumerate_ranges)
{
  GumScriptMatchContext mc;
  GumPageProtection prot;
  GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (args->core);

  mc.self = JSObjectGetPrivate (this_object);
  if (!_gumjs_args_parse (args, "mF{onMatch,onComplete}", &prot, &mc.on_match,
      &mc.on_complete))
    return NULL;
  mc.ctx = ctx;

  gum_kernel_enumerate_ranges (prot, gum_emit_range, &mc);

  JSObjectCallAsFunction (ctx, mc.on_complete, NULL, 0, NULL, &scope.exception);
  _gum_script_scope_flush (&scope);

  return JSValueMakeUndefined (ctx);
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                gpointer user_data)
{
  GumScriptMatchContext * mc = user_data;
  GumScriptCore * core = mc->self->core;
  GumScriptScope scope = GUM_SCRIPT_SCOPE_INIT (core);
  JSContextRef ctx = mc->ctx;
  char prot_str[4] = "---";
  JSObjectRef range;
  const GumFileMapping * f = details->file;
  JSValueRef result;
  gboolean proceed;
  gchar * str;

  if ((details->prot & GUM_PAGE_READ) != 0)
    prot_str[0] = 'r';
  if ((details->prot & GUM_PAGE_WRITE) != 0)
    prot_str[1] = 'w';
  if ((details->prot & GUM_PAGE_EXECUTE) != 0)
    prot_str[2] = 'x';

  range = JSObjectMake (ctx, NULL, NULL);
  _gumjs_object_set_pointer (ctx, range, "base",
      GSIZE_TO_POINTER (details->range->base_address), core);
  _gumjs_object_set_uint (ctx, range, "size", details->range->size);
  _gumjs_object_set_string (ctx, range, "protection", prot_str);

  if (f != NULL)
  {
    JSObjectRef file = JSObjectMake (ctx, NULL, NULL);
    _gumjs_object_set_string (ctx, file, "path", f->path);
    _gumjs_object_set_uint (ctx, file, "offset", f->offset);
    _gumjs_object_set (ctx, range, "file", file);
  }

  result = JSObjectCallAsFunction (ctx, mc->on_match, NULL, 1,
      (JSValueRef *) &range, &scope.exception);
  _gum_script_scope_flush (&scope);

  proceed = TRUE;
  if (result != NULL && _gumjs_string_try_get (ctx, result, &str, NULL))
  {
    proceed = strcmp (str, "stop") != 0;
    g_free (str);
  }

  return proceed;
}
