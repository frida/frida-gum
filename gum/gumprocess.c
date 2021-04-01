/*
 * Copyright (C) 2015-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "gumcloak.h"

typedef struct _GumEmitThreadsContext GumEmitThreadsContext;
typedef struct _GumEmitRangesContext GumEmitRangesContext;
typedef struct _GumResolveSymbolContext GumResolveSymbolContext;
typedef struct _GumRunOnThreadContext GumRunOnThreadContext;

struct _GumEmitThreadsContext
{
  GumFoundThreadFunc func;
  gpointer user_data;
};

struct _GumEmitRangesContext
{
  GumFoundRangeFunc func;
  gpointer user_data;
};

struct _GumResolveSymbolContext
{
  const gchar * name;
  GumAddress result;
};

struct _GumRunOnThreadContext
{
  gboolean is_async;

  union {
    struct {
      GumRunOnThreadSyncUserFunc sync_func;
      void * ret_val;
    } sync;

    struct {
      GumRunOnThreadAsyncUserFunc async_func;
    } async;
  };
  gpointer user_data;

  GumCpuContext cpu_context;

  GMutex data_mutex;
  GCond data_cond;
  gboolean ready;
} ;

static void gum_process_run_callback_on_thread (GumCpuContext * cpu_context,
    gpointer user_data);
static void gum_process_run_callback_with_full_context (GumFullCpuContext * ctx,
    gpointer user_data);
static void gum_process_set_context (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);

static gboolean gum_emit_thread_if_not_cloaked (
    const GumThreadDetails * details, gpointer user_data);
static gboolean gum_emit_range_if_not_cloaked (const GumRangeDetails * details,
    gpointer user_data);
static gboolean gum_store_address_if_name_matches (
    const GumSymbolDetails * details, gpointer user_data);

static GumCodeSigningPolicy gum_code_signing_policy = GUM_CODE_SIGNING_OPTIONAL;

G_DEFINE_BOXED_TYPE (GumModuleDetails, gum_module_details,
    gum_module_details_copy, gum_module_details_free)

GumOS
gum_process_get_native_os (void)
{
#if defined (HAVE_WINDOWS)
  return GUM_OS_WINDOWS;
#elif defined (HAVE_MACOS)
  return GUM_OS_MACOS;
#elif defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
  return GUM_OS_LINUX;
#elif defined (HAVE_IOS)
  return GUM_OS_IOS;
#elif defined (HAVE_ANDROID)
  return GUM_OS_ANDROID;
#elif defined (HAVE_QNX)
  return GUM_OS_QNX;
#else
# error Unknown OS
#endif
}

GumCodeSigningPolicy
gum_process_get_code_signing_policy (void)
{
  return gum_code_signing_policy;
}

void
gum_process_set_code_signing_policy (GumCodeSigningPolicy policy)
{
  gum_code_signing_policy = policy;
}

void *
gum_process_run_on_thread_sync (GumThreadId id,
                                GumRunOnThreadSyncUserFunc func,
                                gpointer user_data)
{
  GumRunOnThreadContext run_ctx =
  {
    .is_async = FALSE,
    .sync = {
      .sync_func = func,
    },
    .user_data = user_data,
    .ready = FALSE,
  };

  g_mutex_init(&run_ctx.data_mutex);
  g_cond_init(&run_ctx.data_cond);

  GumProcessRunOnThreadContext modify_ctx = {
    .callback = gum_process_run_callback_on_thread,
    .user_data = &run_ctx
  };

  volatile gboolean* ready = &run_ctx.ready;

  g_mutex_lock (&run_ctx.data_mutex);

  if (!gum_process_is_run_on_thread_supported())
  {
    g_print ("Unsupported");
    return NULL;
  }

  gum_process_modify_thread (id, gum_process_modify_thread_to_call_function,
      &modify_ctx);

  while (!(*ready))
    g_cond_wait (&run_ctx.data_cond, &run_ctx.data_mutex);

  g_mutex_unlock (&run_ctx.data_mutex);

  return run_ctx.sync.ret_val;
}

void
gum_process_run_on_thread_async (GumThreadId id,
                                 GumRunOnThreadAsyncUserFunc func,
                                 gpointer user_data)
{
  GumRunOnThreadContext run_ctx =
  {
    .is_async = TRUE,
    .async = {
      .async_func = func,
    },
    .user_data = user_data,
    .ready = FALSE,
  };

  g_mutex_init(&run_ctx.data_mutex);
  g_cond_init(&run_ctx.data_cond);

  GumProcessRunOnThreadContext modify_ctx = {
    .callback = gum_process_run_callback_on_thread,
    .user_data = &run_ctx
  };

  volatile gboolean* ready = &run_ctx.ready;

  g_mutex_lock (&run_ctx.data_mutex);

  if (!gum_process_is_run_on_thread_supported())
  {
    g_print ("Unsupported");
  }

  gum_process_modify_thread (id, gum_process_modify_thread_to_call_function,
      &modify_ctx);

  while (!(*ready))
    g_cond_wait (&run_ctx.data_cond, &run_ctx.data_mutex);

  g_mutex_unlock (&run_ctx.data_mutex);

  return;
}

static void
gum_process_run_callback_on_thread (GumCpuContext * cpu_context,
                                    gpointer user_data)
{
  GumCpuContext cached_context = *cpu_context;
  GumRunOnThreadContext * run_ctx = (GumRunOnThreadContext *) user_data;
  GumThreadId id;

  gum_process_call_with_full_context (&cached_context,
    gum_process_run_callback_with_full_context, run_ctx);

  id = gum_process_get_current_thread_id ();
  if (!gum_process_modify_thread(id, gum_process_set_context, &cached_context))
    g_thread_exit((gpointer)1);
}

static void
gum_process_run_callback_with_full_context (GumFullCpuContext * cpu_context,
                                            gpointer user_data)
{
  GumRunOnThreadContext * run_ctx = (GumRunOnThreadContext *) user_data;
  GumRunOnThreadAsyncUserFunc async_func = run_ctx->async.async_func;
  void * async_arg = run_ctx->user_data;
  volatile gboolean* ready = &run_ctx->ready;

  g_mutex_lock (&run_ctx->data_mutex);

  if (run_ctx->is_async)
  {
    *ready = TRUE;
    g_cond_signal (&run_ctx->data_cond);
    g_mutex_unlock (&run_ctx->data_mutex);

    async_func(&cpu_context->regs, async_arg);
  }
  else
  {
    run_ctx->sync.ret_val = run_ctx->sync.sync_func(&cpu_context->regs,
        run_ctx->user_data);

    *ready = TRUE;
    g_cond_signal (&run_ctx->data_cond);
    g_mutex_unlock (&run_ctx->data_mutex);
  }
}

static void
gum_process_set_context (GumThreadId thread_id,
                         GumCpuContext * cpu_context,
                         gpointer user_data)
{
  GumCpuContext * saved_ctx = (GumCpuContext *) user_data;
  *cpu_context = *saved_ctx;
}

void
gum_process_enumerate_threads (GumFoundThreadFunc func,
                               gpointer user_data)
{
  GumEmitThreadsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  _gum_process_enumerate_threads (gum_emit_thread_if_not_cloaked, &ctx);
}

static gboolean
gum_emit_thread_if_not_cloaked (const GumThreadDetails * details,
                                gpointer user_data)
{
  GumEmitThreadsContext * ctx = user_data;

  if (gum_cloak_has_thread (details->id))
    return TRUE;

  return ctx->func (details, ctx->user_data);
}

void
gum_process_enumerate_ranges (GumPageProtection prot,
                              GumFoundRangeFunc func,
                              gpointer user_data)
{
  GumEmitRangesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  _gum_process_enumerate_ranges (prot, gum_emit_range_if_not_cloaked, &ctx);
}

static gboolean
gum_emit_range_if_not_cloaked (const GumRangeDetails * details,
                               gpointer user_data)
{
  GumEmitRangesContext * ctx = user_data;
  GArray * sub_ranges;

  sub_ranges = gum_cloak_clip_range (details->range);
  if (sub_ranges != NULL)
  {
    gboolean carry_on = TRUE;
    GumRangeDetails sub_details;
    guint i;

    sub_details.protection = details->protection;
    sub_details.file = details->file;

    for (i = 0; i != sub_ranges->len && carry_on; i++)
    {
      sub_details.range = &g_array_index (sub_ranges, GumMemoryRange, i);

      carry_on = ctx->func (&sub_details, ctx->user_data);
    }

    g_array_free (sub_ranges, TRUE);

    return carry_on;
  }

  return ctx->func (details, ctx->user_data);
}

GumAddress
gum_module_find_symbol_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumResolveSymbolContext ctx;

  ctx.name = symbol_name;
  ctx.result = 0;

  gum_module_enumerate_symbols (module_name, gum_store_address_if_name_matches,
      &ctx);

  return ctx.result;
}

static gboolean
gum_store_address_if_name_matches (const GumSymbolDetails * details,
                                   gpointer user_data)
{
  GumResolveSymbolContext * ctx = user_data;
  gboolean carry_on = TRUE;

  if (strcmp (details->name, ctx->name) == 0)
  {
    ctx->result = details->address;
    carry_on = FALSE;
  }

  return carry_on;
}

const gchar *
gum_code_signing_policy_to_string (GumCodeSigningPolicy policy)
{
  switch (policy)
  {
    case GUM_CODE_SIGNING_OPTIONAL: return "optional";
    case GUM_CODE_SIGNING_REQUIRED: return "required";
  }

  g_assert_not_reached ();
  return NULL;
}

GumModuleDetails *
gum_module_details_copy (const GumModuleDetails * module)
{
  GumModuleDetails * copy;

  copy = g_slice_new (GumModuleDetails);

  copy->name = g_strdup (module->name);
  copy->range = gum_memory_range_copy (module->range);
  copy->path = g_strdup (module->path);

  return copy;
}

void
gum_module_details_free (GumModuleDetails * module)
{
  if (module == NULL)
    return;

  g_free ((gpointer) module->name);
  gum_memory_range_free ((GumMemoryRange *) module->range);
  g_free ((gpointer) module->path);

  g_slice_free (GumModuleDetails, module);
}

const gchar *
gum_symbol_type_to_string (GumSymbolType type)
{
  switch (type)
  {
    /* Common */
    case GUM_SYMBOL_UNKNOWN:            return "unknown";
    case GUM_SYMBOL_SECTION:            return "section";

    /* Mach-O */
    case GUM_SYMBOL_UNDEFINED:          return "undefined";
    case GUM_SYMBOL_ABSOLUTE:           return "absolute";
    case GUM_SYMBOL_PREBOUND_UNDEFINED: return "prebound-undefined";
    case GUM_SYMBOL_INDIRECT:           return "indirect";

    /* ELF */
    case GUM_SYMBOL_OBJECT:             return "object";
    case GUM_SYMBOL_FUNCTION:           return "function";
    case GUM_SYMBOL_FILE:               return "file";
    case GUM_SYMBOL_COMMON:             return "common";
    case GUM_SYMBOL_TLS:                return "tls";
  }

  g_assert_not_reached ();
  return NULL;
}
